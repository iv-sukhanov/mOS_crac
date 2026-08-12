/* Minimal, single-process (no fork, no signal handler) version of the
 * step-3 reconstruction test. strdup wasn't a clean target -- it calls
 * out to malloc/strlen/memcpy internally, so restoring only its own page
 * doesn't isolate anything. abs() is a genuine leaf function: calls
 * nothing else, tiny, deterministic. Taking its address through a
 * function pointer forces a real out-of-line reference rather than
 * letting the compiler inline it -- confirmed below via dladdr.
 *
 * Deliberately no crash handling: if this crashes or hangs, that's the
 * point -- run it under lldb to inspect registers/memory at the fault.
 */
#include <mach/mach_vm.h>
#include <mach/mach.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>

static void dump_region(const char *label, mach_vm_address_t addr, natural_t depth_in) {
    mach_vm_address_t a = addr;
    mach_vm_size_t size = 0;
    natural_t depth = depth_in;
    vm_region_submap_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;

    kern_return_t kr = mach_vm_region_recurse(mach_task_self(), &a, &size, &depth,
                                               (vm_region_recurse_info_t)&info, &count);
    if (kr != KERN_SUCCESS) {
        printf("[%s] mach_vm_region_recurse failed: %d\n", label, kr);
        return;
    }
    printf("[%s] addr=0x%llx (requested 0x%llx) size=0x%llx is_submap=%d "
           "protection=%d depth_in=%u depth_out=%u\n",
           label, a, addr, size, info.is_submap, info.protection, depth_in, depth);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    long pagesize = sysconf(_SC_PAGESIZE);
    mach_vm_address_t mask = ~(mach_vm_address_t)(pagesize - 1);

    int (*fn)(int) = abs;
    mach_vm_address_t fn_addr = (mach_vm_address_t)(uintptr_t)fn;
    mach_vm_address_t page_start = fn_addr & mask;

    Dl_info dli;
    if (!dladdr((void *)fn, &dli)) {
        printf("dladdr failed to resolve abs -- likely inlined, pick a different target\n");
        return 1;
    }
    printf("abs at 0x%llx, resolved to %s, page start 0x%llx\n",
           fn_addr, dli.dli_fname, page_start);

    printf("baseline: abs(-7) = %d\n", fn(-7));
    
    dump_region("before", page_start, 0);
    dump_region("before with submaps", page_start, 32);

    char *saved = malloc((size_t)pagesize);
    memcpy(saved, (void *)page_start, (size_t)pagesize);

    printf("mmap(MAP_FIXED)...\n");
    void *got = mmap((void *)page_start, (size_t)pagesize, PROT_READ | PROT_WRITE,
                      MAP_FIXED | MAP_ANON | MAP_PRIVATE, -1, 0);
    if (got == MAP_FAILED) { perror("mmap"); return 1; }
    printf("mmap succeeded\n");

    dump_region("after", page_start, 0);
    dump_region("after with submaps", page_start, 32);

    memcpy((void *)page_start, saved, (size_t)pagesize);
    printf("bytes restored\n");

    if (mprotect((void *)page_start, (size_t)pagesize, PROT_READ | PROT_EXEC) != 0) {
        perror("mprotect");
        return 1;
    }
    printf("mprotect succeeded\n");

    dump_region("after mprotect", page_start, 0);
    dump_region("after mprotect with submaps", page_start, 32);

    printf("calling reconstructed abs(-7)...\n");
    int result = fn(-7);
    printf("result: %d (%s)\n", result, result == 7 ? "correct" : "WRONG");

    free(saved);
    return 0;
}
