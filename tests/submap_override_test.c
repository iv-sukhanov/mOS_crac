/* Step 2 of the submap-remapping test plan (NOTES.md, 2026-08-11): can
 * mmap(MAP_FIXED) override a region that's actually a nested VM submap
 * (the dyld shared cache), or does the kernel protect it?
 */
#include <mach/mach_vm.h>
#include <mach/mach.h>
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

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

static uint64_t find_any_submap() {
    
    mach_vm_address_t a = 0;
    mach_vm_size_t size = 0;
    for (;;) {
        natural_t depth = 0;
        vm_region_submap_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
    
        kern_return_t kr = mach_vm_region_recurse(mach_task_self(), &a, &size, &depth, 
                                                    (vm_region_recurse_info_t)&info, &count);
    
        if (kr != KERN_SUCCESS) {
            printf("failed to find a submap region: %d\n", kr);
            return 0;
        }
        if (info.is_submap == 1) {
            printf("fond a submap region at addr=0x%llx size=0x%llx\n", a, size);
            return a + size / 2;
        }
        a += size;
    }
}

int main(void) {
    long pagesize = sysconf(_SC_PAGESIZE);
    printf("pagesize: %ld\n", pagesize);

    mach_vm_address_t submap_address = find_any_submap();
    if (submap_address == 0) {
        printf("didn't find any submaps\n");
        return 1;
    }

    /* depth=0: don't descend at all -- if a submap is right here, this
     * reports the submap boundary itself (is_submap=1), not its flattened
     * leaf content. This is the "is it really a submap" check. */
    dump_region("before, depth=0 (raw submap check)", submap_address, 0);
    dump_region("before, depth=32 (fully descended)", submap_address, 32);

    printf("\nattempting mmap(MAP_FIXED) over the submap's start address...\n");
    void *got = mmap((void *)submap_address, (size_t)pagesize, PROT_READ | PROT_WRITE,
                      MAP_FIXED | MAP_ANON | MAP_PRIVATE, -1, 0);
    if (got == MAP_FAILED) {
        perror("mmap");
        printf("RESULT: mmap(MAP_FIXED) over a submap FAILED -- kernel protects it\n");
        return 0;
    }
    printf("mmap returned %p (%s)\n", got, got == (void *)submap_address ? "matches requested address" : "MISMATCH");
    printf("RESULT: mmap(MAP_FIXED) over a submap SUCCEEDED\n\n");

    /* minimal work after the override -- avoid calling into anything that
     * might route through the page we just clobbered (see the "this could
     * crash the process" caveat flagged before running this). */
    dump_region("after override, depth=0 (raw submap check)", submap_address, 0);
    dump_region("after override, depth=32 (fully descended)", submap_address, 32);

    return 0;
}
