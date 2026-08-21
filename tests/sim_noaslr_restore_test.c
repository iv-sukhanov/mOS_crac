#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sysexits.h>
#include <sys/mman.h>
#include <mach/thread_state.h>
#include <mach/mach_vm.h>
#include <pthread.h>

#define PAGE_SIZE_ASSUMED 16384
#define STACK_CHUNK_BYTES (8 * PAGE_SIZE_ASSUMED)   /* 128KB */
#define CODE_CHUNK_BYTES  (4 * PAGE_SIZE_ASSUMED)   /* 64KB */

typedef struct regs {
    arm_thread_state64_t gregs;
    arm_neon_state64_t neon;
    uint64_t tpidr;
} regs_t;

typedef struct {
    uint64_t stack_addr, stack_len;   /* page-aligned */
    uint64_t code_addr,  code_len;    /* page-aligned */
    uint64_t stack_checksum;
    regs_t   regs;
} checkpoint_header_t;

static regs_t g_regs;
static long g_pagesize;
static uint8_t stack_chunk_buf[STACK_CHUNK_BYTES];
static uint8_t code_chunk_buf[CODE_CHUNK_BYTES];

static uint64_t simple_checksum(const void* buf, size_t len) {
    const uint8_t *p = buf;
    uint64_t sum = 0;
    for (size_t i = 0; i < len; i++) sum = sum * 31 + p[i];
    
    return sum;
}

static uint64_t floor_to_page(uint64_t addr) {
    return addr & ~(uint64_t)(g_pagesize - 1);
}

static void* hijack_fn(void* arg) {
    (void)arg;
    raise(SIGUSR1);
    return NULL;
}

/* EXPERIMENT (2026-08-17): plain munmap() and mach_vm_deallocate() both
 * leave this range's MALLOC guard page stuck (2026-08-14/17 findings) --
 * before concluding no VM call can touch it, try every other plausible
 * primitive: the two more direct allocate/map entry points MAP_FIXED's
 * BSD mmap() wrapper sits on top of (in case that wrapper layer, not
 * vm_map itself, is what refuses), mprotect-then-retry (maybe a live
 * PROT_NONE region behaves differently once it's no longer guard-shaped),
 * and mach_vm_write directly against the untouched region (in case a
 * cross-task memory-write RPC bypasses protection checks the way ptrace
 * writes do on other OSes). Stops at the first one that actually leaves
 * real RW memory mapped at `addr`; returns a label for whichever worked,
 * or NULL if none did. */
static const char* try_reclaim_stuck_range(uint64_t addr, uint64_t len) {
    mach_vm_address_t a;
    kern_return_t kr;

    a = addr;
    kr = mach_vm_allocate(mach_task_self(), &a, len, VM_FLAGS_FIXED);
    fprintf(stderr, "  try mach_vm_allocate(FIXED): kr=%d\n", kr);
    if (kr == KERN_SUCCESS) return "mach_vm_allocate(VM_FLAGS_FIXED)";
    munmap((void*)(uintptr_t)addr, len);

    a = addr;
    kr = mach_vm_allocate(mach_task_self(), &a, len, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE);
    fprintf(stderr, "  try mach_vm_allocate(FIXED|OVERWRITE): kr=%d\n", kr);
    if (kr == KERN_SUCCESS) return "mach_vm_allocate(VM_FLAGS_FIXED|VM_FLAGS_OVERWRITE)";
    munmap((void*)(uintptr_t)addr, len);

    a = addr;
    kr = mach_vm_map(mach_task_self(), &a, len, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                      MACH_PORT_NULL, 0, FALSE,
                      VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE,
                      VM_INHERIT_DEFAULT);
    fprintf(stderr, "  try mach_vm_map(FIXED|OVERWRITE): kr=%d\n", kr);
    if (kr == KERN_SUCCESS) return "mach_vm_map(VM_FLAGS_FIXED|VM_FLAGS_OVERWRITE)";
    munmap((void*)(uintptr_t)addr, len);

    /* mach_vm_write against the region exactly as-is -- no mprotect first,
     * testing whether the RPC itself ignores current protection. */
    uint8_t probe_bytes[16] = {0};
    kr = mach_vm_write(mach_task_self(), addr, (vm_offset_t)probe_bytes, sizeof(probe_bytes));
    fprintf(stderr, "  try mach_vm_write (no mprotect first): kr=%d\n", kr);
    if (kr == KERN_SUCCESS) return "mach_vm_write (bypassing protection)";

    /* mprotect to RW, then retry the plain mmap(MAP_FIXED) that started
     * this whole diagnostic, and mach_vm_write again if that still fails. */
    int mp = mprotect((void*)(uintptr_t)addr, len, PROT_READ | PROT_WRITE);
    fprintf(stderr, "  try mprotect(RW) first: rc=%d errno=%d (%s)\n",
            mp, mp == 0 ? 0 : errno, mp == 0 ? "ok" : strerror(errno));
    if (mp == 0) {
        void* got = mmap((void*)(uintptr_t)addr, len, PROT_READ | PROT_WRITE,
                          MAP_FIXED | MAP_ANON | MAP_PRIVATE, -1, 0);
        fprintf(stderr, "  try mmap(MAP_FIXED) after mprotect(RW): %s\n",
                got == MAP_FAILED ? strerror(errno) : "ok");
        if (got != MAP_FAILED) return "mprotect(RW) then mmap(MAP_FIXED)";

        kr = mach_vm_write(mach_task_self(), addr, (vm_offset_t)probe_bytes, sizeof(probe_bytes));
        fprintf(stderr, "  try mach_vm_write after mprotect(RW): kr=%d\n", kr);
        if (kr == KERN_SUCCESS) return "mprotect(RW) then mach_vm_write";
    }

    return NULL;
}

static bool range_is_free(uint64_t start, uint64_t len) {
    mach_vm_address_t addr = 0;
    for (;;) {
        mach_vm_address_t a = addr;
        mach_vm_size_t size = 0;
        natural_t depth = 32;
        vm_region_submap_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        kern_return_t kr = mach_vm_region_recurse(mach_task_self(), &a, &size, &depth,
                                                   (vm_region_recurse_info_t)&info, &count);
        if (kr == KERN_INVALID_ADDRESS) break;
        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "range_is_free: region walk error %d\n", kr);
            break;
        }
        if (a < start + len && start < (uint64_t)a + size) {
            fprintf(stderr, "collision: target [0x%llx,0x%llx) overlaps existing region "
                    "[0x%llx,0x%llx) protection=%d\n",
                    start, start + len,
                    a, a + size, info.protection);
            return false;
        }
        addr = a + size;
    }
    return true;
}

/* mmap(MAP_FIXED) at `addr`, with the MALLOC-guard-page collision (2026-08-14
 * onward) handled instead of left to the caller. `try_reclaim_stuck_range()`
 * is tried first on the off chance this particular collision is reclaimable
 * (2026-08-17: none tested ever were, but cheap to keep trying). If that
 * fails too, this exits the whole process with EX_TEMPFAIL ("temporary
 * failure, retry" -- sysexits.h) rather than returning an error: a collision
 * here isn't this process's bug, it's this *launch's* malloc-metadata layout
 * being unlucky, and the only known fix is a fresh process with a fresh
 * layout (see NOTES.md 2026-08-21). `spawn_noaslr -r <n>` is the retry
 * wrapper that acts on this exit code. Only ENOMEM is treated as that known,
 * retryable collision signature -- any other errno is a real bug and exits
 * 1 instead, so a genuine problem doesn't just get silently retried forever.
 * Set MOS_CRAC_PAUSE_ON_COLLISION=1 to get the old manual-vmmap-inspection
 * behavior instead of exiting, for one-off debugging. */
static void* map_fixed_or_retry(uint64_t addr, uint64_t len, const char* label) {
    void* got = mmap((void*)(uintptr_t)addr, len, PROT_READ | PROT_WRITE,
                      MAP_FIXED | MAP_ANON | MAP_PRIVATE, -1, 0);
    if (got != MAP_FAILED) return got;

    int saved_errno = errno;
    fprintf(stderr, "mmap %s: %s\n", label, strerror(saved_errno));
    if (saved_errno != ENOMEM) {
        fprintf(stderr, "  errno isn't the known MALLOC-guard-page collision "
                "signature -- treating as a real bug, not retrying\n");
        exit(1);
    }

    const char* worked = try_reclaim_stuck_range(addr, len);
    if (worked) {
        printf("  RECLAIMED via: %s\n", worked);
        return (void*)(uintptr_t)addr;
    }

    if (getenv("MOS_CRAC_PAUSE_ON_COLLISION")) {
        printf("  PAUSED for inspection: pid=%d target=[0x%llx,0x%llx]\n"
               "  run: vmmap -noCoalesce -interleaved %d\n",
               getpid(), addr, addr + len, getpid());
        pause();
    }

    fprintf(stderr, "  %s collided with an unreclaimable region -- exiting "
            "EX_TEMPFAIL so a retry wrapper can try a fresh process\n", label);
    exit(EX_TEMPFAIL);
}

void restore_state(int sig, siginfo_t* info, void* ctx) {
    (void)sig; (void)info;
    ((ucontext_t*)ctx)->uc_mcontext->__ss = g_regs.gregs;
    ((ucontext_t*)ctx)->uc_mcontext->__ns = g_regs.neon;
    __asm__ volatile ("msr tpidr_el0, %0" :: "r" (g_regs.tpidr));
}

static int do_restore(const char* path) {
    FILE* f = fopen(path, "rb");
    if (!f) { perror("fopen"); return 1; }

    checkpoint_header_t hdr;
    if (fread(&hdr, sizeof(hdr), 1, f) != 1) { fprintf(stderr, "short read on header\n"); fclose(f); return 1; }
    if (hdr.stack_len > sizeof(stack_chunk_buf) || hdr.code_len > sizeof(code_chunk_buf)) {
        fprintf(stderr, "chunk too big for compiled-in buffer\n"); fclose(f); return 1;
    }
    if (fread(stack_chunk_buf, 1, hdr.stack_len, f) != hdr.stack_len) {
        fprintf(stderr, "short read on stack chunk\n"); fclose(f); return 1;
    }
    if (fread(code_chunk_buf, 1, hdr.code_len, f) != hdr.code_len) {
        fprintf(stderr, "short read on code chunk\n"); fclose(f); return 1;
    }
    fclose(f);

    printf("restoring from %s\n", path);
    printf("  stack [0x%llx, 0x%llx] pc=0x%llx sp=0x%llx\n",
           hdr.stack_addr, hdr.stack_addr + hdr.stack_len,
           hdr.regs.gregs.__pc, hdr.regs.gregs.__sp);

    bool stack_clean = range_is_free(hdr.stack_addr, hdr.stack_len);
    bool code_clean  = range_is_free(hdr.code_addr, hdr.code_len);
    printf("  collision check: stack %s, code %s\n",
           stack_clean ? "clean" : "COLLISION", code_clean ? "clean" : "COLLISION");

    printf("mapping stack/code chunks at their original addresses... size=%llu\n", hdr.stack_len);
    munmap((void*)(uintptr_t)hdr.stack_addr, hdr.stack_len);
    void* got_stack = map_fixed_or_retry(hdr.stack_addr, hdr.stack_len, "stack");
    if ((uint64_t)(uintptr_t)got_stack != hdr.stack_addr) {
        fprintf(stderr, "MAP_FIXED did not honor the stack address\n"); return 1;
    } else {
        printf("  mmap()ed stack chunk at 0x%llx\n", (uint64_t)(uintptr_t)got_stack);
    }
    memcpy(got_stack, stack_chunk_buf, hdr.stack_len);

    uint64_t restored_checksum = simple_checksum(got_stack, hdr.stack_len);
    printf("  stack checksum: file=0x%llx restored=0x%llx (%s)\n",
           hdr.stack_checksum, restored_checksum,
           hdr.stack_checksum == restored_checksum ? "MATCH" : "MISMATCH");

    printf("allocating code chunk at its original address... size=%llu\n", hdr.code_len);
    void* got_code = map_fixed_or_retry(hdr.code_addr, hdr.code_len, "code");
    if ((uint64_t)(uintptr_t)got_code != hdr.code_addr) {
        fprintf(stderr, "MAP_FIXED did not honor the code address\n"); return 1;
    } else {
        printf("  mmap()ed code chunk at 0x%llx\n", (uint64_t)(uintptr_t)got_code);
    }
    memcpy(got_code, code_chunk_buf, hdr.code_len);
    if (mprotect(got_code, hdr.code_len, PROT_READ | PROT_EXEC) != 0) { perror("mprotect code"); return 1; }

    g_regs = hdr.regs;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_flags = SA_SIGINFO;
    sa.__sigaction_u.__sa_sigaction = restore_state;
    if (sigaction(SIGUSR1, &sa, NULL) == -1) { perror("sigaction"); return 1; }

    pthread_t hijack;
    if (pthread_create(&hijack, NULL, hijack_fn, NULL) != 0) { perror("pthread_create"); return 1; }
    pthread_detach(hijack);

    printf("  hijacking a fresh thread onto the restored state...\n");
    sleep(3); /* give the resumed loop time to finish + hit the write */

    return 0;
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    g_pagesize = sysconf(_SC_PAGESIZE);
    printf("system _text addr %llx\n", floor_to_page((uint64_t)(uintptr_t)&main));
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\n", argv[0]);
        return 2;
    }
    return do_restore(argv[1]);
}