/* Milestone 4, first slice: checkpoint one thread (register state + a chunk
 * of its real stack + the code page(s) containing its resume point) in one
 * process, restore it in a genuinely separate process launch.
 *
 * `worker_fn` deliberately makes NO calls and touches NO globals in the
 * portion that can be interrupted/resumed. This isn't incidental style --
 * it's load-bearing. Its captured PC is an address inside *this process's*
 * own __TEXT segment, restored via mmap(MAP_FIXED) at that exact original
 * address in the restoring process. Any call worker_fn made (even to libc)
 * would go through a per-image stub + a __DATA-resident bound pointer,
 * and any global reference is a PC-relative computation assuming *this
 * process's* own ASLR slide -- both resolve to garbage once the same
 * instructions are spliced into a different process with a different
 * slide. worker_fn stays a pure register/stack-local leaf, matching the
 * same "genuine leaf function" shape submap_minimal_test.c already proved
 * safe for code-page reconstruction (abs()). Everything else (drivers,
 * signal handlers, the hijack trampoline) runs natively in its own process
 * and isn't restored/spliced, so it's free to call whatever it wants.
 */
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/thread_state.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdint.h>
#include <time.h>

#define PAGE_SIZE_ASSUMED 16384
#define STACK_CHUNK_BYTES (8 * PAGE_SIZE_ASSUMED)   /* 128KB */
#define CODE_CHUNK_BYTES  (4 * PAGE_SIZE_ASSUMED)   /* 64KB */

#define WORKER_ITERS 100000000ULL
#define SIGNAL_DELAY_USEC 20000

#define SENTINEL 0xC0FFEEULL

typedef struct regs {
    uint64_t pc, sp, cpsr, fp, lr, pad;
    uint64_t x[29];
    arm_neon_state64_t neon;
    uint64_t tpidr;
} regs_t;

typedef struct {
    uint64_t stack_addr, stack_len;   /* page-aligned */
    uint64_t code_addr,  code_len;    /* page-aligned */
    uint64_t stack_checksum;
    regs_t   regs;
} checkpoint_header_t;

static long g_pagesize;
static regs_t g_regs;
static uint64_t g_stack_addr, g_stack_len;
static uint64_t g_code_addr, g_code_len;
static atomic_bool captured = false;
static uint8_t stack_chunk_buf[STACK_CHUNK_BYTES];
static uint8_t code_chunk_buf[CODE_CHUNK_BYTES];

static uint64_t floor_to_page(uint64_t addr) {
    return addr & ~(uint64_t)(g_pagesize - 1);
}

static double elapsed_ms(struct timespec* start) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (now.tv_sec - start->tv_sec) * 1000.0 + (now.tv_nsec - start->tv_nsec) / 1e6;
}

static int wait_for_flag(atomic_bool* flag, int budget_ms) {
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    while (!atomic_load(flag)) {
        if (elapsed_ms(&start) > budget_ms) return -1;
        usleep(500);
    }
    return 0;
}

static uint64_t simple_checksum(const void* buf, size_t len) {
    const uint8_t* p = buf;
    uint64_t sum = 0;
    for (size_t i = 0; i < len; i++) sum = sum * 31 + p[i];
    return sum;
}

/* Unaligned linear scan for an 8-byte value anywhere in buf -- avoids
 * needing to know worker_fn's exact stack-frame layout for `sentinel`. */
static bool scan_for_u64(const void* buf, size_t len, uint64_t needle) {
    const uint8_t* p = buf;
    for (size_t i = 0; i + 8 <= len; i++) {
        uint64_t v;
        memcpy(&v, p + i, 8);
        if (v == needle) return true;
    }
    return false;
}

/* How many bytes starting at `start`, up to `budget`, are actually mapped
 * -- clamps a chunk request to reality instead of guessing a byte count
 * and reading off the end. Walks region-by-region rather than trusting
 * the first region's own boundary: mach_vm_region_recurse reports fine-
 * grained regions (different tags/protections/object_ids even within one
 * logical Mach-O segment -- same granularity the 2026-08-11 submap
 * investigation already ran into), so the single containing region for
 * `start` can be much smaller than the code or stack actually spans.
 * Accumulates across CONSECUTIVE regions (no gap between them) so a
 * function or stack frame straddling one of those finer boundaries still
 * gets fully captured, and only stops at a genuine gap or the budget.
 * The stack-chunk case is the empirically-confirmed motivating example:
 * a worker thread's shallow call depth leaves very little headroom above
 * SP before hitting a real EXC_BAD_ACCESS if this isn't done. */
static uint64_t probe_contiguous_len(uint64_t start, uint64_t budget) {
    uint64_t total = 0;
    uint64_t addr = start;
    while (total < budget) {
        mach_vm_address_t a = addr;
        mach_vm_size_t size = 0;
        natural_t depth = 32;
        vm_region_submap_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        kern_return_t kr = mach_vm_region_recurse(mach_task_self(), &a, &size, &depth,
                                                   (vm_region_recurse_info_t)&info, &count);
        if (kr != KERN_SUCCESS) break;   /* no more regions at all */
        if ((uint64_t)a != addr) break;  /* gap right here -- stop, don't jump over it */
        uint64_t take = size;
        if (total + take > budget) take = budget - total;
        total += take;
        if (take < size) break; /* hit budget mid-region */
        addr += size;
    }
    return total;
}

/* Walk this process's own memory (same technique as mach_vm_region_test.c)
 * and report whether [start, start+len) overlaps anything already mapped. */
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
                    (unsigned long long)start, (unsigned long long)(start + len),
                    (unsigned long long)a, (unsigned long long)(a + size), info.protection);
            return false;
        }
        addr = a + size;
    }
    return true;
}

/* --- the checkpointed thread: leaf-only, see file header comment --- */
static void* worker_fn(void* arg) {
    (void)arg;
    volatile uint64_t counter = 0;
    volatile uint64_t sentinel = 0;
    volatile uint64_t park = 0;
    for (volatile uint64_t i = 0; i < WORKER_ITERS; i++) {
        counter = i;
    }
    sentinel = SENTINEL;
    /* EXPERIMENT (2026-08-13): does a call to a boot-scoped shared-cache
     * function survive being spliced into a different process? Prediction:
     * no -- the call still goes through a per-image stub + a __DATA-
     * resident bound pointer, both computed relative to *this process's*
     * own ASLR slide, same as any other external call. write()'s own
     * destination being boot-scoped doesn't help if the path to it is
     * process-relative. Testing directly rather than trusting that
     * reasoning alone. */
    char msg[] = "worker_fn resumed and finished the loop\n";
    write(STDOUT_FILENO, msg, sizeof(msg) - 1);
    for (;;) {
        park = park; /* volatile touch -- keeps this from being UB-eliminated */
    }
    return NULL; /* unreachable */
}

static void* hijack_fn(void* arg) {
    (void)arg;
    raise(SIGUSR2);
    return NULL;
}

void action_usr1_fn(int sig, siginfo_t* info, void* ctx) {
    (void)sig; (void)info;
    arm_thread_state64_t state = ((ucontext_t*)ctx)->uc_mcontext->__ss;
    g_regs.pc = (uint64_t)arm_thread_state64_get_pc(state);
    g_regs.sp = (uint64_t)arm_thread_state64_get_sp(state);
    g_regs.fp = (uint64_t)arm_thread_state64_get_fp(state);
    g_regs.lr = (uint64_t)arm_thread_state64_get_lr(state);
    g_regs.cpsr = (uint64_t)(state.__cpsr);
    g_regs.pad = (uint64_t)(state.__pad);
    memcpy(g_regs.x, state.__x, sizeof(g_regs.x));
    g_regs.neon = ((ucontext_t*)ctx)->uc_mcontext->__ns;
    __asm__ volatile ("mrs %0, tpidr_el0" : "=r" (g_regs.tpidr));

    /* Snapshot the stack/code chunks *inside* the handler, not later in
     * main -- the interrupted thread is about to keep running the moment
     * this handler returns (no self-park this time, unlike
     * thread_create_test.c: restore happens in a different process, so
     * there's no same-process race to guard against). Waiting until main
     * gets around to it would let the worker's own later iterations mutate
     * `counter` further, making the snapshot inconsistent with the
     * captured PC/SP. memcpy itself isn't on POSIX's async-signal-safe
     * list, but this codebase has already leaned on it inside handlers
     * successfully (thread_create_test.c's register copies) -- the actual
     * hazard class that list is guarding against is allocation/locking
     * (malloc, GCD), not a bounded pointer-to-pointer copy.
     */
    g_stack_addr = floor_to_page(g_regs.sp);
    g_stack_len  = probe_contiguous_len(g_stack_addr, STACK_CHUNK_BYTES);
    if (g_stack_len == 0) g_stack_len = (uint64_t)g_pagesize; /* couldn't confirm bounds -- smallest safe guess */
    if (g_stack_len > sizeof(stack_chunk_buf)) g_stack_len = sizeof(stack_chunk_buf);
    memcpy(stack_chunk_buf, (void*)(uintptr_t)g_stack_addr, g_stack_len);

    g_code_addr = floor_to_page(g_regs.pc);
    g_code_len  = probe_contiguous_len(g_code_addr, CODE_CHUNK_BYTES);
    if (g_code_len == 0) g_code_len = (uint64_t)g_pagesize;
    if (g_code_len > sizeof(code_chunk_buf)) g_code_len = sizeof(code_chunk_buf);
    memcpy(code_chunk_buf, (void*)(uintptr_t)g_code_addr, g_code_len);

    atomic_store(&captured, true);
}

void action_usr2_fn(int sig, siginfo_t* info, void* ctx) {
    (void)sig; (void)info;
    arm_thread_state64_t* state = &((ucontext_t*)ctx)->uc_mcontext->__ss;
    state->__pc = g_regs.pc;
    state->__sp = g_regs.sp;
    state->__fp = g_regs.fp;
    state->__lr = g_regs.lr;
    state->__cpsr = g_regs.cpsr;
    state->__pad = g_regs.pad;
    memcpy(state->__x, g_regs.x, sizeof(g_regs.x));
    ((ucontext_t*)ctx)->uc_mcontext->__ns = g_regs.neon;
    __asm__ volatile ("msr tpidr_el0, %0" :: "r" (g_regs.tpidr));
}

static int do_checkpoint(const char* path) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_flags = SA_SIGINFO;
    sa.__sigaction_u.__sa_sigaction = action_usr1_fn;
    if (sigaction(SIGUSR1, &sa, NULL) == -1) { perror("sigaction"); return 1; }

    pthread_t worker;
    if (pthread_create(&worker, NULL, worker_fn, NULL) != 0) { perror("pthread_create"); return 1; }

    /* Signal delivered *externally*, not via worker_fn self-raising --
     * matches the "worker_fn calls nothing" constraint from the file
     * header comment. Timing is heuristic (WORKER_ITERS/SIGNAL_DELAY_USEC
     * picked, not derived) -- tune if a run shows the signal landing
     * before the loop starts or after it already finished. */
    usleep(SIGNAL_DELAY_USEC);
    if (pthread_kill(worker, SIGUSR1) != 0) { perror("pthread_kill"); return 1; }

    if (wait_for_flag(&captured, 3000) == -1) {
        fprintf(stderr, "timed out waiting for capture\n");
        return 1;
    }

    uint64_t checksum = simple_checksum(stack_chunk_buf, g_stack_len);

    FILE* f = fopen(path, "wb");
    if (!f) { perror("fopen"); return 1; }
    checkpoint_header_t hdr = {
        .stack_addr = g_stack_addr, .stack_len = g_stack_len,
        .code_addr  = g_code_addr,  .code_len  = g_code_len,
        .stack_checksum = checksum,
        .regs = g_regs,
    };
    fwrite(&hdr, sizeof(hdr), 1, f);
    fwrite(stack_chunk_buf, 1, g_stack_len, f);
    fwrite(code_chunk_buf, 1, g_code_len, f);
    fclose(f);

    printf("checkpoint written to %s\n", path);
    printf("  stack [0x%llx, 0x%llx) checksum=0x%llx\n",
           (unsigned long long)g_stack_addr, (unsigned long long)(g_stack_addr + g_stack_len),
           (unsigned long long)checksum);
    printf("  code  [0x%llx, 0x%llx)\n",
           (unsigned long long)g_code_addr, (unsigned long long)(g_code_addr + g_code_len));
    printf("  pc=0x%llx sp=0x%llx\n",
           (unsigned long long)g_regs.pc, (unsigned long long)g_regs.sp);

    pthread_detach(worker); /* let it run to completion on its own; we no longer need it */
    return 0;
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
    printf("  stack [0x%llx, 0x%llx) pc=0x%llx sp=0x%llx\n",
           (unsigned long long)hdr.stack_addr, (unsigned long long)(hdr.stack_addr + hdr.stack_len),
           (unsigned long long)hdr.regs.pc, (unsigned long long)hdr.regs.sp);

    bool stack_clean = range_is_free(hdr.stack_addr, hdr.stack_len);
    bool code_clean  = range_is_free(hdr.code_addr, hdr.code_len);
    printf("  collision check: stack %s, code %s\n",
           stack_clean ? "clean" : "COLLISION", code_clean ? "clean" : "COLLISION");

    /* Explicit munmap() before the restoring mmap, matching minicriu's own
     * approach (minicriu.c:293-349) rather than relying on MAP_FIXED's
     * documented silent-replace alone -- our own empirical batch runs
     * showed that behavior isn't as consistent on Darwin as assumed
     * (some collisions replaced fine, some "clean" targets still failed
     * with ENOMEM). munmap() on unmapped memory is a harmless no-op either
     * way (same as minicriu's own comment notes). */
    printf("allocating stack/code chunks at their original addresses... size=%llu\n", (unsigned long long)hdr.stack_len);
    munmap((void*)(uintptr_t)hdr.stack_addr, hdr.stack_len);
    void* got_stack = mmap((void*)(uintptr_t)hdr.stack_addr, hdr.stack_len, PROT_READ | PROT_WRITE,
                            MAP_FIXED | MAP_ANON | MAP_PRIVATE, -1, 0);
    if (got_stack == MAP_FAILED) { perror("mmap stack"); return 1; }
    if ((uint64_t)(uintptr_t)got_stack != hdr.stack_addr) {
        fprintf(stderr, "MAP_FIXED did not honor the stack address\n"); return 1;
    }
    memcpy(got_stack, stack_chunk_buf, hdr.stack_len);

    uint64_t restored_checksum = simple_checksum(got_stack, hdr.stack_len);
    printf("  stack checksum: file=0x%llx restored=0x%llx (%s)\n",
           (unsigned long long)hdr.stack_checksum, (unsigned long long)restored_checksum,
           hdr.stack_checksum == restored_checksum ? "MATCH" : "MISMATCH");

    if (munmap((void*)(uintptr_t)hdr.code_addr, hdr.code_len) != 0) {
        perror("  DIAG munmap code");
    }
    printf("  DIAG post-munmap re-check: code %s\n",
           range_is_free(hdr.code_addr, hdr.code_len) ? "clean" : "STILL COLLIDING");

    printf("allocating code chunk at its original address... size=%llu\n", (unsigned long long)hdr.code_len);
    void* got_code = mmap((void*)(uintptr_t)hdr.code_addr, hdr.code_len, PROT_READ | PROT_WRITE,
                           MAP_FIXED | MAP_ANON | MAP_PRIVATE, -1, 0);
    if (got_code == MAP_FAILED) { perror("mmap code"); return 1; }
    if ((uint64_t)(uintptr_t)got_code != hdr.code_addr) {
        fprintf(stderr, "MAP_FIXED did not honor the code address\n"); return 1;
    }
    memcpy(got_code, code_chunk_buf, hdr.code_len);
    if (mprotect(got_code, hdr.code_len, PROT_READ | PROT_EXEC) != 0) { perror("mprotect code"); return 1; }

    g_regs = hdr.regs;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_flags = SA_SIGINFO;
    sa.__sigaction_u.__sa_sigaction = action_usr2_fn;
    if (sigaction(SIGUSR2, &sa, NULL) == -1) { perror("sigaction"); return 1; }

    pthread_t hijack;
    if (pthread_create(&hijack, NULL, hijack_fn, NULL) != 0) { perror("pthread_create"); return 1; }
    pthread_detach(hijack);

    printf("  hijacking a fresh thread onto the restored state...\n");
    usleep(1000000); /* give the resumed loop time to finish + hit the sentinel */

    bool finished = scan_for_u64((void*)(uintptr_t)hdr.stack_addr, hdr.stack_len, SENTINEL);
    printf("  resumed worker completed (sentinel found): %s\n", finished ? "YES" : "NO");

    return finished ? 0 : 1;
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 3) {
        fprintf(stderr, "usage: %s checkpoint|restore <file>\n", argv[0]);
        return 2;
    }

    g_pagesize = sysconf(_SC_PAGESIZE);
    if (g_pagesize != PAGE_SIZE_ASSUMED) {
        fprintf(stderr, "warning: actual page size %ld != assumed %d -- chunk buffers may be undersized\n",
                g_pagesize, PAGE_SIZE_ASSUMED);
    }

    if (strcmp(argv[1], "checkpoint") == 0) return do_checkpoint(argv[2]);
    if (strcmp(argv[1], "restore") == 0) return do_restore(argv[2]);

    fprintf(stderr, "usage: %s checkpoint|restore <file>\n", argv[0]);
    return 2;
}
