/* cr_test.c (2026-09-01) -- shared checkpoint/restore mechanism, one
 * canonical on-disk format and one do_capture()/do_restore() pair, instead
 * of the near-duplicate copies thread_capture_test.c/full_capture_test.c/
 * sim_capture_test.c have each accumulated. No main() of its own -- meant
 * to be #include'd directly by small driver .c files, each providing a
 * main() to construct one specific test scenario (single-thread
 * self-capture for now; worker-thread, multi-region, restore-side
 * scenarios later), reusing the same functions and the same struct
 * definitions rather than forking the file again.
 *
 * Region classification is a direct port of full_capture_test.c's
 * (2026-08-21) -- not re-explained here, see that file. The one deliberate
 * departure: capture buffers are allocated PER REGION (mmap'd
 * individually, sized exactly to that region's length), not one big
 * fixed-capacity buffer -- removes the "capture needs more than the
 * buffer's fixed cap" failure mode entirely. Side effect, not a separate
 * fix: no should_capture() self-exclusion is needed for these buffers at
 * all, unlike every earlier file's g_capture_buf -- classify_regions() runs
 * BEFORE any of them exist, so they can never appear in the classified
 * list to begin with.
 *
 * do_capture() only for now: single-threaded, self-inspecting, via raise()
 * (synchronous self-signal, same shape as full_capture_test.c) -- no
 * worker thread. pthread_addr in the header is this (the only) thread's
 * own pthread_self(), for whatever mode-D-style restore eventually wants
 * it.
 */
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <mach/thread_state.h>
#include <mach/mach_vm.h>
#include <mach/task.h>
#include <mach-o/dyld_images.h>
#include <libproc.h>
#include <sys/param.h>
#include <sys/mman.h>

#define MAX_REGIONS 256

typedef struct regs {
    arm_thread_state64_t gregs;
    arm_neon_state64_t neon;
    uint64_t tpidr;
} regs_t;

typedef struct {
    uint64_t addr, len;
    uint32_t protection;
} region_desc_t;

/* The one on-disk checkpoint header -- shared by every driver that
 * #includes this file, capture and (eventually) restore alike. */
typedef struct {
    uint32_t region_count;
    uint64_t capture_used;  /* total bytes across all regions -- informational
                                now, no shared buffer left to size-check against */
    regs_t   regs;
    uint64_t pthread_addr;  /* this thread's own pthread_self(), captured at signal time */
} checkpoint_header_t;

static region_desc_t g_regions[MAX_REGIONS];
static void*         g_region_bufs[MAX_REGIONS];

static uint32_t      g_region_count;
static regs_t        g_regs;
static uint64_t      g_pthread_addr;

/* --- region classification: verbatim from full_capture_test.c (2026-08-21) --- */

static bool in_shared_cache_submap(mach_vm_address_t addr) {
    mach_vm_address_t a = addr;
    mach_vm_size_t size = 0;
    natural_t depth = 0;
    vm_region_submap_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
    kern_return_t kr = mach_vm_region_recurse(mach_task_self(), &a, &size, &depth,
                                               (vm_region_recurse_info_t)&info, &count);
    return kr == KERN_SUCCESS && info.is_submap;
}

#define CACHE_SPAN_BYTES (8ull * 1024 * 1024 * 1024)
static bool in_shared_cache_range(mach_vm_address_t addr) {
    task_dyld_info_data_t info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    if (task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&info, &count) != KERN_SUCCESS) return false;
    struct dyld_all_image_infos* infos = (struct dyld_all_image_infos*)(uintptr_t)info.all_image_info_addr;
    uint64_t base = (uint64_t)infos->sharedCacheBaseAddress;
    return base != 0 && (uint64_t)addr >= base && (uint64_t)addr < base + CACHE_SPAN_BYTES;
}

static bool should_capture(mach_vm_address_t addr, mach_vm_size_t size,
                            const vm_region_submap_info_data_64_t* info) {
    (void)size;
    if (info->protection == VM_PROT_NONE) return false; /* guard pages, VA reservations: nothing to copy */

    if (info->external_pager) {
        /* File-backed. Our own binary's own segments resolve to a real path;
         * the dyld shared cache's regions don't -- see full_capture_test.c. */
        char buf[MAXPATHLEN];
        int ret = proc_regionfilename(getpid(), addr, buf, sizeof(buf));
        if (ret <= 0) return false;
    } else if (in_shared_cache_submap(addr) || in_shared_cache_range(addr)) {
        return false; /* privatized cache page -- see full_capture_test.c */
    }
    return true;
}

static void classify_regions(void) {
    g_region_count = 0;
    mach_vm_address_t addr = 0;
    while (g_region_count < MAX_REGIONS) {
        mach_vm_address_t a = addr;
        mach_vm_size_t size = 0;
        natural_t depth = 32;
        vm_region_submap_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        kern_return_t kr = mach_vm_region_recurse(mach_task_self(), &a, &size, &depth,
                                                   (vm_region_recurse_info_t)&info, &count);
        if (kr != KERN_SUCCESS) break;

        if (should_capture(a, size, &info)) {
            g_regions[g_region_count].addr = a;
            g_regions[g_region_count].len = size;
            g_regions[g_region_count].protection = (uint32_t)info.protection;
            g_region_count++;
        }
        addr = a + size;
    }
    if (g_region_count == MAX_REGIONS) {
        fprintf(stderr, "WARNING: hit MAX_REGIONS=%d, some regions were not classified\n", MAX_REGIONS);
    }
}

/* Allocate a dedicated, exactly-sized buffer for each classified region.
 * mmap, not malloc: malloc's own arena could carve this space out of an
 * ALREADY-classified heap region, silently aliasing something we're also
 * trying to capture. A fresh mmap is guaranteed to be its own distinct
 * vm_map entry, and (since it's created after classify_regions() already
 * ran) never needs excluding either -- it simply isn't in the list. */
static int allocate_region_bufs(void) {
    for (uint32_t i = 0; i < g_region_count; i++) {
        void* buf = mmap(NULL, g_regions[i].len, PROT_READ | PROT_WRITE,
                          MAP_ANON | MAP_PRIVATE, -1, 0);
        if (buf == MAP_FAILED) {
            fprintf(stderr, "mmap failed for region[%u] buffer (%llu bytes): %s\n",
                    i, (unsigned long long)g_regions[i].len, strerror(errno));
            return 1;
        }
        g_region_bufs[i] = buf;
    }
    return 0;
}

/* Signal handler: registers + memcpy of each already-classified region into
 * its own dedicated buffer. Nothing new decided here -- same "classify
 * first, handler only copies" principle as full_capture_test.c. */
static void capture_state(int sig, siginfo_t* info, void* ctx) {
    (void)sig; (void)info;
    g_regs.gregs = ((ucontext_t*)ctx)->uc_mcontext->__ss;
    g_regs.neon  = ((ucontext_t*)ctx)->uc_mcontext->__ns;
    __asm__ volatile ("mrs %0, tpidr_el0" : "=r" (g_regs.tpidr));
    g_pthread_addr = (uint64_t)(uintptr_t)pthread_self();

    for (uint32_t i = 0; i < g_region_count; i++) {
        memcpy(g_region_bufs[i], (void*)(uintptr_t)g_regions[i].addr, g_regions[i].len);
    }
}

/* Self-inspecting, single-threaded capture: classify -> allocate per-region
 * buffers -> self-signal (raise(), synchronous, runs on this same
 * thread/stack) -> write file. No worker thread -- pthread_addr in the
 * header is THIS (the only) thread's own pthread_self(). */
int do_capture(const char* path) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_flags = SA_SIGINFO;
    sa.__sigaction_u.__sa_sigaction = capture_state;
    if (sigaction(SIGUSR1, &sa, NULL) == -1) { perror("sigaction"); return 1; }

    classify_regions();
    uint64_t total = 0;
    for (uint32_t i = 0; i < g_region_count; i++) {
        total += g_regions[i].len;
        printf("  region[%u] [0x%llx,0x%llx) %.2fMB prot=%u\n", i,
               (unsigned long long)g_regions[i].addr,
               (unsigned long long)(g_regions[i].addr + g_regions[i].len),
               g_regions[i].len / 1048576.0, g_regions[i].protection);
    }
    printf("classified %u regions, %.2f MB total\n", g_region_count, total / 1048576.0);

    if (allocate_region_bufs() != 0) return 1;

    raise(SIGUSR1); /* synchronous self-signal -- handler runs on this same
                        thread/stack, then execution just continues here
                        (matches full_capture_test.c) */

    printf("captured %u regions, %.2f MB, pc=0x%llx sp=0x%llx tpidr=0x%llx pthread_addr=0x%llx\n",
           g_region_count, total / 1048576.0,
           (unsigned long long)g_regs.gregs.__pc, (unsigned long long)g_regs.gregs.__sp,
           (unsigned long long)g_regs.tpidr, (unsigned long long)g_pthread_addr);

    FILE* f = fopen(path, "wb");
    if (!f) { perror("fopen"); return 1; }
    checkpoint_header_t hdr = {
        .region_count = g_region_count,
        .capture_used = total,
        .regs = g_regs,
        .pthread_addr = g_pthread_addr,
    };
    fwrite(&hdr, sizeof(hdr), 1, f);
    fwrite(g_regions, sizeof(region_desc_t), g_region_count, f);
    for (uint32_t i = 0; i < g_region_count; i++) {
        fwrite(g_region_bufs[i], 1, g_regions[i].len, f);
    }
    fclose(f);
    printf("checkpoint written to %s (pthread_addr=0x%llx)\n", path, (unsigned long long)g_pthread_addr);

    return 0;
}
