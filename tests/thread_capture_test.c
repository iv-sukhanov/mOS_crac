/* Single-thread checkpoint capture + mode-D restore test (2026-08-25).
 *
 * Everything up to now (full_capture_test.c/full_restore_test.c, docs/006
 * "Part 1") restored a whole process by hijacking main() directly via
 * raise() -- proven to mechanically work but with a known, unfixed problem
 * (2026-08-21: hijacking main() produces SIGKILL-immune stuck processes,
 * since main()'s own return/exit sequence runs against a completely
 * different, restored stack the kernel never registered).
 *
 * This captures a *worker* thread instead (never main), the same shape as
 * every earlier proven-working test (sim_capture_test.c, mode C). The new
 * piece under test on the restore side (see thread_restore_test.c) is mode
 * D: recreate the worker via a self-signed __bsdthread_create() (docs/007)
 * instead of ever letting main() get hijacked, seed its saved state via
 * thread_set_state() on a suspended thread, and specifically check whether
 * TPIDR_EL0-based `__thread` storage survives -- thread_set_state has no
 * flavor for TPIDR_EL0 (confirmed 2026-08-25 by grepping the actual SDK
 * headers: arm_thread_state64_t has no tpidr field at all), so this needs
 * the same seed-trampoline trick thread_create_test.c's mode b-tls already
 * proved (2026-08-17) -- see thread_restore_test.c.
 *
 * Capture side is otherwise a direct copy of full_capture_test.c's whole-
 * process region classification/capture -- deliberately not re-explained
 * here, see that file's own comments. Compiled WITHOUT -arch arm64e, same
 * as every other capture/restore file in this codebase: keeps
 * arm_thread_state64_t in its plain (non-opaque) layout, matching what
 * gets read back on the restore side without needing ptrauth accessor
 * macros (see thread_restore_test.c's own note on why that file needs
 * -arch arm64e for a *different* reason and works around this).
 */
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <string.h>
#include <mach/thread_state.h>
#include <mach/mach_vm.h>
#include <mach/task.h>
#include <mach-o/dyld_images.h>
#include <libproc.h>
#include <sys/param.h>
#include <sys/mman.h>

#define MAX_REGIONS       256
#define CAPTURE_BUF_BYTES (512u * 1024 * 1024)

typedef struct regs {
    arm_thread_state64_t gregs;
    arm_neon_state64_t neon;
    uint64_t tpidr;
} regs_t;

typedef struct {
    uint64_t addr, len;
    uint32_t protection;
} region_desc_t;

#define WORKER_TLS_VALUE 99

// Must match thread_restore_test.c's checkpoint_header_t byte-for-byte.
typedef struct {
    uint32_t region_count;
    uint64_t capture_used;
    regs_t   regs;
    uint64_t worker_struct_addr; /* worker's pthread_self(), for mode-D self-sign+recreate */
} checkpoint_header_t;

static region_desc_t g_regions[MAX_REGIONS];
static uint32_t g_region_count;
static regs_t g_regs;
static uint8_t* g_capture_buf;    /* mmap'd, not static/BSS -- see full_capture_test.c 2026-08-21 */
static const uint64_t g_capture_buf_cap = CAPTURE_BUF_BYTES;
static uint64_t g_capture_used;

static uint64_t g_worker_struct_addr;
static atomic_bool g_worker_ready = false;
static atomic_bool g_captured = false;

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
    if (info->protection == VM_PROT_NONE) return false;

    uint64_t buf_lo = (uint64_t)(uintptr_t)g_capture_buf;
    uint64_t buf_hi = buf_lo + CAPTURE_BUF_BYTES;
    if ((uint64_t)addr < buf_hi && buf_lo < (uint64_t)addr + size) return false;

    if (info->external_pager) {
        char buf[MAXPATHLEN];
        int ret = proc_regionfilename(getpid(), addr, buf, sizeof(buf));
        if (ret <= 0) return false;
    } else if (in_shared_cache_submap(addr) || in_shared_cache_range(addr)) {
        return false;
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

/* Signal handler -- runs on the WORKER thread's own stack, delivered via
 * pthread_kill() from main (async, unlike full_capture_test.c's self-
 * raise()), matching thread_test.c's already-proven pthread_kill capture
 * idiom. classify_regions() already ran (in main, before the signal), so
 * this only memcpy()s the known list -- same "nothing new inside the
 * handler" principle as full_capture_test.c. */
static void capture_state(int sig, siginfo_t* info, void* ctx) {
    (void)sig; (void)info;
    g_regs.gregs = ((ucontext_t*)ctx)->uc_mcontext->__ss;
    g_regs.neon  = ((ucontext_t*)ctx)->uc_mcontext->__ns;
    __asm__ volatile ("mrs %0, tpidr_el0" : "=r" (g_regs.tpidr));

    uint64_t used = 0;
    uint32_t i;
    for (i = 0; i < g_region_count; i++) {
        uint64_t len = g_regions[i].len;
        if (used + len > g_capture_buf_cap) break;
        memcpy(g_capture_buf + used, (void*)(uintptr_t)g_regions[i].addr, len);
        used += len;
    }
    g_region_count = i;
    g_capture_used = used;

    atomic_store(&g_captured, true);
}

static __thread int g_tls_val;

static void* worker_fn(void* arg) {
    (void)arg;
    g_tls_val = WORKER_TLS_VALUE;
    g_worker_struct_addr = (uint64_t)(uintptr_t)pthread_self();
    atomic_store(&g_worker_ready, true);

    uint64_t counter = 0;
    for (;;) {
        counter++;
        if (counter % 200000000ULL == 0) {
            printf("  worker alive: counter=%llu tls_val=%d\n",
                   (uint64_t)counter, g_tls_val);
        }
    }
    return NULL; /* unreachable */
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\n", argv[0]);
        return 2;
    }

    g_capture_buf = mmap(NULL, CAPTURE_BUF_BYTES, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (g_capture_buf == MAP_FAILED) { perror("mmap capture buffer"); return 1; }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_flags = SA_SIGINFO;
    sa.__sigaction_u.__sa_sigaction = capture_state;
    if (sigaction(SIGUSR1, &sa, NULL) == -1) { perror("sigaction"); return 1; }

    pthread_t worker;
    if (pthread_create(&worker, NULL, worker_fn, NULL) != 0) { perror("pthread_create"); return 1; }
    while (!atomic_load(&g_worker_ready)) usleep(1000);

    classify_regions();
    uint64_t total = 0;
    for (uint32_t i = 0; i < g_region_count; i++) {
        total += g_regions[i].len;
        printf("  region[%u] [0x%llx,0x%llx) %.2fMB prot=%u\n", i,
               (uint64_t)g_regions[i].addr,
               (uint64_t)(g_regions[i].addr + g_regions[i].len),
               g_regions[i].len / 1048576.0, g_regions[i].protection);
    }
    printf("classified %u regions, %.2f MB total; worker struct_addr=0x%llx\n",
           g_region_count, total / 1048576.0, (uint64_t)g_worker_struct_addr);
    if (total > g_capture_buf_cap) {
        fprintf(stderr, "capture needs %.2fMB, buffer is only %.2fMB\n",
                total / 1048576.0, g_capture_buf_cap / 1048576.0);
        return 1;
    }

    pthread_kill(worker, SIGUSR1);
    while (!atomic_load(&g_captured)) usleep(1000);

    printf("captured %u regions, %.2f MB, pc=0x%llx sp=0x%llx tpidr=0x%llx\n",
           g_region_count, g_capture_used / 1048576.0,
           (uint64_t)g_regs.gregs.__pc, (uint64_t)g_regs.gregs.__sp,
           (uint64_t)g_regs.tpidr);

    FILE* f = fopen(argv[1], "wb");
    if (!f) { perror("fopen"); return 1; }
    checkpoint_header_t hdr = {
        .region_count = g_region_count,
        .capture_used = g_capture_used,
        .regs = g_regs,
        .worker_struct_addr = g_worker_struct_addr,
    };
    fwrite(&hdr, sizeof(hdr), 1, f);
    fwrite(g_regions, sizeof(region_desc_t), g_region_count, f);
    fwrite(g_capture_buf, 1, g_capture_used, f);
    fclose(f);
    printf("checkpoint written to %s (worker_struct_addr=0x%llx, expected tls_val=%d)\n",
           argv[1], (uint64_t)g_worker_struct_addr, WORKER_TLS_VALUE);

    /* Let the worker keep running a little, same as full_capture_test.c, so the checkpoint
     * being written doesn't race with the process exiting before fwrite() lands. */
    sleep(2);
    return 0;
}
