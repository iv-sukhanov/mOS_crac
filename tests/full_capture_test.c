/* Whole-process checkpoint capture, single-threaded target (2026-08-21).
 *
 * Earlier capture (sim_capture_test.c) grabbed a fixed-size stack window and
 * a fixed-size code window around one thread's PC/SP -- enough to prove the
 * restore mechanism, not enough to run arbitrary code (a spliced call
 * resolves through the calling process's own __DATA_CONST-relative bound
 * pointer, computed against *that* process's own load address -- see
 * docs/006 "Part 1"). This captures every private (non-shared-cache) region
 * of the process instead, the way minicriu itself restores every PT_LOAD,
 * not just a leaf function's page.
 *
 * Single-threaded target means no separate worker thread / barrier needed
 * at all (contrast sim_capture_test.c): the one thread there is signals
 * itself directly (raise(), not pthread_kill() from another thread) and the
 * handler runs synchronously on that same thread's own stack, so "capture,
 * then keep running" falls out for free.
 *
 * Region classification (which regions to skip) happens *before* the
 * self-signal, in ordinary code -- not inside the handler, which only
 * memcpy()s an already-known list. That's not a new risk: mach_vm_region_
 * recurse() is already called from inside a signal handler elsewhere in
 * this codebase (sim_capture_test.c's capture_state() -> probe_contiguous_
 * len()) without incident, but proc_regionfilename() (needed to tell the
 * shared cache apart from our own binary's segments, see below) has no such
 * precedent here, so it stays out of the handler on principle.
 */
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <mach/thread_state.h>
#include <mach/mach_vm.h>
#include <mach/task.h>
#include <mach-o/dyld_images.h>
#include <libproc.h>
#include <sys/param.h>
#include <sys/mman.h>

#define MAX_REGIONS       256
#define CAPTURE_BUF_BYTES (512u * 1024 * 1024)  /* static/BSS, not malloc'd --
    see the note on g_capture_buf below for why. 512MB has real headroom over
    the 337MB actually observed on this machine 2026-08-21 (two ~128MB
    malloc-nanozone VA reservations dominate it) */

typedef struct regs {
    arm_thread_state64_t gregs;
    arm_neon_state64_t neon;
    uint64_t tpidr;
} regs_t;

typedef struct {
    uint64_t addr, len;      /* page-aligned, as reported by the kernel */
    uint32_t protection;     /* VM_PROT_* bits -- same values as PROT_* */
    uint32_t _pad;
} region_desc_t;

typedef struct {
    uint32_t region_count;
    uint32_t _pad;
    uint64_t capture_used;      /* bytes actually copied into g_capture_buf */
    regs_t   regs;
} checkpoint_header_t;

static bool is_restore;
static region_desc_t g_regions[MAX_REGIONS];
static uint32_t g_region_count;
static regs_t g_regs;
/* An explicit mmap(), not a static/BSS array -- found necessary the hard
 * way 2026-08-21 (NOTES.md): a plain `static uint8_t g_capture_buf[...]`
 * gets packed by the linker right next to whatever small globals precede
 * it in BSS (confirmed directly: a reproduction had a 4-byte-int global and
 * the capture buffer share the exact same 16KB kernel-reported region).
 * should_capture()'s self-exclusion then throws out that *whole* region --
 * g_region_count/g_regs/etc. included, since they're in the same region as
 * part of the buffer -- which is exactly why a restored process was reading
 * those back as zero after resuming. A separate mmap() is a genuinely
 * distinct vm_map entry (confirmed: lands tens of MB away from everything
 * else), so excluding it can't collide with anything real ever again.
 * Called once, at the very start of main(), before anything else runs --
 * still well before classify_regions(), so the earlier ordering concern
 * (an allocation appearing *after* classification, unable to be excluded by
 * address or reflected in the captured list) doesn't apply here. */
static uint8_t* g_capture_buf;
static const uint64_t g_capture_buf_cap = CAPTURE_BUF_BYTES;
static uint64_t g_capture_used;

static int g_heap_val_index = -1;   /* which g_regions[] entry holds it, for the self-check */
static uint64_t g_heap_val_off;     /* byte offset of heap_val within that region */

/* Is this address structurally inside a nested submap? A depth=0 (non-
 * recursing) mach_vm_region_recurse resolves a plain private address (heap,
 * stack, our own __DATA) directly, is_submap=0. The dyld shared cache is
 * mapped via nested submaps (established 2026-08-11/12) -- any address
 * inside it, even a leaf page that's since been privatized via copy-on-
 * write, resolves at depth=0 to the *submap's own* boundary, is_submap=1.
 * Confirmed directly 2026-08-21: our own data/code/stack all is_submap=0;
 * a known CoW'd-from-cache page resolved to a 640MB is_submap=1 entry. */
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

/* Complementary check for a CoW'd cache page that's fully detached from the
 * submap (is_submap=0 too -- found empirically 2026-08-21: not every
 * privatized cache page stays nested, "unused system shared lib __DATA" per
 * vmmap either way, but only *some* still resolve as a submap boundary).
 * sharedCacheBaseAddress comes from task_info(TASK_DYLD_INFO)'s
 * dyld_all_image_infos -- a real, already-ASLR-slid runtime address,
 * confirmed directly to match where the cache's own regions actually start
 * on this machine. CACHE_SPAN_BYTES is a generous (not exact) guess at the
 * cache's extent -- the combined dyld_shared_cache_arm64e[.01/.02] files
 * observed on this machine sum to ~5.6GB; 8GB covers that with headroom.
 * A generous guess, not a precise bound, is deliberate: this only ever
 * excludes candidates that already passed every other check, so a false
 * positive here means capturing a few bytes of cache-adjacent memory
 * unnecessarily, not missing something real. */
#define CACHE_SPAN_BYTES (8ull * 1024 * 1024 * 1024)
static bool in_shared_cache_range(mach_vm_address_t addr) {
    task_dyld_info_data_t info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    if (task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&info, &count) != KERN_SUCCESS) return false;
    struct dyld_all_image_infos* infos = (struct dyld_all_image_infos*)(uintptr_t)info.all_image_info_addr;
    uint64_t base = (uint64_t)infos->sharedCacheBaseAddress;
    return base != 0 && (uint64_t)addr >= base && (uint64_t)addr < base + CACHE_SPAN_BYTES;
}

/* Decide whether a region is worth capturing. Not signal-handler code --
 * called only during the pre-signal classification pass. */
static bool should_capture(mach_vm_address_t addr, mach_vm_size_t size,
                            const vm_region_submap_info_data_64_t* info) {
    if (info->protection == VM_PROT_NONE) return false; /* guard pages, VA reservations: nothing to copy */

    /* Our own scratch buffer (and the rest of this driver's static data) is
     * this process's own bookkeeping, not the target's state -- don't
     * capture a copy of ourselves. */
    uint64_t buf_lo = (uint64_t)(uintptr_t)g_capture_buf;
    uint64_t buf_hi = buf_lo + CAPTURE_BUF_BYTES;
    if ((uint64_t)addr < buf_hi && buf_lo < (uint64_t)addr + size) return false;

    if (info->external_pager) {
        /* File-backed. Our own binary's own segments resolve to a real
         * path; the dyld shared cache's regions don't -- confirmed
         * directly on this machine 2026-08-21 (NOTES.md): libSystem.B.
         * dylib isn't even a file on disk anymore, its code lives only in
         * the cache blob, and proc_regionfilename() can't name a path for
         * memory backed that way. The cache doesn't need capturing anyway
         * (boot-scoped, already at a fixed address in every process --
         * 2026-08-12). Known limitation: this also skips any *other*
         * genuinely file-backed-but-unresolvable mapping, if one exists;
         * none has been seen in practice on this machine. */
        char buf[MAXPATHLEN];
        int ret = proc_regionfilename(getpid(), addr, buf, sizeof(buf));
        if (ret <= 0) return false;
    } else if (in_shared_cache_submap(addr) || in_shared_cache_range(addr)) {
        /* Caught what external_pager alone misses (2026-08-21, found from a
         * real restore failure -- EACCES on mmap(MAP_FIXED), a different
         * signature than the usual malloc-guard-page ENOMEM): a shared-
         * cache page that's been privatized via copy-on-write reports
         * external_pager=0 (genuinely private now, at the VM level), so the
         * branch above never even runs for it. Two checks, not one: some
         * such pages stay nested in the cache's own submap (caught by
         * in_shared_cache_submap), others fully detach from it (caught only
         * by the address-range check) -- both observed directly on this
         * machine for what vmmap itself labels the same way either case.
         * It's dyld/libSystem's own internal artifact of how the loader
         * happened to privatize one page, not anything the checkpointed
         * program logically depends on; the restoring process's own fresh
         * dyld privatizes its own copy the same way if it ever needs to. */
        return false;
    }
    return true;
}

static void classify_regions(void* heap_val_addr) {
    g_region_count = 0;
    g_heap_val_index = -1;
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
            uint64_t hv = (uint64_t)(uintptr_t)heap_val_addr;
            if (hv >= (uint64_t)a && hv < (uint64_t)a + size) {
                g_heap_val_index = (int)g_region_count;
                g_heap_val_off = hv - (uint64_t)a;
            }
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

/* Signal handler: registers + memcpy of the already-classified region list
 * only. No Mach RPCs, no libproc, nothing not already used from inside a
 * handler elsewhere in this codebase. */
static void capture_state(int sig, siginfo_t* info, void* ctx) {
    (void)sig; (void)info;
    g_regs.gregs = ((ucontext_t*)ctx)->uc_mcontext->__ss;
    g_regs.neon  = ((ucontext_t*)ctx)->uc_mcontext->__ns;
    __asm__ volatile ("mrs %0, tpidr_el0" : "=r" (g_regs.tpidr));

    uint64_t used = 0;
    uint32_t i;
    for (i = 0; i < g_region_count; i++) {
        uint64_t len = g_regions[i].len;
        if (used + len > g_capture_buf_cap) break; /* shouldn't happen -- buffer is sized
                                                        exactly off this same region list
                                                        moments earlier -- but stop cleanly
                                                        rather than overrun if it ever does */
        memcpy(g_capture_buf + used, (void*)(uintptr_t)g_regions[i].addr, len);
        used += len;
    }
    g_region_count = i;    /* truncate the descriptor list to match what actually got copied */
    g_capture_used = used;
}

static int do_checkpoint(const char* path, void* heap_val_addr) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_flags = SA_SIGINFO;
    sa.__sigaction_u.__sa_sigaction = capture_state;
    if (sigaction(SIGUSR1, &sa, NULL) == -1) { perror("sigaction"); return 1; }

    classify_regions(heap_val_addr);
    uint64_t total = 0;
    for (uint32_t i = 0; i < g_region_count; i++) {
        total += g_regions[i].len;
        printf("  region[%u] [0x%llx,0x%llx) %.2fMB prot=%u\n", i,
               g_regions[i].addr, g_regions[i].addr + g_regions[i].len,
               g_regions[i].len / 1048576.0, g_regions[i].protection);
    }
    printf("classified %u regions to capture, %.2f MB total\n", g_region_count, total / 1048576.0);
    if (g_heap_val_index < 0) {
        fprintf(stderr, "heap_val's address wasn't inside any captured region -- bug\n");
        return 1;
    }

    if (total > g_capture_buf_cap) {
        fprintf(stderr, "capture needs %.2fMB, buffer is only %.2fMB -- bump CAPTURE_BUF_BYTES\n",
                total / 1048576.0, g_capture_buf_cap / 1048576.0);
        return 1;
    }

    raise(SIGUSR1); /* synchronous self-signal: handler runs on this same
                        thread/stack, then execution just continues here */

    printf("captured %u regions, %.2f MB, pc=0x%llx sp=0x%llx\n",
           g_region_count, g_capture_used / 1048576.0,
           g_regs.gregs.__pc, g_regs.gregs.__sp);

    /* Self-check, same idiom as sim_capture_test.c's stack checksum: read
     * the captured bytes back out of g_capture_buf at heap_val's known
     * offset and confirm they match what's still live in real memory. */
    uint64_t buf_off = 0;
    for (int i = 0; i < g_heap_val_index; i++) buf_off += g_regions[i].len;
    buf_off += g_heap_val_off;
    int captured_val, live_val = *(int*)heap_val_addr;
    memcpy(&captured_val, g_capture_buf + buf_off, sizeof(captured_val));
    printf("  heap_val self-check: live=%d captured=%d (%s)\n",
           live_val, captured_val, live_val == captured_val ? "MATCH" : "MISMATCH");

    is_restore = !(live_val == captured_val);
    if (!is_restore) {
        FILE* f = fopen(path, "wb");
        if (!f) { perror("fopen"); return 1; }
        checkpoint_header_t hdr = { .region_count = g_region_count, .regs = g_regs, .capture_used = g_capture_used };
        fwrite(&hdr, sizeof(hdr), 1, f);
        fwrite(g_regions, sizeof(region_desc_t), g_region_count, f);
        fwrite(g_capture_buf, 1, g_capture_used, f);
        fclose(f);
        printf("checkpoint written to %s\n", path);
    } else {
        printf("heap_val self-check failed, not writing checkpoint\n");
    }


    return 0;
}

static volatile uint64_t g_global_counter = 0; /* exercises __DATA capture */

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\n", argv[0]);
        return 2;
    }

    /* First thing, deliberately -- see the note on g_capture_buf's
     * declaration for why this can't be a static array. */
    g_capture_buf = mmap(NULL, CAPTURE_BUF_BYTES, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (g_capture_buf == MAP_FAILED) { perror("mmap capture buffer"); return 1; }

    int* heap_val = malloc(sizeof(int));
    if (!heap_val) { perror("malloc"); return 1; }
    *heap_val = 42;

    if (do_checkpoint(argv[1], heap_val) != 0) return 1;

    printf("post-checkpoint: heap_val=%d, running...\n", *heap_val);
    uint8_t times = 0;
    for (;;) {
        g_global_counter++;
        if (g_global_counter % 200000000ULL == 0) {
            printf("  alive: global_counter=%llu heap_val=%d\n", g_global_counter, *heap_val);
            times++;
        }

        if (times > 4) {
            if (is_restore) pause();    
            exit(0);
        } /* exit normally after a few iterations, so the test harness doesn't think it hung */
    }
    return 0; /* unreachable */
}
