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
 *
 * Needs -arch arm64e (2026-09-03, Ivan's call): munge (below) needs a real
 * ptrauth_sign_unauthenticated(), which is compile-time gated on
 * __has_feature(ptrauth_calls) -- confirmed empirically, not assumed: it
 * doesn't even compile without -arch arm64e, let alone silently no-op (see
 * NOTES.md 2026-09-03). Consequence accepted, not yet acted on: captured
 * pc/sp in regs_t are now genuinely PAC-signed bit patterns (this process
 * is really arm64e), not the plain raw addresses thread_capture_test.c's
 * deliberately-non-arm64e captures produce -- correctly interpreting them
 * on the restore side (strip/resign via the FP chain, per lr_resign_test.c)
 * is deferred, not done here.
 */
#include <pthread.h>
#include <ptrauth.h>
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
#include <sysexits.h>
#include <mach/mach.h>

#if !__has_feature(ptrauth_calls)
#error "build with -arch arm64e -- see file header for why this is required"
#endif

#define MAX_REGIONS 256
#define STACK_SIZE  (256 * 1024)

#define PTHREAD_START_CUSTOM    0x01000000u
#define PTHREAD_START_SUSPENDED 0x20000000u

extern void *__bsdthread_create(void *func, void *func_arg, void *stack,
                                 void *pthread, uint32_t flags);

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
    uint64_t munge;         /* this thread's own live munge (docs/007 algebra: stored_sig XOR
                                sign_for_addr(pthread_addr)), captured alongside pthread_addr.
                                Belongs to THIS (capture) process's own key -- a restore process
                                must still recompute its OWN munge fresh from its OWN live thread
                                (thread_restore_test.c already does this correctly, munge/G is
                                per-process, not portable). Captured anyway, for future use: e.g.
                                re-interpreting some OTHER munge-XORed signed value that shows up
                                elsewhere in captured __DATA, which needs the ORIGINAL process's
                                munge to undo, not the restore process's. Not yet consumed by
                                anything -- see file header re: -arch arm64e. */
    uint64_t sentinel;      /* address of a stack-local flag in do_capture() (Ivan, 2026-09-03):
                                since this thread self-signals then keeps running the same code
                                (matching full_capture_test.c's pattern), a restore that resumes
                                this checkpoint by seeding PC back to right after raise() would
                                otherwise fall straight into fopen/fwrite again and re-write a
                                checkpoint. Restore pokes a 1 at this exact address (the stack
                                region restores it to the captured 0 first); do_capture() checks
                                it right after raise() and skips writing if it's no longer 0. */
} checkpoint_header_t;

static region_desc_t g_regions[MAX_REGIONS];
static void*         g_region_bufs[MAX_REGIONS];

static uint32_t      g_region_count;
static regs_t        g_regs;
static uint64_t      g_pthread_addr;
static uint64_t      g_munge;

/* Same (addr, key, discriminator) triple as libpthread's own
 * _pthread_init_signature/_pthread_validate_signature (docs/007), and as
 * thread_restore_test.c's own copy -- must match exactly, this is what
 * makes the XOR algebra below actually recover the real munge/G. */
static uintptr_t sign_for_addr(uintptr_t addr) {
    return (uintptr_t)ptrauth_sign_unauthenticated(
        (void *)addr, ptrauth_key_process_dependent_data,
        ptrauth_string_discriminator("pthread.signature"));
}

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

/* A generous (not exact) guess at the cache's extent -- the combined
 * dyld_shared_cache_arm64e[.01/.02] files sum to ~5.6GB on this machine;
 * 8GB covers that with headroom. Generous is deliberate, not sloppy: this
 * only ever excludes candidates that already passed every other check, so
 * a false positive here means capturing a few bytes of cache-adjacent
 * memory unnecessarily, not missing something real (full_capture_test.c,
 * 2026-08-21). */
#define CACHE_SPAN_BYTES (8ull * 1024 * 1024 * 1024)
static bool in_shared_cache_range(mach_vm_address_t addr) {
    task_dyld_info_data_t info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    if (task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&info, &count) != KERN_SUCCESS) return false;
    struct dyld_all_image_infos* infos = (struct dyld_all_image_infos*)(uintptr_t)info.all_image_info_addr;
    uint64_t base = (uint64_t)infos->sharedCacheBaseAddress;
    return base != 0 && (uint64_t)addr >= base && (uint64_t)addr < base + CACHE_SPAN_BYTES;
}

static bool should_capture(mach_vm_address_t addr, const vm_region_submap_info_data_64_t* info) {
    if (info->protection == VM_PROT_NONE) return false; /* guard pages, VA reservations: nothing to copy */

    if (info->external_pager) {
        /* File-backed. Our own binary's own segments resolve to a real path;
         * the dyld shared cache's regions don't -- see full_capture_test.c. */
        char buf[MAXPATHLEN];
        int ret = proc_regionfilename(getpid(), addr, buf, sizeof(buf));
        if (ret <= 0 && (info->protection & VM_PROT_EXECUTE || info->protection == VM_PROT_READ)) {
            // printf("  skipped external-pager region at 0x%llx-0x%llx prot=%u dirty=%u\n",
            //        (uint64_t)addr, (uint64_t)addr + size, info->protection, info->pages_dirtied);
            return false;
        }
    } else if (in_shared_cache_submap(addr) || in_shared_cache_range(addr)) {
        if (info->protection & VM_PROT_EXECUTE) {
            /* Not expected in practice (this branch is only reached for
             * non-external-pager pages, and ordinary cache code should
             * stay pager-backed/pristine) -- printed so a real occurrence
             * doesn't pass by silently. */
            printf("  note: executable, non-external-pager region in shared-cache "
                   "range at 0x%llx prot=%u -- capturing, not filtered\n",
                   (uint64_t)addr, info->protection);
        }
        if (info->protection == VM_PROT_READ) {
            // printf("  skipped read-only shared-cache region at 0x%llx prot=%u dirty=%u\n",
            //        (uint64_t)addr, info->protection, info->pages_dirtied);
            return false;
        }
        return info->protection != VM_PROT_READ; //exclude read-only shared-cache pages 
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

        if (should_capture(a, &info)) {
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
                    i, (uint64_t)g_regions[i].len, strerror(errno));
            return 1;
        }
        g_region_bufs[i] = buf;
    }
    return 0;
}

/* Release the per-region buffers once they're written out. Not strictly
 * necessary for a one-shot driver that exits right after do_capture()
 * returns (the OS reclaims everything on exit either way) -- but
 * do_capture() is meant to be reusable across different test scenarios,
 * some of which may call it more than once or keep running afterward, so
 * leaking tens of MB of anonymous mappings per call would be a real,
 * accumulating problem there. */
static void free_region_bufs(void) {
    for (uint32_t i = 0; i < g_region_count; i++) {
        if (g_region_bufs[i]) {
            munmap(g_region_bufs[i], g_regions[i].len);
            g_region_bufs[i] = NULL;
        }
    }
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
    uintptr_t stored_sig = *(uintptr_t *)(uintptr_t)g_pthread_addr;
    g_munge = stored_sig ^ sign_for_addr((uintptr_t)g_pthread_addr);

    for (uint32_t i = 0; i < g_region_count; i++) {
        memcpy(g_region_bufs[i], (void*)(uintptr_t)g_regions[i].addr, g_regions[i].len);
    }
}

/* Self-inspecting, single-threaded capture: classify -> allocate per-region
 * buffers -> self-signal (raise(), synchronous, runs on this same
 * thread/stack) -> write file. No worker thread -- pthread_addr in the
 * header is THIS (the only) thread's own pthread_self(). */
int do_capture(const char* path) {
    /* volatile: must force a real memory load on every check below, not a
     * cached register value from before raise(). A restored thread's
     * registers come from thread_set_state()'s copied GPRs, seeded from
     * whatever was resident at capture time -- if this value had been
     * sitting in a register rather than reloaded from the stack, resume
     * would see that stale cached value forever, never the fresh 1 a
     * restore process pokes into the actual stack slot. */
    volatile int restored_flag = 0;
    uint64_t sentinel = (uint64_t)(uintptr_t)&restored_flag;

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
               (uint64_t)g_regions[i].addr,
               (uint64_t)(g_regions[i].addr + g_regions[i].len),
               g_regions[i].len / (1024.0 * 1024.0), g_regions[i].protection);
    }
    printf("classified %u regions, %.2f MB total\n", g_region_count, total / (1024.0 * 1024.0));

    if (allocate_region_bufs() != 0) return 1;

    raise(SIGUSR1); /* synchronous self-signal -- handler runs on this same
                        thread/stack, then execution just continues here
                        (matches full_capture_test.c) */

    /* A restore that resumes this exact checkpoint seeds PC back to right
     * here (or thereabouts) and pokes a 1 into *sentinel before doing so --
     * see checkpoint_header_t's own comment. Skip re-writing a checkpoint
     * in that case; a genuinely fresh call to do_capture() later gets its
     * own new stack frame and a fresh restored_flag=0, so no reset needed. */
    if (restored_flag != 0) {
        printf("resumed from a restore -- not writing a checkpoint again\n");
        /* NOT free_region_bufs() here (2026-09-03 fix): g_region_bufs[] is
         * ordinary __DATA, captured like any other global -- by this point
         * remap_regions() has already overwritten it with the ORIGINAL
         * capturing process's stale pointer values. Calling munmap() on
         * those would be operating on garbage addresses from a different
         * process's address space -- best case a harmless failed syscall,
         * worst case it coincidentally unmaps something real here. Nothing
         * was ever allocated in THIS process's g_region_bufs[] to free. */
        return 0;
    }

    /* arm64e's arm_thread_state64_t has no plain __pc/__sp fields -- pc/sp
     * are opaque (ptrauth-signed), need the real accessor macros, not raw
     * field access (thread_restore_test.c's own plain-cast reads only work
     * because ITS source bytes come from a plain-arm64 capture file; this
     * process's own live gregs here genuinely are signed). */
    printf("captured %u regions, %.2f MB, pc=%p sp=%p tpidr=0x%llx pthread_addr=0x%llx munge=0x%llx\n",
           g_region_count, total / (1024.0 * 1024.0),
           arm_thread_state64_get_pc_fptr(g_regs.gregs),
           (void*)arm_thread_state64_get_sp(g_regs.gregs),
           (uint64_t)g_regs.tpidr, (uint64_t)g_pthread_addr, (uint64_t)g_munge);

    FILE* f = fopen(path, "wb");
    if (!f) { perror("fopen"); free_region_bufs(); return 1; }
    checkpoint_header_t hdr = {
        .region_count = g_region_count,
        .capture_used = total,
        .regs = g_regs,
        .pthread_addr = g_pthread_addr,
        .munge = g_munge,
        .sentinel = sentinel,
    };
    fwrite(&hdr, sizeof(hdr), 1, f);
    fwrite(g_regions, sizeof(region_desc_t), g_region_count, f);
    for (uint32_t i = 0; i < g_region_count; i++) {
        fwrite(g_region_bufs[i], 1, g_regions[i].len, f);
    }
    fclose(f);
    printf("checkpoint written to %s (pthread_addr=0x%llx)\n", path, (uint64_t)g_pthread_addr);

    free_region_bufs();
    pause();
    return 0;
}

/* --- do_restore() (2026-09-03) ---
 *
 * Same self-signed __bsdthread_create() (docs/007) as thread_restore_test.c
 * for a real, validly-signed thread identity -- but a different resume
 * mechanism (Ivan's call): instead of a hand-rolled asm trampoline seeding
 * PC/SP/TPIDR via thread_set_state() (thread_restore_test.c's
 * tls_seed_trampoline), signal the thread WHILE STILL SUSPENDED, then
 * thread_resume() it -- the queued signal delivers the instant it resumes
 * (NOTES.md 2026-09-01/03), before the kernel-initialized _pthread_start
 * path ever runs dummy_entry_fn for real. The handler just overwrites the
 * delivered ucontext_t wholesale (mode C's classic technique,
 * full_restore_test.c's restore_state()) and returns -- sigreturn applies
 * it. Simpler than the trampoline: no opaque-PC-signing dance needed
 * (capture and restore are both arm64e now, same struct layout on both
 * sides, a whole-struct copy is well-typed), and no separate TPIDR seed
 * step (the handler can just execute `msr` directly, unlike
 * thread_set_state which has no TPIDR_EL0 flavor at all).
 *
 * Ordering (Ivan's call, 2026-09-03): remap non-cache regions -> sign the
 * worker struct with THIS process's own live munge (recovered from main's
 * own already-valid struct, same algebra as thread_restore_test.c) ->
 * __bsdthread_create() (succeeds: the munge global is still this
 * process's own, untouched) -> remap_cache_regions() (clobbers the munge
 * global with hdr.munge, the CAPTURED process's own value) -> re-sign the
 * SAME struct a second time, this time with hdr.munge directly (no
 * recovery needed, it's already in the header) so the struct's signature
 * stays consistent with whatever the global now actually holds. Two signs
 * of one field, not a global patch -- avoids needing
 * thread_restore_test.c's PTHREAD_LIST_LOCK_CACHE_OFFSET-style direct
 * addressing of the munge global entirely.
 *
 * Expected to fail at this stage, on purpose (Ivan's framing): captured
 * pc (and any stack-resident LR) are genuinely PAC-signed under the
 * CAPTURING process's own key (cr_test.c is arm64e now, unlike
 * thread_capture_test.c) -- this whole session's LR-signing research
 * (lr_sign_probe.c, lr_resign_test.c) exists to eventually fix this, not
 * done here. Goal for this pass: confirm everything up to and including
 * the resume mechanism itself works, and observe the predicted signature
 * failure directly rather than assume it. */

static uint8_t* g_restore_buf;
static uint64_t g_region_off[MAX_REGIONS];

static bool is_cache_region(uint64_t addr) {
    return in_shared_cache_range((mach_vm_address_t)addr) || in_shared_cache_submap((mach_vm_address_t)addr);
}

/* Non-cache regions only -- verbatim shape from thread_restore_test.c's
 * remap_regions(). Cache regions are deferred to remap_cache_regions(),
 * called separately after __bsdthread_create() (see file header re:
 * ordering). */
static int remap_regions(uint32_t region_count) {
    for (uint32_t i = 0; i < region_count; i++) {
        uint64_t addr = g_regions[i].addr;
        uint64_t len = g_regions[i].len;
        int prot = (int)g_regions[i].protection;
        uint64_t offset = g_region_off[i];

        if (is_cache_region(addr)) continue;

        void* got = mmap((void*)(uintptr_t)addr, len, PROT_READ | PROT_WRITE,
                         MAP_FIXED | MAP_ANON | MAP_PRIVATE, -1, 0);
        if (got == MAP_FAILED) {
            int saved_errno = errno;
            fprintf(stderr, "mmap failed for region[%u] [0x%llx,0x%llx): %s\n",
                    i, (unsigned long long)addr, (unsigned long long)(addr + len), strerror(saved_errno));
            if (saved_errno == ENOMEM) {
                fprintf(stderr, "  exiting EX_TEMPFAIL for a retry wrapper to try a fresh process\n");
                exit(EX_TEMPFAIL);
            }
            return 1;
        }
        if ((uint64_t)(uintptr_t)got != addr) {
            fprintf(stderr, "mmap did not honor the fixed address for region[%u]: got 0x%llx, expected 0x%llx\n",
                    i, (unsigned long long)(uintptr_t)got, (unsigned long long)addr);
            return 1;
        }

        memcpy(got, g_restore_buf + offset, len);

        if (prot != (PROT_READ | PROT_WRITE) && mprotect(got, len, prot) != 0) {
            fprintf(stderr, "mprotect failed for region[%u] [0x%llx,0x%llx): %s\n",
                    i, (unsigned long long)addr, (unsigned long long)(addr + len), strerror(errno));
            return 1;
        }
    }
    return 0;
}

/* Cache regions -- verbatim shape from thread_restore_test.c's
 * remap_cache_regions(). A region that won't map (kernel-sealed cache
 * pages) is printed and skipped, never fatal -- the replay is partial by
 * design. */
static void remap_cache_regions(uint32_t region_count) {
    for (uint32_t i = 0; i < region_count; i++) {
        uint64_t addr = g_regions[i].addr;
        uint64_t len = g_regions[i].len;
        int prot = (int)g_regions[i].protection;
        uint64_t offset = g_region_off[i];

        if (!is_cache_region(addr)) continue;

        void* got = mmap((void*)(uintptr_t)addr, len, PROT_READ | PROT_WRITE,
                         MAP_FIXED | MAP_ANON | MAP_PRIVATE, -1, 0);
        if (got == MAP_FAILED || (uint64_t)(uintptr_t)got != addr) {
            fprintf(stderr, "  skipped cache region[%u] addr=0x%llx size=0x%llx prot=%d : %s\n",
                    i, (unsigned long long)addr, (unsigned long long)len, prot,
                    got == MAP_FAILED ? strerror(errno) : "fixed address not honored");
            continue;
        }
        memcpy(got, g_restore_buf + offset, len);
        if (prot != (PROT_READ | PROT_WRITE) && mprotect(got, len, prot) != 0) {
            fprintf(stderr, "  cache region[%u] addr=0x%llx mapped+copied but mprotect(%d) failed: %s\n",
                    i, (unsigned long long)addr, prot, strerror(errno));
        }
    }
}

static void* dummy_entry_fn(void* arg) { (void)arg; for (;;) pause(); return NULL; }

/* Mode C's classic technique (full_restore_test.c's restore_state()):
 * overwrite the delivered ucontext_t wholesale, return, let sigreturn
 * apply it. Runs on the worker thread once the queued signal delivers
 * (see file header). Raw write(), not printf -- remap_cache_regions()
 * already ran by the time this fires, same __sF[]._write corruption risk
 * as thread_restore_test.c hit. */
static void restore_state(int sig, siginfo_t* info, void* ctx) {
    (void)sig; (void)info;
    char buf[160];
    int n = snprintf(buf, sizeof(buf),
        "restore_state: about to apply pc=%p sp=%p tpidr=0x%llx\n",
        arm_thread_state64_get_pc_fptr(g_regs.gregs),
        (void*)arm_thread_state64_get_sp(g_regs.gregs), (uint64_t)g_regs.tpidr);
    write(2, buf, n > 0 ? (size_t)n : 0);

    ((ucontext_t*)ctx)->uc_mcontext->__ss = g_regs.gregs;
    ((ucontext_t*)ctx)->uc_mcontext->__ns = g_regs.neon;
    __asm__ volatile ("msr tpidr_el0, %0" :: "r" (g_regs.tpidr));
}

int do_restore(const char* path) {
    FILE* f = fopen(path, "rb");
    if (!f) { perror("fopen"); return 1; }
    printf("restoring from %s\n", path);

    checkpoint_header_t hdr;
    if (fread(&hdr, sizeof(hdr), 1, f) != 1) { fprintf(stderr, "short read on header\n"); fclose(f); return 1; }
    if (hdr.region_count > MAX_REGIONS) { fprintf(stderr, "region_count too large\n"); fclose(f); return 1; }
    if (fread(g_regions, sizeof(region_desc_t), hdr.region_count, f) != hdr.region_count) {
        fprintf(stderr, "short read on region descriptors\n"); fclose(f); return 1;
    }

    uint64_t region_total = 0;
    for (uint32_t i = 0; i < hdr.region_count; i++) {
        g_region_off[i] = region_total;
        region_total += g_regions[i].len;
    }
    if (region_total != hdr.capture_used) { fprintf(stderr, "corrupt checkpoint file\n"); fclose(f); return 1; }

    /* Sized exactly to capture_used, known from the header -- no fixed cap
     * to exceed, unlike full_restore_test.c/thread_restore_test.c's
     * CAPTURE_BUF_BYTES. One flat buffer is fine here (unlike do_capture()'s
     * per-region buffers): restore isn't capturing its own memory, so
     * there's no self-aliasing risk to avoid. */
    g_restore_buf = mmap(NULL, hdr.capture_used, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (g_restore_buf == MAP_FAILED) { perror("mmap restore buffer"); fclose(f); return 1; }
    if (fread(g_restore_buf, 1, hdr.capture_used, f) != hdr.capture_used) {
        fprintf(stderr, "short read on capture buffer\n"); fclose(f); return 1;
    }
    fclose(f);
    g_regs = hdr.regs;

    printf("read %u regions, %.2f MB, pthread_addr=0x%llx munge=0x%llx sentinel=0x%llx\n",
           hdr.region_count, hdr.capture_used / 1048576.0,
           (unsigned long long)hdr.pthread_addr, (unsigned long long)hdr.munge,
           (unsigned long long)hdr.sentinel);

    if (remap_regions(hdr.region_count) != 0) { fprintf(stderr, "failed to remap regions\n"); return 1; }
    printf("non-cache regions remapped at their original addresses\n");

    /* Recover THIS (restore) process's own live munge from a real,
     * already-valid struct in THIS process -- main() is a real pthread too
     * (_pthread_main_thread_init() runs the same _pthread_init_signature()
     * any pthread_create()'d thread gets), same algebra as
     * thread_restore_test.c's docs/007 trick. Sign the worker struct with
     * THIS value now, before the cache remap -- the munge global still
     * holds this same value at this point, untouched. */
    uintptr_t self_addr = (uintptr_t)pthread_self();
    uintptr_t stored_sig = *(uintptr_t *)self_addr;
    uintptr_t new_munge = stored_sig ^ sign_for_addr(self_addr);

    uintptr_t worker_addr = (uintptr_t)hdr.pthread_addr;
    uintptr_t sig_v1 = sign_for_addr(worker_addr) ^ new_munge;
    *(uintptr_t *)worker_addr = sig_v1;
    printf("signed worker struct pre-cache-remap: munge=0x%lx sig=0x%lx\n", new_munge, sig_v1);

    void* stack = malloc(STACK_SIZE);
    if (!stack) { perror("malloc stack"); return 1; }
    void* stack_top = (char*)stack + STACK_SIZE;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_flags = SA_SIGINFO;
    sa.__sigaction_u.__sa_sigaction = restore_state;
    if (sigaction(SIGUSR1, &sa, NULL) == -1) { perror("sigaction"); return 1; }

    errno = 0;
    void* ret = __bsdthread_create(dummy_entry_fn, NULL, stack_top, (void*)worker_addr,
                                    PTHREAD_START_CUSTOM | PTHREAD_START_SUSPENDED);
    if (ret == (void*)-1) {
        fprintf(stderr, "__bsdthread_create failed: errno=%d (%s)\n", errno, strerror(errno));
        return 1;
    }
    printf("__bsdthread_create returned %p (suspended)\n", ret);

    /* Clobbers the munge global with hdr.munge (the CAPTURED process's own
     * value) -- expected, not a bug, see file header. */
    remap_cache_regions(hdr.region_count);

    /* Re-sign the SAME struct field to match what the global now actually
     * holds (hdr.munge, no recovery needed -- it's already in the header)
     * instead of patching the global back (thread_restore_test.c's
     * approach) -- same end state, opposite direction. From here on: raw
     * write(2), not printf -- same __sF[]._write corruption risk as
     * thread_restore_test.c hit post-cache-remap. */
    uintptr_t sig_v2 = sign_for_addr(worker_addr) ^ (uintptr_t)hdr.munge;
    *(uintptr_t *)worker_addr = sig_v2;
    char buf[192];
    int n = snprintf(buf, sizeof(buf),
        "re-signed worker struct post-cache-remap: munge=0x%llx sig=0x%lx\n",
        (unsigned long long)hdr.munge, sig_v2);
    write(2, buf, n > 0 ? (size_t)n : 0);

    pthread_t worker_pt = (pthread_t)(uintptr_t)hdr.pthread_addr;
    mach_port_t worker_port = pthread_mach_thread_np(worker_pt);
    n = snprintf(buf, sizeof(buf), "pthread_mach_thread_np(worker=0x%llx) => 0x%x\n",
                 (unsigned long long)hdr.pthread_addr, worker_port);
    write(2, buf, n > 0 ? (size_t)n : 0);
    if (worker_port == MACH_PORT_NULL) {
        write(2, "pthread_mach_thread_np failed to resolve the worker's port\n", 61);
        return 1;
    }

    if (hdr.sentinel) {
        *(volatile int *)(uintptr_t)hdr.sentinel = 1;
        n = snprintf(buf, sizeof(buf), "sentinel at 0x%llx set to 1\n", (unsigned long long)hdr.sentinel);
        write(2, buf, n > 0 ? (size_t)n : 0);
    }

    /* Queue the signal on the still-suspended thread -- delivery happens
     * the instant thread_resume() runs, before _pthread_start's real
     * dispatch to dummy_entry_fn (Ivan's finding, NOTES.md 2026-09-01/03). */
    int rc = pthread_kill(worker_pt, SIGUSR1);
    n = snprintf(buf, sizeof(buf), "pthread_kill(worker, SIGUSR1) while suspended => rc=%d\n", rc);
    write(2, buf, n > 0 ? (size_t)n : 0);

    kern_return_t kr = thread_resume(worker_port);
    if (kr != KERN_SUCCESS) {
        write(2, "thread_resume failed\n", 22);
        return 1;
    }
    write(2, "thread_resume succeeded -- worker should now run the queued signal handler\n", 77);

    /* Not exit -- the actual resumed execution happens on the worker
     * thread now, not here. Without this, main returns and the whole
     * process tears down before the worker gets a chance to run at all. */
    pause();
    return 0;
}
