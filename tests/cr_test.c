/* cr_test.c -- macOS/arm64e checkpoint & restore: one on-disk format and one
 * do_capture()/do_restore() pair. No main() of its own -- driver .c files
 * (cr_capture_driver.c, cr_restore_driver.c) #include this directly and
 * supply main(). End-to-end working as of 2026-09-08 (see NOTES.md), happy
 * path only -- not a hardened engine.
 *
 * BUILD: -arch arm64e is mandatory. The PAC intrinsics below
 * (ptrauth_sign_unauthenticated / xpaci / pacib) don't compile otherwise,
 * and this process genuinely runs arm64e, so every captured pc/lr/sp/fp is
 * a real PAC-signed bit pattern that must be re-signed on restore, not a
 * plain address.
 *
 * CAPTURE (do_capture)
 *   1. classify_regions(): walk our own address space, keep every private
 *      region that is writable or was once writable (should_capture()),
 *      skipping the dyld shared cache's immutable pages.
 *   2. allocate one exactly-sized mmap'd buffer per region -- mmap, not
 *      malloc: malloc could carve its arena out of a region we're about to
 *      capture; a fresh mapping is its own vm_map entry and post-dates
 *      classification, so it never lands in the list.
 *   3. raise(SIGUSR1): the handler runs on this same thread/stack, snapshots
 *      registers (gregs/neon/tpidr) + pthread_addr + live munge, and
 *      memcpy's each already-classified region into its buffer. Classify on
 *      the main path; the handler only copies.
 *   4. write header + region descriptors + region bytes. The header's
 *      `sentinel` (address of a do_capture() stack local) lets a restored
 *      resume avoid falling back through here and re-writing the checkpoint.
 *
 * RESTORE (do_restore) -- a hybrid of two mechanisms this project calls
 * "mode C" and "mode D":
 *   - mode C: a signal handler rewrites a running thread's state (minicriu's
 *     shape). Alone it fails here -- overwriting the delivered ucontext
 *     wholesale makes sigreturn reject a PC signed under the capturing
 *     process's key.
 *   - mode D: seed a suspended thread's registers directly with
 *     thread_set_state(). Alone it can't set TPIDR_EL0 (no thread-state
 *     flavor for it) or run any code before the thread resumes.
 * The hybrid uses each for what it can do:
 *   - GPR+NEON are seeded with thread_set_state() into a still-suspended
 *     worker, pc/lr/sp/fp first re-signed under THIS process's key
 *     (resign_regs_for_this_process()). On signal delivery the kernel
 *     re-signs pc/lr again under this process's key, so sigreturn's later
 *     re-validation checks a signature the same kernel/process just made.
 *   - a SIGUSR1 queued while the worker is still suspended delivers the
 *     instant thread_resume() runs, before _pthread_start dispatches for
 *     real. Its handler (restore_state()) does only what thread_set_state
 *     can't: set TPIDR_EL0, and re-sign the frame-record return addresses
 *     on the restored stack (walk_and_resign_stack()). Then it returns and
 *     sigreturn applies the seeded context.
 *
 * ORDERING in do_restore() matters because the cache-region remap pass
 * overwrites the live pthread "munge" global with the captured process's
 * value:
 *   remap non-cache regions
 *   -> recover THIS process's munge, sign the worker struct with it
 *   -> __bsdthread_create(SUSPENDED)      (munge global still ours)
 *   -> remap cache regions                (munge global now = hdr.munge)
 *   -> re-sign the worker struct with hdr.munge to match
 *   -> resolve worker port, thread_set_state(GPR+NEON)
 *   -> pthread_kill(SIGUSR1) while suspended
 *   -> thread_resume()
 *
 * PAC signing domains touched here, for reference:
 *   - register pc/lr from thread_set_state: key IA, discriminator "pc"/"lr",
 *     no modifier (xnu machine_thread_state_convert_from_user).
 *   - register sp/fp: key DA, discriminator "sp"/"fp".
 *   - frame-record LRs on the restored stack: key IB, modifier = frame
 *     entry sp (fp + 0x10). Walked and re-signed by walk_and_resign_stack().
 *
 * The on-disk format (checkpoint_header_t + region_desc_t[] + bytes) is raw
 * structs with native padding -- not portable across builds or machines.
 *
 * KNOWN LIMITS (NOTES.md 2026-09-08): the resumed worker currently runs
 * process teardown on a non-main thread; the guard-page/address collision
 * is only mitigated by reserving the driver's __DATA vmsize + running
 * ASLR-off, not solved; one region set, one thread.
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

typedef struct {
    uint32_t region_count;
    uint64_t capture_used;  // total bytes across all regions
    regs_t   regs;
    uint64_t pthread_addr;  /* capturing thread's own pthread_self() at signal time */
    uint64_t munge;         /* the capturing process's live pthread munge (docs/007
                               algebra: stored_sig XOR sign_for_addr(pthread_addr)).
                               Used on restore to keep the worker struct's signature
                               consistent after the cache-region remap overwrites the
                               live munge global with this value. */
    uint64_t sentinel;      /* address of a do_capture() stack local. A resume seeds
                               PC back into do_capture() after raise(); restore pokes
                               a 1 here first (the stack region restores the captured
                               0), and do_capture() then skips re-writing a checkpoint. */
} checkpoint_header_t;

static region_desc_t g_regions[MAX_REGIONS];
static void*         g_region_bufs[MAX_REGIONS];

static uint32_t      g_region_count;
static regs_t        g_regs;
static uint64_t      g_pthread_addr;
static uint64_t      g_munge;

/* Same (addr, key, discriminator) triple as libpthread's own
 * _pthread_init_signature/_pthread_validate_signature (docs/007) -- must
 * match exactly for the munge XOR-recovery to work. */
static uintptr_t sign_for_addr(uintptr_t addr) {
    return (uintptr_t)ptrauth_sign_unauthenticated(
        (void *)addr, ptrauth_key_process_dependent_data,
        ptrauth_string_discriminator("pthread.signature"));
}

/* Strip a captured code/data pointer with its key (non-authenticating, safe
 * on any input) then re-sign under this process's key. Two functions, not
 * one with a key parameter: ptrauth_strip / ptrauth_sign_unauthenticated
 * need a compile-time-constant key. */
static uint64_t strip_and_resign_code(uint64_t raw, uint64_t discriminator) {
    void *stripped = ptrauth_strip((void *)(uintptr_t)raw, ptrauth_key_process_independent_code);
    void *resigned = ptrauth_sign_unauthenticated(stripped, ptrauth_key_process_independent_code, discriminator);
    return (uint64_t)(uintptr_t)resigned;
}

static uint64_t strip_and_resign_data(uint64_t raw, uint64_t discriminator) {
    void *stripped = ptrauth_strip((void *)(uintptr_t)raw, ptrauth_key_process_independent_data);
    void *resigned = ptrauth_sign_unauthenticated(stripped, ptrauth_key_process_independent_data, discriminator);
    return (uint64_t)(uintptr_t)resigned;
}

/* Re-sign a captured arm_thread_state64_t's pc/lr/sp/fp under this process's
 * key, in place, so thread_set_state() / sigreturn accept them. lr is left
 * untouched when IB_SIGNED_LR is set (a real frame-record-style lr): xnu
 * can't re-derive the original pacibsp sp modifier, so passthrough is the
 * only correct move for that case. */
static void resign_regs_for_this_process(arm_thread_state64_t *s) {
    uint64_t raw_pc = (uint64_t)(uintptr_t)s->__opaque_pc;
    uint64_t raw_lr = (uint64_t)(uintptr_t)s->__opaque_lr;
    uint64_t raw_sp = (uint64_t)(uintptr_t)s->__opaque_sp;
    uint64_t raw_fp = (uint64_t)(uintptr_t)s->__opaque_fp;

    // TODO: look into __DARWIN_ARM_THREAD_STATE64_FLAGS_NO_PTRAUTH flag later
    bool ib_signed_lr = !!(s->__opaque_flags & __DARWIN_ARM_THREAD_STATE64_FLAGS_IB_SIGNED_LR);

    uint64_t new_pc = strip_and_resign_code(raw_pc, ptrauth_string_discriminator("pc"));
    uint64_t new_lr = ib_signed_lr ? raw_lr : strip_and_resign_code(raw_lr, ptrauth_string_discriminator("lr"));
    uint64_t new_sp = strip_and_resign_data(raw_sp, ptrauth_string_discriminator("sp"));
    uint64_t new_fp = strip_and_resign_data(raw_fp, ptrauth_string_discriminator("fp"));

    s->__opaque_pc = (void *)(uintptr_t)new_pc;
    s->__opaque_lr = (void *)(uintptr_t)new_lr;
    s->__opaque_sp = (void *)(uintptr_t)new_sp;
    s->__opaque_fp = (void *)(uintptr_t)new_fp;
}

/* --- region classification --- */

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

/* Generous over-estimate of the shared cache's extent (~5.6 GB of cache
 * files on this machine; 8 GB with headroom). Over-guessing only ever
 * over-captures a little cache-adjacent memory, never misses something. */
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
    if (info->protection == VM_PROT_NONE) return false; /* guard pages, VA reservations */

    if (info->external_pager) {
        /* File-backed. Our own binary's segments resolve to a real path via
         * proc_regionfilename(); dyld shared cache regions don't. Skip such
         * an unresolved region only if it is executable code or can never be
         * written (max_protection is read-only). */
        char buf[MAXPATHLEN];
        int ret = proc_regionfilename(getpid(), addr, buf, sizeof(buf));
        if (ret <= 0 && (info->protection & VM_PROT_EXECUTE || info->max_protection == VM_PROT_READ)) {
            return false;
        }
    } else if (in_shared_cache_submap(addr) || in_shared_cache_range(addr)) {
        if (info->protection & VM_PROT_EXECUTE) {
            /* Not expected: cache code should stay pager-backed/pristine.
             * Printed so a real occurrence doesn't pass by silently. */
            printf("  note: executable non-external-pager region in shared-cache "
                   "range at 0x%llx prot=%u -- capturing\n", (uint64_t)addr, info->protection);
        }
        /* Skip only immutable cache pages. A currently-read-only page whose
         * max_protection allows writes may hold COW-modified data. */
        return info->max_protection != VM_PROT_READ;
    }
    return true;
}

static int classify_regions(void) {
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
        fprintf(stderr, "classify_regions: hit MAX_REGIONS=%d -- checkpoint would be truncated\n", MAX_REGIONS);
        return 1;
    }
    return 0;
}

/* One exactly-sized mmap'd buffer per region -- see the file header for why
 * mmap and not malloc. */
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

/* do_capture() may be called more than once in a longer-running scenario;
 * don't leak tens of MB of anonymous mappings per call. */
static void free_region_bufs(void) {
    for (uint32_t i = 0; i < g_region_count; i++) {
        if (g_region_bufs[i]) {
            munmap(g_region_bufs[i], g_regions[i].len);
            g_region_bufs[i] = NULL;
        }
    }
}

/* Signal handler: snapshot registers, then memcpy each already-classified
 * region into its buffer. Classification happened on the main path; the
 * handler only copies. */
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

/* classify -> per-region buffers -> self-signal -> write file. */
int do_capture(const char* path) {
    /* volatile: force a real load on each check below. A restored thread's
     * GPRs are seeded from what was resident at capture time; if this sat in
     * a register instead of the stack slot, resume would never see the 1 a
     * restore pokes into *sentinel. */
    volatile int restored_flag = 0;
    uint64_t sentinel = (uint64_t)(uintptr_t)&restored_flag;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_flags = SA_SIGINFO;
    sa.__sigaction_u.__sa_sigaction = capture_state;
    if (sigaction(SIGUSR1, &sa, NULL) == -1) { perror("sigaction"); return 1; }

    if (classify_regions() != 0) return 1;
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

    raise(SIGUSR1); /* synchronous self-signal: handler runs on this thread/stack,
                       then execution continues here */

    /* A resume seeds PC back to about here with *sentinel already set to 1
     * (see checkpoint_header_t). Don't re-write a checkpoint in that case. */
    if (restored_flag != 0) {
        printf("resumed from a restore -- not writing a checkpoint again\n");
        return 0;
    }

    /* pc/sp are opaque on arm64e -- use the accessor macros, not raw fields. */
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
    return 0;
}

/* do_restore() -- see the file header for the hybrid mechanism and the
 * ordering constraint. */

static uint8_t* g_restore_buf;
static uint64_t g_region_off[MAX_REGIONS];

static bool is_cache_region(uint64_t addr) {
    return in_shared_cache_range((mach_vm_address_t)addr) || in_shared_cache_submap((mach_vm_address_t)addr);
}

/* Map one classified region back at its original address, copy its bytes
 * from the flat restore buffer, restore its final protection. `fatal`: the
 * non-cache pass treats any failure as fatal and exits EX_TEMPFAIL on an
 * ENOMEM address collision so a retry wrapper can try a fresh process; the
 * cache pass logs and skips an unmappable (kernel-sealed) region -- a
 * partial cache replay is expected. */
static int remap_one_region(uint32_t i, bool fatal) {
    uint64_t addr = g_regions[i].addr;
    uint64_t len  = g_regions[i].len;
    int prot      = (int)g_regions[i].protection;

    void* got = mmap((void*)(uintptr_t)addr, len, PROT_READ | PROT_WRITE,
                     MAP_FIXED | MAP_ANON | MAP_PRIVATE, -1, 0);
    if (got == MAP_FAILED || (uint64_t)(uintptr_t)got != addr) {
        int e = errno;
        fprintf(stderr, "  region[%u] [0x%llx,0x%llx): %s%s\n", i,
                (uint64_t)addr, (uint64_t)(addr + len),
                got == MAP_FAILED ? strerror(e) : "fixed address not honored",
                fatal ? "" : " -- skipped");
        if (!fatal) return 0;
        if (got == MAP_FAILED && e == ENOMEM) {
            fprintf(stderr, "  exiting EX_TEMPFAIL for a retry wrapper to try a fresh process\n");
            exit(EX_TEMPFAIL);
        }
        return 1;
    }

    memcpy(got, g_restore_buf + g_region_off[i], len);

    if (prot != (PROT_READ | PROT_WRITE) && mprotect(got, len, prot) != 0) {
        fprintf(stderr, "  mprotect(%d) failed for region[%u] [0x%llx,0x%llx): %s\n",
                prot, i, (uint64_t)addr, (uint64_t)(addr + len), strerror(errno));
        if (fatal) return 1;
    }
    return 0;
}

/* cache=false: non-cache regions, before __bsdthread_create(). cache=true:
 * shared-cache regions, after it (that pass clobbers the munge global). */
static int remap_regions(uint32_t region_count, bool cache) {
    for (uint32_t i = 0; i < region_count; i++) {

        if (is_cache_region(g_regions[i].addr) != cache) continue;

        if (remap_one_region(i, !cache) != 0) return 1;
    }
    return 0;
}

static void* dummy_entry_fn(void* arg) { (void)arg; for (;;) pause(); return NULL; }

/* Re-sign every frame-record return address on the restored stack under this
 * process's key. resign_regs_for_this_process() fixes only the four register
 * values; the restored stack's {saved fp, saved lr} records still hold LRs
 * signed (IB, modifier = frame entry sp) by the capturing process, so the
 * first authenticated return through one faults. Mechanism from
 * lr_resign_test.c: xpaci strip + pacib with modifier fp+0x10, walking
 * outward, stopping at _dyld_start's sentinel frame (fp==0 && lr strips to
 * 0), with a monotonic-fp guard. Raw loads/stores + xpaci/pacib only:
 * async-signal-safe. Returns the number of records rewritten. */
static int walk_and_resign_stack(uint64_t fp) {
    int n = 0;
    if (fp == 0) return 0;
    for (;; n++) {
        uint64_t next_fp = *(uint64_t *)(uintptr_t)fp;
        uint64_t lr      = *(uint64_t *)(uintptr_t)(fp + 0x8);

        __asm__ volatile("xpaci %0" : "+r"(lr));
        if (lr == 0 && next_fp == 0) break;          /* _dyld_start sentinel frame */

        uint64_t modifier = fp + 0x10;
        __asm__ volatile("pacib %0, %1" : "+r"(lr) : "r"(modifier));
        *(uint64_t *)(uintptr_t)(fp + 0x8) = lr;

        if (next_fp <= fp) break;                    /* chain not strictly outward -- bail */
        fp = next_fp;
    }
    return n;
}

/* Runs before the worker executes any real instruction (see file header).
 * Does the two things thread_set_state() can't: set TPIDR_EL0, and re-sign
 * the restored stack's frame-record LRs. Then returns; sigreturn applies the
 * seeded context. */
static void restore_state(int sig, siginfo_t* info, void* ctx) {
    (void)sig; (void)info; (void)ctx;
    __asm__ volatile ("msr tpidr_el0, %0" :: "r" (g_regs.tpidr));

    /* Captured fp arrives DA-signed (process-independent key), so this strip
     * is valid regardless of which process signed it. */
    uint64_t fp = (uint64_t)(uintptr_t)ptrauth_strip(
        (void *)(uintptr_t)g_regs.gregs.__opaque_fp, ptrauth_key_process_independent_data);
    int n = walk_and_resign_stack(fp);
    printf("restore_state: tpidr=0x%llx set; resigned %d frame-record LR(s) from fp=0x%llx\n",
           (uint64_t)g_regs.tpidr, n, fp);
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

    /* One flat buffer sized exactly to capture_used. No self-aliasing risk
     * on the restore side, so no need for per-region buffers here. */
    g_restore_buf = mmap(NULL, hdr.capture_used, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (g_restore_buf == MAP_FAILED) { perror("mmap restore buffer"); fclose(f); return 1; }
    if (fread(g_restore_buf, 1, hdr.capture_used, f) != hdr.capture_used) {
        fprintf(stderr, "short read on capture buffer\n"); fclose(f); return 1;
    }
    fclose(f);
    g_regs = hdr.regs;

    printf("read %u regions, %.2f MB, pthread_addr=0x%llx munge=0x%llx sentinel=0x%llx\n",
           hdr.region_count, hdr.capture_used / (1024.0 * 1024.0),
           (uint64_t)hdr.pthread_addr, (uint64_t)hdr.munge,
           (uint64_t)hdr.sentinel);

    if (remap_regions(hdr.region_count, false) != 0) { fprintf(stderr, "failed to remap regions\n"); return 1; }
    printf("non-cache regions remapped at their original addresses\n");

    /* Recover THIS process's live munge from main()'s own valid pthread
     * struct (docs/007), and sign the worker struct with it now, while the
     * munge global still holds this value. */
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

    /* Clobbers the munge global with hdr.munge (expected -- see file header). */
    remap_regions(hdr.region_count, true);

    /* Re-sign the worker struct to match the global's new value. */
    uintptr_t sig_v2 = sign_for_addr(worker_addr) ^ (uintptr_t)hdr.munge;
    *(uintptr_t *)worker_addr = sig_v2;
    printf("re-signed worker struct post-cache-remap: munge=0x%llx sig=0x%lx\n",
        (uint64_t)hdr.munge, sig_v2);

    pthread_t worker_pt = (pthread_t)(uintptr_t)hdr.pthread_addr;

    /* Resolve the worker's Mach port via task_threads() -- there are exactly
     * two threads here (main + the suspended worker), and
     * pthread_mach_thread_np() on the freshly self-signed struct returns a
     * bogus fixed port instead of the real one. */
    mach_port_t main_port = mach_thread_self();
    thread_act_array_t acts;
    mach_msg_type_number_t n_acts;
    if (task_threads(mach_task_self(), &acts, &n_acts) != KERN_SUCCESS) {
        fprintf(stderr, "task_threads failed\n"); return 1;
    }
    mach_port_t worker_port = MACH_PORT_NULL;
    for (mach_msg_type_number_t i = 0; i < n_acts; i++) {
        if (acts[i] != main_port) { worker_port = acts[i]; break; }
    }
    vm_deallocate(mach_task_self(), (vm_address_t)acts, sizeof(thread_act_t) * n_acts);
    mach_port_deallocate(mach_task_self(), main_port);
    if (worker_port == MACH_PORT_NULL) {
        fprintf(stderr, "couldn't find the worker thread's port via task_threads()\n");
        return 1;
    }
    printf("worker port = 0x%x\n", worker_port);

    if (hdr.sentinel) {
        *(volatile int *)(uintptr_t)hdr.sentinel = 1;
        printf("sentinel at 0x%llx set to 1\n", (uint64_t)hdr.sentinel);
    }

    /* Seed GPR+NEON into the still-suspended worker, pc/lr/sp/fp re-signed
     * under this process's key first (see file header). */
    printf("resign_regs: __opaque_flags=0x%x IB_SIGNED_LR=%d\n",
           g_regs.gregs.__opaque_flags,
           !!(g_regs.gregs.__opaque_flags & __DARWIN_ARM_THREAD_STATE64_FLAGS_IB_SIGNED_LR));
    arm_thread_state64_t seeded_gregs = g_regs.gregs;
    resign_regs_for_this_process(&seeded_gregs);

    kern_return_t kr_gpr = thread_set_state(worker_port, ARM_THREAD_STATE64,
                                             (thread_state_t)&seeded_gregs, ARM_THREAD_STATE64_COUNT);
    if (kr_gpr != KERN_SUCCESS) {
        fprintf(stderr, "thread_set_state(GPR) failed: %d\n", kr_gpr);
        return 1;
    }
    kern_return_t kr_neon = thread_set_state(worker_port, ARM_NEON_STATE64,
                                              (thread_state_t)&g_regs.neon, ARM_NEON_STATE64_COUNT);
    if (kr_neon != KERN_SUCCESS) {
        fprintf(stderr, "thread_set_state(NEON) failed: %d (non-fatal)\n", kr_neon);
    }
    printf("thread_set_state(GPR+NEON) applied to suspended worker\n");

    /* Queue the signal on the still-suspended thread -- delivery happens the
     * instant thread_resume() runs, before _pthread_start's real dispatch to
     * dummy_entry_fn (NOTES.md 2026-09-01/03). */
    int rc = pthread_kill(worker_pt, SIGUSR1);
    printf("pthread_kill(worker, SIGUSR1) while suspended => rc=%d\n", rc);

    kern_return_t kr = thread_resume(worker_port);
    if (kr != KERN_SUCCESS) {
        printf("thread_resume failed\n");
        return 1;
    }
    printf("thread_resume succeeded -- worker should now run the queued signal handler\n");

    /* The resumed execution is on the worker now; without this, main returns
     * and the process tears down before the worker runs. */
    for (;;) pause();
    
    // Unreachable
    return 0;
}
