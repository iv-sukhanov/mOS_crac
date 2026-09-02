/* Matching restore side for thread_capture_test.c (2026-08-25) -- mode D:
 * recreate the captured worker thread via a self-signed __bsdthread_create()
 * (docs/007) instead of hijacking main() (2026-08-21's known stuck-process
 * bug, avoided here structurally: main() never gets its own registers
 * touched at all). First end-to-end success: docs/008.
 *
 * Needs -arch arm64e for real (not NOP'd) `pacdb`/ptrauth_sign_unauthenticated
 * -- confirmed empirically 2026-08-25: raw `pacdb` compiled into a plain
 * ("arm64", non-e) Mach-O executes as a hardware no-op regardless of
 * whether the C source uses <ptrauth.h> or hand-written asm; it's the
 * *linked binary's* declared CPU subtype that puts the process in real-PAC
 * execution mode, not a property of one translation unit's flags. That in
 * turn means arm_thread_state64_t IS the opaque (ptrauth-aware) struct
 * variant in this file (__has_feature(ptrauth_calls) follows the arch
 * target automatically) -- unlike every other capture/restore file here,
 * and unlike the other file this was ported from (thread_create_test.c's
 * mode b-tls, PAC/BTI-disabled throughout).
 *
 * The actual state-seeding design, arrived at after four real bugs (see
 * docs/008 for the full account, this is the short version): only x0-x28
 * and cpsr are safe to hand to thread_set_state() as a raw copy of the
 * captured (foreign, non-opaque) bytes. pc and sp are NOT -- both are
 * void*-typed opaque fields in this build, and both turned out to be
 * subject to kernel/hardware interpretation a plain byte copy silently
 * breaks (pc needs arm_thread_state64_set_pc_fptr()'s real signing, seeded
 * from the thread's own thread_get_state() so the signing macro's
 * flag-dependent branch sees this thread's real flags, not the capture
 * process's leftover garbage at the same struct offset; sp faulted the
 * same way and is instead never sent through thread_set_state() at all --
 * seeded by the trampoline itself via a plain `mov`, same as TPIDR_EL0).
 */
#include <pthread.h>
#include <ptrauth.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <string.h>
#include <sysexits.h>
#include <errno.h>
#include <signal.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/thread_state.h>
#include <mach-o/dyld_images.h>
#include <sys/mman.h>

#if !__has_feature(ptrauth_calls)
#error "build with -arch arm64e -- see the file header for why this is required"
#endif

#define MAX_REGIONS       256
#define CAPTURE_BUF_BYTES (512u * 1024 * 1024)
#define STACK_SIZE        (256 * 1024)

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

/* Must match thread_capture_test.c's copy. */
#define WORKER_TLS_VALUE 99

// Must match thread_capture_test.c's checkpoint_header_t byte-for-byte
typedef struct {
    uint32_t region_count;
    uint64_t capture_used;
    regs_t   regs;
    uint64_t worker_struct_addr;
} checkpoint_header_t;

static regs_t g_regs;
static region_desc_t g_regions[MAX_REGIONS];
/* mmap'd, not static/BSS -- a static array here collided with a captured
 * region's original address and got silently corrupted mid-copy by
 * MAP_FIXED (found running this file, 2026-08-25; same fix applied to
 * full_restore_test.c, which had the identical bug -- see that file's own
 * note on g_capture_buf for the full explanation). */
static uint8_t* g_capture_buf;
static const uint64_t g_capture_buf_cap = CAPTURE_BUF_BYTES;
/* Byte offset of each region's data within g_capture_buf (prefix sum of
 * g_regions[].len). Filled once in do_restore() after the region list is read.
 * Both remap passes index the buffer by this instead of a running counter, so
 * one pass skipping a region can't desync the other's buffer position. */
static uint64_t g_region_off[MAX_REGIONS];

/* --- shared-cache membership: verbatim from thread_capture_test.c --- */
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
static uint64_t shared_cache_base(void) {
    task_dyld_info_data_t info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    if (task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&info, &count) != KERN_SUCCESS) return 0;
    struct dyld_all_image_infos* infos = (struct dyld_all_image_infos*)(uintptr_t)info.all_image_info_addr;
    return (uint64_t)infos->sharedCacheBaseAddress;
}

static bool in_shared_cache_range(mach_vm_address_t addr) {
    uint64_t base = shared_cache_base();
    return base != 0 && (uint64_t)addr >= base && (uint64_t)addr < base + CACHE_SPAN_BYTES;
}

static bool is_cache_region(uint64_t addr) {
    return in_shared_cache_range((mach_vm_address_t)addr) || in_shared_cache_submap((mach_vm_address_t)addr);
}

/* --- remap_regions(): verbatim from full_restore_test.c (2026-08-21), plus a
 * skip for shared-cache regions -- those are handled later by
 * remap_cache_regions(), after the worker thread exists (see do_restore). --- */
static int remap_regions(uint32_t region_count) {
    for (uint32_t i = 0; i < region_count; i++) {
        uint64_t addr = g_regions[i].addr;
        uint64_t len = g_regions[i].len;
        int prot = (int)g_regions[i].protection;
        uint64_t offset = g_region_off[i];

        if (is_cache_region(addr)) continue; /* deferred to remap_cache_regions() */

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

        memcpy(got, g_capture_buf + offset, len);

        if (prot != (PROT_READ | PROT_WRITE) && mprotect(got, len, prot) != 0) {
            fprintf(stderr, "mprotect failed for region[%u] [0x%llx,0x%llx): %s\n",
                    i, (unsigned long long)addr, (unsigned long long)(addr + len), strerror(errno));
            return 1;
        }
    }
    return 0;
}

/* Second remap pass: the shared-cache regions remap_regions() skipped. Run
 * AFTER the worker thread is created + suspended + state-seeded (see
 * do_restore) so __bsdthread_create / pthread_self / malloc all ran against
 * this process's own intact libpthread+libmalloc __DATA -- only thread_resume
 * sees the replayed state. A region that won't map (kernel-sealed cache pages,
 * region[15]-style) is printed and skipped, never fatal: the replay is
 * partial by design. */
static void remap_cache_regions(uint32_t region_count) {
    unsigned applied = 0, skipped = 0;
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
            skipped++;
            continue;
        }
        memcpy(got, g_capture_buf + offset, len);
        if (prot != (PROT_READ | PROT_WRITE) && mprotect(got, len, prot) != 0) {
            fprintf(stderr, "  cache region[%u] addr=0x%llx mapped+copied but mprotect(%d) failed: %s\n",
                    i, (unsigned long long)addr, prot, strerror(errno));
        }
        applied++;
    }
    // printf("remap_cache_regions: %u applied, %u skipped\n", applied, skipped);
}

/* --- mode D: self-sign + suspended-create + task_threads() + set_state --- */

/* Same list-lock page as cache_data_cow_test.c / NOTES 2026-08-26:
 * disassembling pthread_kill shows the munge global living at [page+0x60],
 * 0xc bytes before _pthread_list_lock ([page+0x6c]) -- both loaded via
 * `adrp` off the same page. cache_data_cow_test.c hardcoded the *absolute*
 * address that session (0x1f616406c) as "boot-session-stable" -- true
 * within one boot, but confirmed FALSE across boots (2026-09-01: this
 * session's real _pthread_list_lock, via `lldb`'s `p/x &_pthread_list_lock`,
 * is 0x1f789c06c instead -- the hardcoded value silently pointed at
 * unrelated, all-zero memory, and the resulting write was a no-op). Fix:
 * store the offset from the shared cache's *base* instead of an absolute
 * address -- the whole cache slides as one block per boot, so the offset
 * of any symbol within it from that base is what's actually stable across
 * boots, not the absolute address. This offset (0x1f789c06c - 0x18a950000)
 * still needs re-deriving by hand if Apple ever reshuffles libpthread's
 * __DATA layout (a toolchain/OS update), same caveat cache_data_cow_test.c
 * already carries for PTHREAD_HEAD_ADDR. */
#define PTHREAD_LIST_LOCK_CACHE_OFFSET 0x6cf4c06cull
#define PTHREAD_MUNGE_CACHE_OFFSET     (PTHREAD_LIST_LOCK_CACHE_OFFSET - 0xc)

/* Same (addr, key, discriminator) triple as libpthread's own
 * _pthread_init_signature/_pthread_validate_signature (docs/007). */
static uintptr_t sign_for_addr(uintptr_t addr) {
    return (uintptr_t)ptrauth_sign_unauthenticated(
        (void *)addr, ptrauth_key_process_dependent_data,
        ptrauth_string_discriminator("pthread.signature"));
}

/* Same trampoline as thread_create_test.c's mode b-tls (2026-08-17): no
 * thread_set_state flavor exposes TPIDR_EL0 (confirmed 2026-08-25 by
 * grepping the actual SDK headers -- arm_thread_state64_t has no tpidr
 * field, and the only tpidr-shaped field anywhere in _structs.h,
 * __tpidr2_el0, belongs to the unrelated SME state), so seeding it has to
 * happen via `msr` executed BY the thread itself, first thing on resume.
 * x16/x17 only (ARM64 ABI linker-scratch registers), so the real captured
 * x0-x15/x18-x30 (set via thread_set_state before this ever runs) stays
 * undisturbed for the real worker code this jumps into. */
static uint64_t tls_seed_data[3]; /* [0]=tpidr, [1]=target pc, [2]=target sp -- sp joined tpidr
    here 2026-08-25: thread_set_state's __opaque_sp, raw-copied from the captured (foreign,
    non-opaque) file data the same way x0-x28 safely are, faulted on the first real stack access
    once execution reached genuine restored worker code (poisoned-address-shaped EXC_BAD_ACCESS,
    same signature class as the PC issue above) -- rather than chase down another opaque-field
    interaction, sp gets the same treatment as tpidr: set by the thread itself via an ordinary
    `mov`, never passed through thread_set_state's own struct interpretation at all. */
extern void tls_seed_trampoline(void);
__asm__(
    ".global _tls_seed_trampoline\n"
    "_tls_seed_trampoline:\n"
    /* Landing pad, required for an indirect-branch-style entry (which is
     * what thread_set_state's PC + thread_resume is, from the CPU's point
     * of view -- confirmed empirically 2026-08-25: an identical hand-
     * written trampoline WITHOUT this instruction faulted immediately on
     * resume, poisoned-pointer-style (EXC_BAD_ACCESS, code=1, fault address
     * sharing the trampoline's own low bits with garbage high bits); adding
     * just this one instruction fixed it, isolated with a standalone raw
     * thread_create()+thread_set_state() repro before touching this file.
     * thread_create_test.c's mode b-tls never needed this because that
     * whole process ran PAC/BTI-disabled (compiled without -arch arm64e) --
     * this file can't avoid arm64e (needs real, non-NOP'd pacdb for the
     * self-sign step, docs/007), so it inherits BTI enforcement too. */
    "  bti c\n"
    "  adrp x16, _tls_seed_data@PAGE\n"
    "  add  x16, x16, _tls_seed_data@PAGEOFF\n"
    "  ldr  x17, [x16]\n"
    "  msr  tpidr_el0, x17\n"
    "  ldr  x17, [x16, #16]\n"
    "  mov  sp, x17\n"
    "  ldr  x16, [x16, #8]\n"
    "  br   x16\n"
);

static void* dummy_entry_fn(void* arg) { (void)arg; for (;;) pause(); return NULL; }

static int do_restore(const char* path) {
    FILE* f = fopen(path, "rb");
    if (!f) { perror("fopen"); return 1; }
    printf("restoring from %s\n", path);

    checkpoint_header_t hdr;
    if (fread(&hdr, sizeof(hdr), 1, f) != 1) { fprintf(stderr, "short read on header\n"); fclose(f); return 1; }
    if (hdr.region_count > MAX_REGIONS) { fprintf(stderr, "region_count too large\n"); fclose(f); return 1; }
    if (hdr.capture_used > g_capture_buf_cap) { fprintf(stderr, "capture_used too large\n"); fclose(f); return 1; }
    if (fread(g_regions, sizeof(region_desc_t), hdr.region_count, f) != hdr.region_count) {
        fprintf(stderr, "short read on region descriptors\n"); fclose(f); return 1;
    }
    uint64_t region_total = 0;
    for (uint32_t i = 0; i < hdr.region_count; i++) {
        g_region_off[i] = region_total;
        region_total += g_regions[i].len;
    }
    if (region_total != hdr.capture_used) { fprintf(stderr, "corrupt checkpoint file\n"); fclose(f); return 1; }
    if (fread(g_capture_buf, 1, hdr.capture_used, f) != hdr.capture_used) {
        fprintf(stderr, "short read on capture buffer\n"); fclose(f); return 1;
    }
    fclose(f);
    g_regs = hdr.regs;

    printf("read %u regions, %.2f MB, worker_struct_addr=0x%llx expected tls_val=%d\n",
           hdr.region_count, hdr.capture_used / 1048576.0,
           (unsigned long long)hdr.worker_struct_addr, WORKER_TLS_VALUE);

    if (remap_regions(hdr.region_count) != 0) { fprintf(stderr, "failed to remap regions\n"); return 1; }
    printf("all regions remapped at their original addresses\n");

    /* Recover munge_token from a real, live, validly-signed thread in THIS
     * process (docs/007's algebraic trick), then self-sign a fresh `sig`
     * for the worker's ORIGINAL (now-restored) address. main() is a real
     * pthread too (_pthread_main_thread_init() runs the same
     * _pthread_init_signature() any pthread_create()'d thread gets) -- no
     * need to spawn a dedicated thread just to have a signed struct to
     * borrow from. */
    uintptr_t self_addr = (uintptr_t)pthread_self();
    uintptr_t stored_sig = *(uintptr_t *)self_addr;
    uintptr_t munge = stored_sig ^ sign_for_addr(self_addr);

    uintptr_t worker_addr = (uintptr_t)hdr.worker_struct_addr;
    uintptr_t new_sig = sign_for_addr(worker_addr) ^ munge;
    *(uintptr_t *)worker_addr = new_sig;
    printf("recovered munge=0x%lx, self-signed worker struct at 0x%lx (sig=0x%lx)\n",
           munge, worker_addr, new_sig);

    void* stack = malloc(STACK_SIZE);
    if (!stack) { perror("malloc stack"); return 1; }
    void* stack_top = (char*)stack + STACK_SIZE;

    errno = 0;
    void* ret = __bsdthread_create(dummy_entry_fn, NULL, stack_top, (void*)worker_addr,
                                    PTHREAD_START_CUSTOM | PTHREAD_START_SUSPENDED);
    if (ret == (void*)-1) {
        fprintf(stderr, "__bsdthread_create failed: errno=%d (%s)\n", errno, strerror(errno));
        return 1;
    }
    printf("__bsdthread_create returned %p (suspended)\n", ret);

    /* Find the new thread's real mach port via task_threads() -- bypasses
     * pthread_mach_thread_np()'s __pthread_head list-membership dependency
     * entirely, confirmed 2026-08-25 to be the wall a self-signed-but-
     * unregistered struct hits there. Only main is a known port now (no
     * helper thread), so elimination against it alone leaves exactly the
     * new one -- main + the new thread is the whole process at this point. */
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
    if (worker_port == MACH_PORT_NULL) {
        fprintf(stderr, "couldn't find the new thread's port via task_threads()\n");
        return 1;
    }
    printf("new thread's mach port = 0x%x\n", worker_port);

    /* Start from the thread's REAL, kernel-populated initial state, not a
     * wholesale copy of the captured (foreign, plain-arm64, non-opaque)
     * gregs blob -- found the hard way, 2026-08-25, after two other fixes
     * (the g_capture_buf collision, then a missing `bti c` landing pad in
     * the trampoline -- confirmed as a real, separate requirement via a
     * minimal raw thread_create()+thread_set_state() repro) still left an
     * identical, repeatable EXC_BAD_ACCESS at the trampoline's very first
     * instruction. Root cause: a PTHREAD_START_SUSPENDED thread's PC is
     * pre-signed *by the kernel* pointing at _pthread_start, and
     * arm_thread_state64_set_pc_fptr()'s own signing logic branches on
     * __opaque_flags (KERNEL_SIGNED_PC / NO_PTRAUTH / the diversifier mask)
     * -- wholesale-copying gregs clobbered that field with whatever
     * meaningless garbage sat in the *captured* process's non-opaque
     * `.__pad` slot, at the exact same offset, making the signing macro
     * take the wrong branch. Fix: thread_get_state() the real initial
     * state first (correct flags for *this* thread), then only overwrite
     * the fields that are genuinely safe to replay raw (x0-x28, sp -- never
     * ptrauth-signed on this ABI, confirmed empirically 2026-08-25 by the
     * control test that resumed straight into MAP_FIXED-restored, raw-
     * captured code with no signing at all and worked). fp/lr are left as
     * whatever the kernel initialized -- worker_fn's own prologue rebuilds
     * them from sp on entry regardless, same as any normal call. */
    arm_thread_state64_t state;
    mach_msg_type_number_t state_count = ARM_THREAD_STATE64_COUNT;
    kern_return_t kr = thread_get_state(worker_port, ARM_THREAD_STATE64, (thread_state_t)&state, &state_count);
    if (kr != KERN_SUCCESS) { fprintf(stderr, "thread_get_state failed: %d\n", kr); return 1; }
    memcpy(state.__x, g_regs.gregs.__x, sizeof(state.__x));
    state.__cpsr = g_regs.gregs.__cpsr; /* never opaque, plain uint32 in both builds */
    /* __opaque_sp deliberately left as thread_get_state()'s own value here --
     * the trampoline overwrites it itself via `mov sp, x17` before touching
     * anything that needs a stack, so what thread_set_state ships for it
     * doesn't matter (and per the note above, sending it a raw captured
     * value there was exactly what faulted). */
    tls_seed_data[0] = g_regs.tpidr;
    tls_seed_data[1] = (uint64_t)(uintptr_t)g_regs.gregs.__opaque_pc; /* plain cast -- same
        reasoning as __opaque_sp below: these are raw, never-signed bytes from a plain-arm64
        capture process, safe to read as a bit pattern outside any ptrauth macro. No separate
        header field needed, g_regs.gregs already carries this value. */
    tls_seed_data[2] = (uint64_t)(uintptr_t)g_regs.gregs.__opaque_sp; /* plain cast, not
        thread_set_state -- the trampoline loads this into sp itself via `mov`, see above */
    arm_thread_state64_set_pc_fptr(state, &tls_seed_trampoline);

    kr = thread_set_state(worker_port, ARM_THREAD_STATE64, (thread_state_t)&state, ARM_THREAD_STATE64_COUNT);
    if (kr != KERN_SUCCESS) { fprintf(stderr, "thread_set_state(GPR) failed: %d\n", kr); return 1; }
    kr = thread_set_state(worker_port, ARM_NEON_STATE64, (thread_state_t)&g_regs.neon, ARM_NEON_STATE64_COUNT);
    if (kr != KERN_SUCCESS) { fprintf(stderr, "thread_set_state(NEON) failed: %d\n", kr); }

    /* The experiment (2026-08-31): replay the captured process's libSystem
     * __DATA now -- worker exists + is suspended + state-seeded, so this only
     * affects what it sees on resume. The point is __pthread_head /
     * _pthread_list_lock: if the captured list state lands, the recreated
     * worker (at its ORIGINAL address, so the captured list's pointer to it is
     * still valid) becomes visible to pthread_kill from this thread. */
    remap_cache_regions(hdr.region_count);

    /* remap_cache_regions() just overwrote this whole page with the
     * CAPTURED process's bytes -- including the munge global `new_sig`
     * above was signed against, clobbering it with the OTHER process's
     * value and breaking pthread_kill's internal autdb check (disassembly:
     * eor x16, x9, x8; autdb x16, x17, where x9 is this global). Patch just
     * this one word back to THIS process's own live value (`munge`,
     * recovered above before the clobber) so the signature still validates.
     * Deliberately scoped to exactly this word, not a general fix -- see
     * file header. */
    *(uintptr_t *)(uintptr_t)(shared_cache_base() + PTHREAD_MUNGE_CACHE_OFFSET) = munge;

    mach_port_t mach_port = pthread_mach_thread_np((pthread_t)(uintptr_t)hdr.worker_struct_addr);
    char buf1[128];
    if (mach_port != worker_port) {
        sprintf(buf1, "pthread_mach_thread_np(worker=0x%llx) => 0x%x, expected 0x%x\n",
                (unsigned long long)hdr.worker_struct_addr, mach_port, worker_port);
        write(2, buf1, strlen(buf1));
        return 1;
    } else {
        sprintf(buf1, "pthread_mach_thread_np(worker=0x%llx) => 0x%x (matches task_threads)\n",
                (unsigned long long)hdr.worker_struct_addr, mach_port);
        write(2, buf1, strlen(buf1));
    }
    
    pthread_t worker_pt = (pthread_t)(uintptr_t)hdr.worker_struct_addr;
    int rc = pthread_kill(worker_pt, 0);
    /* Raw write(2), not printf/fprintf -- deliberately: remap_cache_regions()
     * just overwrote several unrelated process-dependent (DB-keyed) signed
     * globals scattered through the shared-cache __DATA it blanket-copied,
     * not just the pthread munge patched above. One instance found the hard
     * way, lldb-confirmed: libc's own __sF[]._write (stdio's FILE-struct
     * write callback) traps the exact same way pthread_kill did before the
     * munge patch, the moment anything calls printf/fprintf after this
     * remap. Scope for NOW is strictly "what does pthread_kill report" --
     * sidestep stdio entirely (snprintf only formats into a buffer, no FILE*
     * involved) rather than chase every other clobbered signed global --
     * that's the bigger, not-yet-solved problem this file's header already
     * flags for a later rewrite. Stops here on purpose: thread_resume() and
     * the worker's own prints are untested past this point now, left for a
     * follow-up pass once more of __DATA's signed fields are understood. */
    char buf[160];
    int n = snprintf(buf, sizeof(buf),
        "pthread_kill(worker=0x%llx, 0) after cache __DATA replay => rc=%d (%s)\n",
        (unsigned long long)hdr.worker_struct_addr, rc, rc == 0 ? "FOUND -- registered" : strerror(rc));
    write(2, buf, n > 0 ? (size_t)n : 0);
    /* _exit(), not return/exit() -- an ordinary return here still runs
     * exit()'s atexit-registered stdio flush-all-open-streams pass, which
     * touches the same corrupted __sF[]._write field write(2) above was
     * built to avoid, producing a cosmetic SIGBUS after the real answer is
     * already printed. _exit() skips atexit entirely. */
    _exit(0);
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 2) { fprintf(stderr, "usage: %s <file>\n", argv[0]); return 2; }

    g_capture_buf = mmap(NULL, CAPTURE_BUF_BYTES, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (g_capture_buf == MAP_FAILED) { perror("mmap capture buffer"); return 1; }

    return do_restore(argv[1]);
}
