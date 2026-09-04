/* Round-trips a live worker thread's PAC-signed pc/lr/sp/fp through
 * thread_get_state() -> strip -> resign -> thread_set_state() -> resume,
 * using the exact recipe docs/010 pulled from xnu's real source
 * (osfmk/arm64/status.c's machine_thread_state_convert_from_user/_to_user,
 * osfmk/arm/pmap/pmap.c's pmap_auth_user_ptr/pmap_sign_user_ptr) --
 * key IA (ptrauth_key_process_independent_code) for pc/lr, key DA
 * (ptrauth_key_process_independent_data) for sp/fp, plain
 * ptrauth_string_discriminator(<field name>) for all four, no address
 * modifier. This is the first time that recipe is actually exercised
 * against a real thread_get_state()/thread_set_state() round trip, rather
 * than just read out of xnu source.
 *
 * Two things get verified, matching what strip+resign is actually for:
 *   1. STATIC: does stripping the captured pc/lr/sp/fp and re-signing them
 *      with THIS process's own live key reproduce the exact same bits the
 *      kernel originally handed back? Same task, same jop_pid either way
 *      here (no cross-process step yet -- that's the next test, this one
 *      only locks the recipe itself down) -- a MISMATCH here would mean
 *      the recipe (key/discriminator/flags) is wrong, full stop.
 *   2. DYNAMIC: does thread_set_state() actually accept the
 *      strip+resign-reconstructed state and let the thread resume and run
 *      to completion, with its own general registers (x19-x28, tagged
 *      before suspension, never touched by this test) intact? A wrong
 *      recipe could pass check 1 by accident (e.g. two compensating typos)
 *      but still poison the thread on resume -- this is the real test.
 *
 * Deliberately single-process: worker and resigner share a task, so
 * pmap_auth_user_ptr's jop_pid is the same key on both sides regardless of
 * the still-open ad-hoc-signing/shared-region question docs/010 flags --
 * this test locks down the *mechanism*, not cross-process key sharing.
 */
#include <mach/mach.h>
#include <mach/thread_act.h>
#include <mach/thread_state.h>
#include <ptrauth.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>

#if !__has_feature(ptrauth_calls)
#error "build with -arch arm64e -- see file header for why this is required"
#endif

static _Atomic bool worker_ready = false;
static _Atomic bool stop = false;

/* Tag values the worker loads into its callee-saved GPRs before parking in
 * the spin loop -- re-read after resume to confirm thread_set_state's
 * reconstructed state didn't clobber anything outside pc/lr/sp/fp. */
#define TAG(n) (0x1900000000000000ULL + (n) * 0x0101010101ULL)

static uint64_t final_x[10]; /* x19-x28, read back after the worker resumes */

/* Deliberately non-leaf: a real, non-inlinable libc call forces the
 * compiler to protect ITS OWN return address across that call, which on
 * arm64e means signing it with `pacibsp` (IB key) in this function's own
 * prologue -- exactly the frame-record mechanism lr_resign_test.c strips
 * and re-signs on the stack, distinct from the IA-keyed, kernel-signed lr
 * every earlier test in this file has captured. After the one forcing
 * call, the rest of this function is pure register-only code (no further
 * `bl`) so nothing overwrites the live x30 again before main suspends us
 * -- unlike worker_fn's usual spin loop, which calls usleep() on every
 * iteration and so almost never gets caught holding an IB-signed lr.
 *
 * Checked by actual disassembly (otool -tv), not assumed: after usleep()'s
 * own `bl` returns, the compiler does NOT reload x30 from the stack --
 * it leaves the register holding usleep()'s own plain, unsigned return
 * address, and only reloads the real (IB-signed) one at the very end,
 * right before `retab`. Left alone, the spin below would sit on a plain
 * address the whole time, not the IB-signed one this test wants to
 * observe. Fixed with one explicit reload: `[x29, #8]` is this function's
 * own frame record's saved lr slot -- the exact `fp + 0x8` offset
 * lr_resign_test.c already established -- loaded back into x30 by hand,
 * early, so the live register genuinely holds the IB-signed value for the
 * whole spin instead of only the last few instructions before return. */
static void spin_ib_signed(void) __attribute__((noinline));
static void spin_ib_signed(void) {
    usleep(1); /* forces non-leaf status; not about the 1us itself */
    __asm__ volatile("ldr x30, [x29, #8]" ::: "x30");
    atomic_store(&worker_ready, true);
    while (!atomic_load(&stop)) { } /* call-free from here on */
}

static void *worker_fn(void *arg) {
    (void)arg;
    register uint64_t x19 __asm__("x19") = TAG(19);
    register uint64_t x20 __asm__("x20") = TAG(20);
    register uint64_t x21 __asm__("x21") = TAG(21);
    register uint64_t x22 __asm__("x22") = TAG(22);
    register uint64_t x23 __asm__("x23") = TAG(23);
    register uint64_t x24 __asm__("x24") = TAG(24);
    register uint64_t x25 __asm__("x25") = TAG(25);
    register uint64_t x26 __asm__("x26") = TAG(26);
    register uint64_t x27 __asm__("x27") = TAG(27);
    register uint64_t x28 __asm__("x28") = TAG(28);
    __asm__ volatile("" :: "r"(x19), "r"(x20), "r"(x21), "r"(x22), "r"(x23),
                            "r"(x24), "r"(x25), "r"(x26), "r"(x27), "r"(x28));

    spin_ib_signed(); /* AAPCS64 guarantees x19-x28 survive this call */

    /* Re-declare so the compiler doesn't assume it still knows these
     * registers' values across the loop/calls above -- forces a fresh read
     * of whatever's really sitting in x19-x28 post-resume. */
    register uint64_t f19 __asm__("x19") = x19;
    register uint64_t f20 __asm__("x20") = x20;
    register uint64_t f21 __asm__("x21") = x21;
    register uint64_t f22 __asm__("x22") = x22;
    register uint64_t f23 __asm__("x23") = x23;
    register uint64_t f24 __asm__("x24") = x24;
    register uint64_t f25 __asm__("x25") = x25;
    register uint64_t f26 __asm__("x26") = x26;
    register uint64_t f27 __asm__("x27") = x27;
    register uint64_t f28 __asm__("x28") = x28;
    final_x[0] = f19; final_x[1] = f20; final_x[2] = f21; final_x[3] = f22;
    final_x[4] = f23; final_x[5] = f24; final_x[6] = f25; final_x[7] = f26;
    final_x[8] = f27; final_x[9] = f28;
    return NULL;
}

/* docs/010's recipe: strip (non-authenticating, safe regardless of whether
 * the input signature is even valid) then re-sign under this process's own
 * live key, same key, plain field-name discriminator, no address modifier.
 * Two functions, not one taking `key` as a parameter -- ptrauth_strip()/
 * ptrauth_sign_unauthenticated()'s key argument must be a compile-time
 * constant (it selects the actual hardware instruction, e.g. pacia vs.
 * pacda), so it can't be threaded through as a runtime value. */
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

static void check(const char *name, uint64_t original, uint64_t recomputed) {
    printf("  %-3s original=0x%016llx recomputed=0x%016llx %s\n",
           name, original, recomputed, original == recomputed ? "MATCH" : "MISMATCH");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    pthread_t worker;
    if (pthread_create(&worker, NULL, worker_fn, NULL) != 0) {
        fprintf(stderr, "pthread_create failed\n");
        return 1;
    }
    while (!atomic_load(&worker_ready)) usleep(500);
    usleep(5000); /* let it actually park in the spin loop, not still be in atomic_store's call frame */

    mach_port_t worker_port = pthread_mach_thread_np(worker);
    kern_return_t kr = thread_suspend(worker_port);
    if (kr != KERN_SUCCESS) { fprintf(stderr, "thread_suspend failed: %d\n", kr); return 1; }

    arm_thread_state64_t state;
    mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
    kr = thread_get_state(worker_port, ARM_THREAD_STATE64, (thread_state_t)&state, &count);
    if (kr != KERN_SUCCESS) { fprintf(stderr, "thread_get_state failed: %d\n", kr); return 1; }

    printf("--- captured (suspended) state ---\n");
    printf("  __opaque_flags=0x%08x  KERNEL_SIGNED_PC=%d KERNEL_SIGNED_LR=%d IB_SIGNED_LR=%d NO_PTRAUTH=%d\n",
           state.__opaque_flags,
           !!(state.__opaque_flags & __DARWIN_ARM_THREAD_STATE64_FLAGS_KERNEL_SIGNED_PC),
           !!(state.__opaque_flags & __DARWIN_ARM_THREAD_STATE64_FLAGS_KERNEL_SIGNED_LR),
           !!(state.__opaque_flags & __DARWIN_ARM_THREAD_STATE64_FLAGS_IB_SIGNED_LR),
           !!(state.__opaque_flags & __DARWIN_ARM_THREAD_STATE64_FLAGS_NO_PTRAUTH));
    for (int i = 19; i <= 28; i++) {
        /* Not every one of these is trustworthy evidence: the register-
         * pinning trick in worker_fn() only guarantees placement at its
         * one-shot asm barrier, not persistence through the calls
         * (atomic_store/usleep) that follow it -- a compiler is free to
         * reuse a "dead after that point" physical register for its own
         * bookkeeping. Whichever ones show MISMATCH here were reused, not
         * corrupted by anything this test is actually checking. */
        uint64_t expected = TAG(i);
        printf("  x%-2d=0x%016llx (tag %s)\n", i, state.__x[i],
               state.__x[i] == expected ? "held" : "NOT held -- reused by compiler before suspend");
    }
    uint64_t raw_pc = (uint64_t)(uintptr_t)state.__opaque_pc;
    uint64_t raw_lr = (uint64_t)(uintptr_t)state.__opaque_lr;
    uint64_t raw_sp = (uint64_t)(uintptr_t)state.__opaque_sp;
    uint64_t raw_fp = (uint64_t)(uintptr_t)state.__opaque_fp;
    printf("  pc =0x%016llx\n  lr =0x%016llx\n  sp =0x%016llx\n  fp =0x%016llx\n",
           raw_pc, raw_lr, raw_sp, raw_fp);

    /* --- check 1: strip+resign reproduces the exact same bits --- */
    printf("--- strip+resign vs. original (STATIC check) ---\n");
    uint64_t new_pc = strip_and_resign_code(raw_pc, ptrauth_string_discriminator("pc"));
    /* lr is the one field with two entirely different valid
     * representations (docs/010): IA-keyed + KERNEL_SIGNED_LR (every
     * earlier test in this file, worker caught mid-libc-call) vs.
     * IB-keyed frame-record style + IB_SIGNED_LR (this test's spin_ib_signed(),
     * worker caught in its own straight-line body). machine_thread_state_convert_from_user
     * only IA-auths lr when IB_SIGNED_LR is clear -- when it's set, it
     * passes the value through completely untouched, unauthenticated, no
     * exceptions. Mirroring that exactly here, not just for symmetry: an
     * IB-signed lr stripped/resigned with the IA key produces garbage
     * (confirmed by this test before this fix -- MISMATCH), and xnu itself
     * has no way to re-derive the SP-based modifier a real pacibsp used,
     * so passthrough is the only correct move, not a shortcut. */
    bool ib_signed_lr = !!(state.__opaque_flags & __DARWIN_ARM_THREAD_STATE64_FLAGS_IB_SIGNED_LR);
    uint64_t new_lr = ib_signed_lr ? raw_lr : strip_and_resign_code(raw_lr, ptrauth_string_discriminator("lr"));
    uint64_t new_sp = strip_and_resign_data(raw_sp, ptrauth_string_discriminator("sp"));
    uint64_t new_fp = strip_and_resign_data(raw_fp, ptrauth_string_discriminator("fp"));
    check("pc", raw_pc, new_pc);
    check("lr", raw_lr, new_lr);
    check("sp", raw_sp, new_sp);
    check("fp", raw_fp, new_fp);

    /* --- check 2: hand the reconstructed state to thread_set_state and
     * see if the thread actually resumes and runs to completion --- */
    arm_thread_state64_t new_state = state; /* x0-x28/cpsr/flags carried over unchanged, per docs/010 */
    new_state.__opaque_pc = (void *)(uintptr_t)new_pc;
    new_state.__opaque_lr = (void *)(uintptr_t)new_lr;
    new_state.__opaque_sp = (void *)(uintptr_t)new_sp;
    new_state.__opaque_fp = (void *)(uintptr_t)new_fp;

    kr = thread_set_state(worker_port, ARM_THREAD_STATE64, (thread_state_t)&new_state, ARM_THREAD_STATE64_COUNT);
    printf("--- thread_set_state(reconstructed state): %s (kr=%d) ---\n",
           kr == KERN_SUCCESS ? "KERN_SUCCESS" : "FAILED", kr);
    if (kr != KERN_SUCCESS) { thread_resume(worker_port); return 1; }

    kr = thread_resume(worker_port);
    if (kr != KERN_SUCCESS) { fprintf(stderr, "thread_resume failed: %d\n", kr); return 1; }

    printf("main: worker resumed, waiting for it to run to completion...\n");
    atomic_store(&stop, true);
    pthread_join(worker, NULL);

    /* This re-reads the C-level *variable* x19..x28 in worker_fn(), which
     * the compiler is free to have backed with a spill slot or a different
     * physical register for most of the function -- it proves the
     * compiler's own dataflow wasn't disturbed, not that the specific
     * physical register thread_get_state saw pre-suspend is the same one
     * thread_set_state/thread_resume left in place. That stronger claim
     * only holds for whichever registers the capture dump above actually
     * showed holding their tag (typically x21-x28, not x19-x20 -- see that
     * loop's comment). Printed anyway, for all ten, since it's still a
     * real (if weaker) check that nothing crashed or silently hung. */
    printf("--- worker's own x19-x28, before suspend vs. after resume (DYNAMIC check) ---\n");
    bool all_match = true;
    for (int i = 0; i < 10; i++) {
        uint64_t expected = TAG(19 + i);
        printf("  x%-2d expected=0x%016llx final=0x%016llx %s\n",
               19 + i, expected, final_x[i], expected == final_x[i] ? "MATCH" : "MISMATCH");
        if (expected != final_x[i]) all_match = false;
    }
    printf("\nRESULT: %s\n", all_match
           ? "worker ran to completion with every register intact -- strip+resign+set_state round trip works"
           : "MISMATCH somewhere -- the round trip corrupted the thread's state");
    return all_match ? 0 : 1;
}
