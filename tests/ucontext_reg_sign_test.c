/* Register-by-register PAC survey of a real, kernel-delivered ucontext_t --
 * follow-on to lr_resign_test.c, which only ever looked at the STACK-stored
 * LR of a compiler-emitted frame record. Different subject here: the LIVE
 * arm_thread_state64_t a signal handler receives via uc_mcontext->__ss at
 * the instant of a self-raised trap, straight from the kernel -- nothing
 * this program signed itself.
 *
 * Motivating question, from NOTES.md 2026-09-03: cr_test.c's restore hit
 * `sigreturn` rejecting a resumed pc's signature, one step earlier than
 * the LR-resign mechanism targets. Does the kernel's own delivered pc (and
 * lr/sp/fp) carry real PAC bits at capture time, and does that hold for
 * every GPR or just the four pointer-shaped fields? Answered two ways,
 * cross-checked against each other:
 *   1. Empirically: strip every register with `xpaci`/`xpacd` and diff
 *      against the raw value -- a MISMATCH means real PAC bits were set.
 *   2. Authoritatively: <mach/arm/_structs.h>'s own opaque-field flags
 *      (__opaque_flags: NO_PTRAUTH / IB_SIGNED_LR / KERNEL_SIGNED_PC /
 *      KERNEL_SIGNED_LR / a packed "user diversifier" byte) say exactly
 *      what the kernel did -- no guessing needed, decoded and printed
 *      alongside the empirical diff as a check on it.
 *
 * On arm64e, arm_thread_state64_t's pc/lr/sp/fp fields are opaque (`void*`
 * __opaque_pc/__opaque_lr/__opaque_sp/__opaque_fp, per _structs.h) --
 * read here as raw bit patterns via a plain (uint64_t)(uintptr_t) cast,
 * deliberately NOT through the authenticating arm_thread_state64_get_*()
 * macros, which would trap (FPAC) on any signature that doesn't verify.
 * x0-x28 (__x[29]) are always plain __uint64_t regardless of arm64e --
 * never PAC-wrapped by the OS -- surveyed anyway as a same-format control
 * group that should come back 100% MATCH.
 *
 * _structs.h's own get_fp/get_sp macros sign those two with
 * ptrauth_key_process_independent_data (the "D" key), not the "I" key
 * lr_resign_test.c strips lr with -- so xpacd is the bit-correct strip for
 * fp/sp, xpaci for pc/lr. Both run against every field regardless (cheap,
 * and the project's own rule is "verify, don't assume" -- NOTES.md
 * 2026-09-03) in case the two don't actually agree on this hardware.
 */
#include <mach/thread_state.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#if !__has_feature(ptrauth_calls)
#error "build with -arch arm64e -- see file header for why this is required"
#endif

static uint64_t xpaci_of(uint64_t v) { __asm__ volatile("xpaci %0" : "+r"(v)); return v; }
static uint64_t xpacd_of(uint64_t v) { __asm__ volatile("xpacd %0" : "+r"(v)); return v; }

static void report(const char *name, uint64_t raw) {
    uint64_t i = xpaci_of(raw), d = xpacd_of(raw);
    printf("%-4s raw=0x%016llx  xpaci=0x%016llx (%s)  xpacd=0x%016llx (%s)\n",
           name, raw, i, raw == i ? "MATCH" : "MISMATCH",
           d, raw == d ? "MATCH" : "MISMATCH");
}

static void handler(int sig, siginfo_t *info, void *ctx) {
    (void)sig; (void)info;
    arm_thread_state64_t *ss = &((ucontext_t *)ctx)->uc_mcontext->__ss;

    printf("--- __opaque_flags=0x%08x ---\n", ss->__opaque_flags);
    printf("  NO_PTRAUTH:       %d\n", !!(ss->__opaque_flags & __DARWIN_ARM_THREAD_STATE64_FLAGS_NO_PTRAUTH));
    printf("  IB_SIGNED_LR:     %d\n", !!(ss->__opaque_flags & __DARWIN_ARM_THREAD_STATE64_FLAGS_IB_SIGNED_LR));
    printf("  KERNEL_SIGNED_PC: %d\n", !!(ss->__opaque_flags & __DARWIN_ARM_THREAD_STATE64_FLAGS_KERNEL_SIGNED_PC));
    printf("  KERNEL_SIGNED_LR: %d\n", !!(ss->__opaque_flags & __DARWIN_ARM_THREAD_STATE64_FLAGS_KERNEL_SIGNED_LR));
    printf("  CUSTOM_X18_ABI:   %d\n", !!(ss->__opaque_flags & __DARWIN_ARM_THREAD_STATE64_FLAGS_CUSTOM_X18_ABI));
    printf("  user diversifier byte: 0x%02x\n",
           (unsigned)((ss->__opaque_flags & __DARWIN_ARM_THREAD_STATE64_USER_DIVERSIFIER_MASK) >> 24));

    printf("--- general registers (x0-x28, always plain -- control group) ---\n");
    char name[8];
    for (int i = 0; i < 29; i++) {
        snprintf(name, sizeof(name), "x%d", i);
        report(name, ss->__x[i]);
    }

    printf("--- pointer-bearing fields (opaque on arm64e) ---\n");
    report("fp", (uint64_t)(uintptr_t)ss->__opaque_fp);
    report("lr", (uint64_t)(uintptr_t)ss->__opaque_lr);
    report("sp", (uint64_t)(uintptr_t)ss->__opaque_sp);
    report("pc", (uint64_t)(uintptr_t)ss->__opaque_pc);

    _exit(0); /* raise()'d from main; don't return into its half-run frame */
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    struct sigaction sa = {0};
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGUSR1, &sa, NULL);

    /* Tag callee-saved GPRs right before the call into raise() -- AAPCS64
     * guarantees x19-x28 survive across it. x0-x18 are caller-saved:
     * raise()'s own body is free to clobber them before the trap actually
     * happens, so whatever the handler prints for those reflects raise()'s
     * internals, not this test -- still surveyed, still expected MATCH. */
    register uint64_t x19 __asm__("x19") = 0x1919191919191919ULL;
    register uint64_t x20 __asm__("x20") = 0x2020202020202020ULL;
    register uint64_t x21 __asm__("x21") = 0x2121212121212121ULL;
    register uint64_t x22 __asm__("x22") = 0x2222222222222222ULL;
    register uint64_t x23 __asm__("x23") = 0x2323232323232323ULL;
    register uint64_t x24 __asm__("x24") = 0x2424242424242424ULL;
    register uint64_t x25 __asm__("x25") = 0x2525252525252525ULL;
    register uint64_t x26 __asm__("x26") = 0x2626262626262626ULL;
    register uint64_t x27 __asm__("x27") = 0x2727272727272727ULL;
    register uint64_t x28 __asm__("x28") = 0x2828282828282828ULL;
    __asm__ volatile("" :: "r"(x19), "r"(x20), "r"(x21), "r"(x22), "r"(x23),
                            "r"(x24), "r"(x25), "r"(x26), "r"(x27), "r"(x28));

    raise(SIGUSR1);
    printf("main: handler didn't fire or returned unexpectedly\n");
    return 1;
}
