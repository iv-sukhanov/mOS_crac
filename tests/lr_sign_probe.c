/* Standalone PAC probe (2026-09-01), independent of the capture/restore
 * machinery: does the signed LR value ARM's PAC puts on the stack differ
 * across separate process launches, the way struct pthread's DB-keyed
 * signature does (docs/007), or is it process-invariant like the shared
 * cache's IA-keyed function pointers (confirmed this session -- see
 * NOTES.md 2026-09-01, the __sF[]._write finding)?
 *
 * Method: recurse through a few non-leaf frames, each reading its OWN raw
 * x30 (LR) and sp via inline asm right on entry -- before any nested call
 * can clobber x30, and without going through __builtin_return_address()
 * (which may already strip/authenticate under the hood, defeating the
 * point). Print both per frame. Run under spawn_noaslr so sp -- LR's own
 * signing modifier on this ABI -- is pinned identical across separate
 * launches; a differing sp would by itself change the tag even under an
 * identical key, confounding the comparison. Compare two same-boot runs
 * first (cheap, no reboot needed -- same trick that already worked for the
 * __sF[]._write finding); a cross-boot comparison is a separate, lower-
 * priority follow-up.
 *
 * Must build -arch arm64e -- comparing a real signed LR against a plain-
 * arm64 (PAC-disabled, hardware-no-op) one would test "is it signed at
 * all", not "does the key differ" (exactly the lesson from this session's
 * __swrite bug: the capture side there was plain arm64, not a key
 * mismatch). Both runs being compared must be genuinely arm64e.
 *
 * Second check, same run (added once the above was confirmed): can WE
 * recreate pacibsp's own signature ourselves, explicitly, via xpaci
 * (strip) + pacib+sp (resign)? Validates the actual mechanism -- key (IB)
 * and modifier (sp) -- the eventual restore-side fix needs, before trying
 * it cross-process.
 */
#include <stdint.h>
#include <stdio.h>

#if !__has_feature(ptrauth_calls)
#error "build with -arch arm64e -- see file header for why this is required"
#endif

#define DEPTH 5

static void leaf_marker(int level) __attribute__((noinline));
static void leaf_marker(int level) {
    /* Genuinely leaf -- no calls, so no pacibsp/spill of its own. Only
     * present to end the recursion; not itself a comparison point. */
    printf("frame=%d (leaf, no LR of its own to sign)\n", level);
}

static void frame(int level) __attribute__((noinline));
static void frame(int level) {
    uint64_t lr, sp, fp, entry_sp, raw, resigned;
    __asm__ volatile("mov %0, x30" : "=r"(lr));
    __asm__ volatile("mov %0, sp"  : "=r"(sp));
    __asm__ volatile("mov %0, x29" : "=r"(fp));
    /* pacibsp signed `lr` using SP as it stood BEFORE this frame's own
     * prologue allocated anything (it's the first instruction executed,
     * before any stack allocation) -- NOT the live, post-prologue `sp`
     * read above. Per the FP-chain discussion: that entry sp is always
     * recoverable as fp+0x10 (the frame record {old fp, lr} always sits
     * exactly 16 bytes below entry sp, confirmed against pthread_kill's
     * own disassembly, not just the simple-prologue case). Using plain
     * `sp` here instead was tried first and produced a real, diagnostic
     * mismatch: every frame's `resigned` exactly matched the *next*
     * frame's `lr` -- because this frame's post-prologue sp equals the
     * next recursion level's entry sp, proving the mechanism was already
     * right and only the modifier was wrong. */
    entry_sp = fp + 0x10;

    /* Strip pacibsp's own signature -- no auth needed, xpaci just masks the
     * tag bits back off -- to recover the raw, unsigned return address,
     * then re-sign it ourselves with an explicit pacib+entry_sp: LR's own
     * key (ptrauth_key_return_address = IB, NOT IA -- NOTES 2026-09-01)
     * and modifier (entry_sp, matching pacibsp's own implicit operand). If
     * this reproduces pacibsp's own output bit-for-bit, we've confirmed we
     * can recreate a valid signature ourselves rather than merely observe
     * one -- the exact mechanism the eventual restore-side fix needs
     * (strip a foreign-key LR, resign it with the current process's own
     * live key). */
    __asm__ volatile(
        "mov x0, %1\n\t"
        "xpaci x0\n\t"
        "mov %0, x0"
        : "=r"(raw) : "r"(lr) : "x0");
    __asm__ volatile(
        "mov x0, %1\n\t"
        "mov x1, %2\n\t"
        "pacib x0, x1\n\t"
        "mov %0, x0"
        : "=r"(resigned) : "r"(raw), "r"(entry_sp) : "x0", "x1");

    printf("frame=%d lr=0x%016llx sp=0x%016llx entry_sp=0x%016llx raw=0x%016llx resigned=0x%016llx %s\n",
           level, (uint64_t)lr, (uint64_t)sp, (uint64_t)entry_sp, (uint64_t)raw, (uint64_t)resigned,
           resigned == lr ? "MATCH -- recreated pacibsp's own signature" : "MISMATCH");
    if (level < DEPTH) {
        frame(level + 1);
    } else {
        leaf_marker(level + 1);
    }
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    frame(1);
    return 0;
}
