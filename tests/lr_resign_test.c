/* Lock the stack-walk + resign mechanism before touching real restore code
 * (2026-09-01): main -> f1 -> f2 -> f3, and f3 walks the FP chain all the
 * way up (not just its own frame), stripping and resigning every frame's
 * LR in place on the real stack. Validated per-frame formula (fp+0x10 as
 * modifier) is from lr_sign_probe.c; this test's job is to confirm walking
 * + rewriting the real stack doesn't break anything -- if the mechanism is
 * right, every rewrite is bit-identical to what was already there and nothing
 * breaks; if not, we see it as either a MISMATCH print or an outright crash
 * when a frame later actually returns through its rewritten record.
 *
 * Stop condition: fp==0 AND (stripped) lr==0 together -- confirmed directly
 * via lldb, not assumed from ABI docs: _dyld_start sets both x29 and x30 to
 * 0 before jumping to its successor, which then pushes them as its own
 * frame's {old fp, lr} record (fp=0 raw, lr=PAC(0) -- a real signed zero,
 * which is exactly why the check strips lr first and compares the STRIPPED
 * value against 0, not the raw memory word).
 */
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#if !__has_feature(ptrauth_calls)
#error "build with -arch arm64e -- see file header for why this is required"
#endif

void f3(void) __attribute__((noinline));
void f3(void) {
    uint64_t fp, stack_fp, stack_lr, modifier_sp;
    __asm__ volatile("mov %0, x29" : "=r"(fp));
    for (int i = 0;; fp = stack_fp, i++) {
        stack_fp = *(uint64_t *)(intptr_t)fp;
        stack_lr = *(uint64_t *)(intptr_t)(fp + 0x8);
        uint64_t orig_lr = stack_lr; /* pre-strip, for the MATCH/MISMATCH check below */

        printf("f3, iter=%d: before stripping: lr=0x%016llx\n", i, stack_lr);
        __asm__ volatile("xpaci %0" : "+r"(stack_lr));
        printf("f3, iter=%d: after xpaci: lr=0x%016llx\n", i, stack_lr);

        if (stack_lr == 0 && stack_fp == 0) {
            printf("f3, iter=%d: reached end of stack (fp=0, lr strips to 0)\n", i);
            break;
        }

        modifier_sp = fp + 0x10;
        __asm__ volatile("pacib %0, %1" : "+r"(stack_lr) : "r"(modifier_sp));
        printf("f3, iter=%d: after pacib with modifier_sp=0x%016llx: lr=0x%016llx %s\n",
               i, modifier_sp, stack_lr, stack_lr == orig_lr ? "MATCH" : "MISMATCH");

        *(uint64_t *)(intptr_t)(fp + 0x8) = stack_lr;

        /* Safety net: a valid chain is strictly increasing in address going
         * outward (stack grows down, so the caller's frame always sits
         * above the callee's). Not needed for this clean, single-threaded,
         * uncorrupted stack -- but costs nothing, and is exactly the guard
         * a real restore engine will want against a corrupted/foreign
         * chain later. Checked on the NEXT hop, since the current frame
         * (just resigned above) was already validly reached. */
        if (stack_fp <= fp) {
            printf("f3, iter=%d: SAFETY NET TRIPPED -- next fp 0x%016llx not "
                   "strictly greater than current fp 0x%016llx, stack walk "
                   "looks corrupted, aborting\n", i, stack_fp, fp);
            break;
        }
    }
}

void f2(void) __attribute__((noinline));
void f2(void) {
    uint64_t lr, sp, fp, new_lr;
    __asm__ volatile("mov %0, x30" : "=r"(lr));
    __asm__ volatile("mov %0, x29" : "=r"(fp));
    __asm__ volatile("mov %0, sp"  : "=r"(sp));

    printf("f2: calling f3 with lr=0x%016llx sp=0x%016llx fp=0x%016llx\n", lr, sp, fp);
    f3();
    printf("f2: back from f3\n");

    __asm__ volatile("ldr %0, [x29, 0x8]" : "=r"(new_lr));
    printf("f2: own frame's lr re-read from stack: 0x%016llx %s\n",
           new_lr, new_lr == lr ? "MATCH" : "MISMATCH");
}

void f1(void) __attribute__((noinline));
void f1(void) {
    uint64_t lr, sp, fp, new_lr;
    __asm__ volatile("mov %0, x30" : "=r"(lr));
    __asm__ volatile("mov %0, x29" : "=r"(fp));
    __asm__ volatile("mov %0, sp"  : "=r"(sp));

    printf("f1: calling f2 with lr=0x%016llx sp=0x%016llx fp=0x%016llx\n", lr, sp, fp);
    f2();
    printf("f1: back from f2\n");

    __asm__ volatile("ldr %0, [x29, 0x8]" : "=r"(new_lr));
    printf("f1: own frame's lr re-read from stack: 0x%016llx %s\n",
           new_lr, new_lr == lr ? "MATCH" : "MISMATCH");
}

int main(void) {
    uint64_t lr, new_lr;
    /* Must be the very first thing, before ANY call (including setvbuf) --
     * x30 is clobbered by whatever a callee's own internals last leave
     * there, even after that callee fully returns (its own retab strips
     * its OWN signed value, not necessarily main's). f1/f2/f3 all read
     * their registers first for the same reason; this file's first draft
     * didn't, and that alone produced a spurious MISMATCH here even though
     * the actual stack-stored value (confirmed by f3's own loop, iter=3)
     * was correct all along. */
    __asm__ volatile("mov %0, x30" : "=r"(lr));
    setvbuf(stdout, NULL, _IONBF, 0); /* crash-observability matters here -- see file header */

    printf("main: calling f1 with lr=0x%016llx\n", lr);
    f1();
    printf("main: back from f1\n");

    __asm__ volatile("ldr %0, [x29, 0x8]" : "=r"(new_lr));
    printf("main: own frame's lr re-read from stack: 0x%016llx %s\n",
           new_lr, new_lr == lr ? "MATCH" : "MISMATCH");
    return 0;
}
