/* Ordinary, fully normal dynamically-linked hello world -- no freestanding
 * tricks here, that's the point. Used to test whether extending an
 * existing Mach-O segment's vmsize past its filesize (same BSS-style
 * mechanism __PAGEZERO already uses) actually reserves that address range
 * before dyld/malloc ever run, the way the custom-segment idea needs.
 * See tests/extend_segment_vmsize.py for the patch itself and NOTES.md for
 * what running this found.
 */
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

/* Must land inside the actual reserved gap the patch creates -- see
 * NOTES.md for the layout math (__DATA_CONST's vmsize grows past its
 * filesize, __LINKEDIT's vmaddr moves out of the way; the gap between
 * __DATA_CONST's real content and __LINKEDIT's new start is what's
 * genuinely zero-filled/reserved, not the boundary address itself). */
#define RESERVED_ADDR 0x100010000ull

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("pid=%d\n", getpid());

    volatile uint8_t *p = (volatile uint8_t *)RESERVED_ADDR;
    printf("reading byte at reserved addr 0x%llx ...\n", (unsigned long long)RESERVED_ADDR);
    uint8_t v = *p; /* if this segfaults, the address isn't actually mapped */
    printf("read ok: byte=%d (mapped, readable -- reservation confirmed from inside the process)\n", v);

    for (;;) pause();
    return 0;
}
