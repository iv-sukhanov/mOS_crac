/* AI-assistance disclosure: developed with the assistance of Claude
 * (Anthropic) as a coding assistant, under the author's direction, review,
 * and testing. Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
 */
/* Minimal driver exercising cr_restore.c's do_restore(). Linked against
 * cr_restore.o + cr_common.o -- see src/Makefile. Run directly, this fails
 * (no ASLR-off, no reserved regions) -- launch via cr_restore_launcher
 * instead, which patches and spawns this binary appropriately. */
#include "cr_common.h"
#include <stdio.h>
#include <unistd.h>

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 2) { fprintf(stderr, "usage: %s <file>\n", argv[0]); return 2; }
    printf("sleeping 1s\n");
    sleep(1);
    printf("waking up\n");
    return do_restore(argv[1]);
}
