/* AI-assistance disclosure: developed with the assistance of Claude
 * (Anthropic) as a coding assistant, under the author's direction, review,
 * and testing. Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
 */
/* Minimal driver exercising cr_restore.c's do_restore(). Linked against
 * cr_restore.o + cr_common.o -- see src/Makefile. Needs the built binary
 * patched with extend_segment_vmsize.py and launched via spawn_noaslr
 * (both still in tests/) -- run directly, it will fail; see cr_restore.c's
 * file header. */
#include "cr_common.h"
#include <stdio.h>

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 2) { fprintf(stderr, "usage: %s <file>\n", argv[0]); return 2; }
    return do_restore(argv[1]);
}
