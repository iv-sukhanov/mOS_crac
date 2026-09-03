/* Minimal driver exercising cr_test.c's do_capture(), single-threaded
 * self-capture case (2026-09-01). #includes the .c directly -- this
 * project has no multi-.o linking today (see tests/Makefile's generic
 * rule), and cr_test.c is deliberately a shared module, not its own
 * binary. */
#include "cr_test.c"

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 2) { fprintf(stderr, "usage: %s <file>\n", argv[0]); return 2; }
    return do_capture(argv[1]);
}
