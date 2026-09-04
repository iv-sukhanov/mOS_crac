/* Minimal driver exercising cr_test.c's do_restore() (2026-09-03).
 * #includes the .c directly -- same reasoning as cr_capture_driver.c. */
#include "cr_test.c"

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 2) { fprintf(stderr, "usage: %s <file>\n", argv[0]); return 2; }
    return do_restore(argv[1]);
}
