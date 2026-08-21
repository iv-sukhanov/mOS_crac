/* Launches another binary with _POSIX_SPAWN_DISABLE_ASLR set, so its __TEXT
 * (and everything else the image loader positions relative to it) lands at
 * its exact link-time address instead of a randomized slide on top of it --
 * confirmed 2026-08-14 (see NOTES.md) to be the provable *lowest* address
 * that binary can ever load at, since the kernel's slide is always added,
 * never subtracted (bsd/kern/mach_loader.c: random() % bound, unsigned).
 *
 * _POSIX_SPAWN_DISABLE_ASLR (0x0100) is NOT in any public header on this
 * SDK -- confirmed absent from spawn.h and `man posix_spawnattr_setflags`.
 * It's real (same value used by lldb/gdb since Mac OS X Lion, confirmed
 * both empirically here and against public XNU source, bsd/sys/spawn.h),
 * but undocumented -- same risk class already accepted for
 * os_sync_wait_on_address over __ulock_wait elsewhere in this project:
 * could change or vanish across an OS update without notice. Revisit if it
 * ever does.
 *
 * `-r <n>` (2026-08-21): retry up to n times, in a fresh process each time,
 * whenever the child exits EX_TEMPFAIL -- the code
 * sim_noaslr_restore_test.c's map_fixed_or_retry() uses to mean "this
 * launch's malloc-guard-page layout collided with the restore target, try
 * a different one" (see NOTES.md 2026-08-21/2026-08-17: that collision is
 * unfixable within one process, but its placement is randomized per launch,
 * so a fresh process is a fresh roll).
 *
 * IMPORTANT, found the hard way (NOTES.md 2026-08-21): `-r` does NOT combine
 * with disabling ASLR. Verified directly -- 6/6 identical collide/clean
 * outcome across independent ASLR-disabled launches against the same
 * checkpoint file. `_POSIX_SPAWN_DISABLE_ASLR` doesn't just fix the kernel's
 * image slide, it fixes the *whole* process layout, malloc's own
 * guard-page placement included, so every relaunch is the exact same roll
 * -- retrying buys nothing. So: `-r` (n>1) leaves ASLR on (real per-launch
 * variability, which retry actually needs); omitting -r (n=1, the default)
 * keeps the original single-shot ASLR-disabled behavior exactly.
 */
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <sys/wait.h>

#ifndef _POSIX_SPAWN_DISABLE_ASLR
#define _POSIX_SPAWN_DISABLE_ASLR 0x0100
#endif

extern char **environ;

int main(int argc, char **argv) {
    int argi = 1;
    int max_attempts = 1;
    if (argi < argc && strcmp(argv[argi], "-r") == 0) {
        if (argi + 1 >= argc) { fprintf(stderr, "-r needs an attempt count\n"); return 2; }
        max_attempts = atoi(argv[argi + 1]);
        if (max_attempts < 1) { fprintf(stderr, "-r attempt count must be >= 1\n"); return 2; }
        argi += 2;
    }
    if (argi >= argc) {
        fprintf(stderr, "usage: %s [-r max_attempts] <path> [args...]\n", argv[0]);
        return 2;
    }

    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    if (max_attempts == 1) {
        /* Single-shot: original deterministic-layout behavior, unchanged. */
        posix_spawnattr_setflags(&attr, _POSIX_SPAWN_DISABLE_ASLR);
    }
    /* max_attempts > 1: leave ASLR on -- see the top-of-file note on why
     * retry and disabled-ASLR don't combine. */

    int status = 0;
    for (int attempt = 1; attempt <= max_attempts; attempt++) {
        pid_t pid;
        int rc = posix_spawn(&pid, argv[argi], NULL, &attr, &argv[argi], environ);
        if (rc != 0) {
            fprintf(stderr, "posix_spawn failed: %s\n", strerror(rc));
            posix_spawnattr_destroy(&attr);
            return 1;
        }
        if (waitpid(pid, &status, 0) == -1) {
            perror("waitpid");
            posix_spawnattr_destroy(&attr);
            return 1;
        }

        if (WIFEXITED(status) && WEXITSTATUS(status) == EX_TEMPFAIL && attempt < max_attempts) {
            fprintf(stderr, "attempt %d/%d: collided (EX_TEMPFAIL), retrying in a fresh process...\n",
                    attempt, max_attempts);
            continue;
        }
        break; /* success, a real failure, signal death, or attempts exhausted */
    }
    posix_spawnattr_destroy(&attr);

    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) { fprintf(stderr, "child killed by signal %d\n", WTERMSIG(status)); return 128 + WTERMSIG(status); }
    return 1;
}
