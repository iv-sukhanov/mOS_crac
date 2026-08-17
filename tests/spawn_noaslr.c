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
 */
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>

#ifndef _POSIX_SPAWN_DISABLE_ASLR
#define _POSIX_SPAWN_DISABLE_ASLR 0x0100
#endif

extern char **environ;

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <path> [args...]\n", argv[0]);
        return 2;
    }

    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_setflags(&attr, _POSIX_SPAWN_DISABLE_ASLR);

    pid_t pid;
    int rc = posix_spawn(&pid, argv[1], NULL, &attr, &argv[1], environ);
    posix_spawnattr_destroy(&attr);
    if (rc != 0) {
        fprintf(stderr, "posix_spawn failed: %s\n", strerror(rc));
        return 1;
    }

    int status;
    if (waitpid(pid, &status, 0) == -1) { perror("waitpid"); return 1; }
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) { fprintf(stderr, "child killed by signal %d\n", WTERMSIG(status)); return 128 + WTERMSIG(status); }
    return 1;
}
