/* crac_daemon.c -- idle PAC-key anchor for mos_crac's checkpoint/restore
 * (NOTES.md 2026-09-10, "BREAKTHROUGH" entry).
 *
 * Its only job is to exist. As a non-platform, ad-hoc-signed arm64e binary
 * it lands in the kernel's "T-" pointer-authentication A-key bucket, same
 * as cr_capture_driver and cr_restore_driver. The kernel refcounts that
 * bucket's IA/DA key by how many "T-" processes are currently alive; as
 * long as at least one is, the key doesn't get regenerated. So a capture
 * and a later restore that both run while this daemon is alive get the
 * SAME key, and every captured IA/DA-signed pointer stays valid across the
 * restore -- without this, each launch gets a fresh random key (measured
 * 2026-09-10, scratchpad/pac_anchor.c).
 *
 * Standard fork/setsid daemonize sequence (see NOTES.md 2026-09-10 for why
 * setsid() must run in a forked child, not the process job control handed
 * us directly), then parks in pause() forever -- 0% CPU, negligible RSS.
 * Writes its own final (post-fork) pid to CRAC_DAEMON_PIDFILE so a spawner
 * can learn it without a pipe/handshake.
 *
 * Known limits (see NOTES.md): boot-local (the "T-" key is regenerated
 * every boot), and a single point of failure -- if this process dies,
 * every checkpoint taken while it was alive becomes unrestorable. Not
 * hardened against logout/session teardown; see NOTES.md for why a real
 * launchd job would be the robust fix and why it wasn't done here.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>

#define CRAC_DAEMON_PIDFILE "/tmp/crac_daemon.pid"

static void write_pidfile(void) {
    FILE* f = fopen(CRAC_DAEMON_PIDFILE, "w");
    if (!f) return; /* best-effort -- a spawner that never sees this file
                        just times out and treats the launch as failed */
    fprintf(f, "%d\n", (int)getpid());
    fclose(f);
}

int main(void) {
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 1; }
    if (pid > 0) return 0; /* whoever launched us gets control back at once */

    /* Child: never a process-group leader (it inherited the parent's pgid),
     * so setsid() is guaranteed to succeed here regardless of how we were
     * launched -- new session, new pgid, NO controlling terminal. Without
     * this, closing the terminal that (indirectly) launched us would send
     * SIGHUP to the daemon along with everything else attached to it. */
    if (setsid() < 0) { perror("setsid"); return 1; }

    /* Defensive second fork (classic SVR4 daemon idiom): only a session
     * leader can ever acquire a controlling tty (by open()ing one without
     * O_NOCTTY); re-forking means the final process isn't the session
     * leader, so it structurally cannot pick one up later. We never open a
     * tty here, so this is pure insurance, but it's free. */
    pid = fork();
    if (pid < 0) { perror("fork"); return 1; }
    if (pid > 0) return 0;

    chdir("/");   /* don't pin whatever filesystem our launch cwd was on */
    umask(0);

    int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
        dup2(devnull, STDIN_FILENO);
        dup2(devnull, STDOUT_FILENO);
        dup2(devnull, STDERR_FILENO); /* release any reference to the tty device itself */
        if (devnull > 2) close(devnull);
    }

    /* Belt-and-suspenders: setsid() already means no SIGHUP can reach us via
     * tty hangup, but ignore it too in case anything ever signals us
     * directly (e.g. `killall -HUP crac_daemon`). */
    signal(SIGHUP, SIG_IGN);

    write_pidfile();

    for (;;) pause();
    return 0;
}
