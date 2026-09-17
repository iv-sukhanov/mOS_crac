/* AI-assistance disclosure: developed with the assistance of Claude
 * (Anthropic) as a coding assistant, under the author's direction, review,
 * and testing. Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
 */
/* cr_capture.c -- do_capture(): classify -> per-region buffers ->
 * self-signal -> write file. See cr_common.h for the wire format shared
 * with cr_restore.c, and cr_restore.c's file header for the overall
 * capture/restore design.
 *
 * BUILD: -arch arm64e (see cr_common.h's ptrauth_calls guard).
 *
 *   0. find_or_launch_daemon(): look up crac_daemon by comm name, launching
 *      it if it isn't running. Its pid goes into the header as a
 *      diagnostic -- see checkpoint_header_t.daemon_pid.
 *   1. classify_regions(): walk our own address space, keep every private
 *      region that is writable or was once writable, skipping the dyld
 *      shared cache's immutable pages.
 *   2. allocate one exactly-sized mmap'd buffer per region -- mmap, not
 *      malloc: malloc could carve its arena out of a region we're about to
 *      capture; a fresh mapping is its own vm_map entry and post-dates
 *      classification, so it never lands in the list.
 *   3. raise(SIGUSR1): the handler runs on this same thread/stack, snapshots
 *      registers + pthread_addr + live munge, and memcpy's each
 *      already-classified region into its buffer.
 *   4. write header + region descriptors + region bytes.
 */
#include "cr_common.h"

#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <mach/mach_vm.h>
#include <mach/mach.h>
#include <libproc.h>
#include <sys/param.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <spawn.h>

extern char **environ;

#define CRAC_DAEMON_PIDFILE "/tmp/crac_daemon.pid"

/* TODO: task_threads()'s own out-of-line `acts` array (do_capture()) has
 * to exist before classify_regions() runs (needed to suspend everyone
 * first), so it always ends up captured as an ordinary region -- and
 * these static globals get captured too, as part of this file's own data
 * segment, no matter when anything here runs. Reconsider whether
 * capture-tool-internal state should be excluded from the checkpoint at
 * all (the way shared-cache pages already are) rather than accepted as
 * unavoidable -- not done here since it doesn't change capture_used size
 * either way (the data segment is captured as one region regardless). */
static region_desc_t g_regions[MAX_REGIONS];
static void*         g_region_bufs[MAX_REGIONS];
static uint32_t      g_region_count;
static uint64_t      g_munge;
static void*         g_threads;
static uint32_t      g_main_th_ind;

/* --- region classification --- */

static bool should_capture(mach_vm_address_t addr, const vm_region_submap_info_data_64_t* info) {
    if (info->protection == VM_PROT_NONE) return false; /* guard pages, VA reservations */

    if (info->external_pager) {
        /* File-backed. Skip an unresolved (no real path) region only if
         * it's executable or can never be written. */
        char buf[MAXPATHLEN];
        int ret = proc_regionfilename(getpid(), addr, buf, sizeof(buf));
        if (ret <= 0 && (info->protection & VM_PROT_EXECUTE || info->max_protection == VM_PROT_READ)) {
            return false;
        }
    } else if (in_shared_cache_submap(addr) || in_shared_cache_range(addr)) {
        if (info->protection & VM_PROT_EXECUTE) {
            printf("  note: executable non-external-pager region in shared-cache "
                   "range at 0x%llx prot=%u -- capturing\n", (uint64_t)addr, info->protection);
        }
        /* Skip only immutable cache pages; a read-only page that COULD be
         * written (max_protection) may hold COW-modified data. */
        return info->max_protection != VM_PROT_READ;
    }
    return true;
}

static int classify_regions(void) {
    g_region_count = 0;
    mach_vm_address_t addr = 0;
    while (g_region_count < MAX_REGIONS) {
        mach_vm_address_t a = addr;
        mach_vm_size_t size = 0;
        natural_t depth = 32;
        vm_region_submap_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        kern_return_t kr = mach_vm_region_recurse(mach_task_self(), &a, &size, &depth,
                                                   (vm_region_recurse_info_t)&info, &count);
        if (kr != KERN_SUCCESS) break;

        if (should_capture(a, &info)) {
            g_regions[g_region_count].addr = a;
            g_regions[g_region_count].len = size;
            g_regions[g_region_count].protection = (uint32_t)info.protection;
            g_region_count++;
        }
        addr = a + size;
    }
    if (g_region_count == MAX_REGIONS) {
        fprintf(stderr, "classify_regions: hit MAX_REGIONS=%d -- checkpoint would be truncated\n", MAX_REGIONS);
        return 1;
    }
    return 0;
}

static int allocate_thread_buf(uint32_t thread_count) {
    g_threads = mmap(NULL, thread_count * sizeof(thread_desc_t),
                     PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (g_threads == MAP_FAILED) {
        fprintf(stderr, "mmap failed for thread buffer (%llu bytes): %s\n",
                (uint64_t)(thread_count * sizeof(thread_desc_t)), strerror(errno));
        return 1;
    }
    return 0;
}

/* mmap, not malloc -- see file header. */
static int allocate_region_bufs(void) {
    for (uint32_t i = 0; i < g_region_count; i++) {
        void* buf = mmap(NULL, g_regions[i].len, PROT_READ | PROT_WRITE,
                          MAP_ANON | MAP_PRIVATE, -1, 0);
        if (buf == MAP_FAILED) {
            fprintf(stderr, "mmap failed for region[%u] buffer (%llu bytes): %s\n",
                    i, (uint64_t)g_regions[i].len, strerror(errno));
            return 1;
        }
        g_region_bufs[i] = buf;
    }
    return 0;
}

/* do_capture() may run more than once per process; don't leak the buffers. */
static void free_thread_buf(uint32_t thread_count) {
    if (g_threads) {
        munmap(g_threads, thread_count * sizeof(thread_desc_t));
        g_threads = NULL;
    }
}

static void free_region_bufs(void) {
    for (uint32_t i = 0; i < g_region_count; i++) {
        if (g_region_bufs[i]) {
            munmap(g_region_bufs[i], g_regions[i].len);
            g_region_bufs[i] = NULL;
        }
    }
}

/* Snapshot registers, then memcpy each already-classified region. */
static void capture_state(int sig, siginfo_t* info, void* ctx) {
    (void)sig; (void)info;
    thread_desc_t* td = &((thread_desc_t*)g_threads)[g_main_th_ind];
    td->regs.gregs = ((ucontext_t*)ctx)->uc_mcontext->__ss;
    td->regs.neon  = ((ucontext_t*)ctx)->uc_mcontext->__ns;
    __asm__ volatile ("mrs %0, tpidr_el0" : "=r" (td->regs.tpidr));
    td->pthread_addr = (uint64_t)(uintptr_t)pthread_self();
    uintptr_t stored_sig = *(uintptr_t *)(uintptr_t)td->pthread_addr;
    g_munge = stored_sig ^ sign_for_addr((uintptr_t)td->pthread_addr);

    for (uint32_t i = 0; i < g_region_count; i++) {
        memcpy(g_region_bufs[i], (void*)(uintptr_t)g_regions[i].addr, g_regions[i].len);
    }
}

/* --- crac_daemon lookup/launch, see its own file header --- */

/* crac_daemon is built into the same directory as this binary. */
static int daemon_binary_path(char* out, size_t outsz) {
    char self[PROC_PIDPATHINFO_MAXSIZE];
    if (proc_pidpath(getpid(), self, sizeof(self)) <= 0) return -1;
    char* slash = strrchr(self, '/');
    if (!slash) return -1;
    *slash = '\0';
    snprintf(out, outsz, "%s/%s", self, CRAC_DAEMON_NAME);
    return 0;
}

/* Match by comm name (what `ps`/proc_name() report) -- unprivileged. */
static pid_t find_running_daemon(void) {
    pid_t pids[4096]; // TODO: get rid of hard-coded limit
    int bytes = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
    if (bytes <= 0) return -1;
    int n = bytes / (int)sizeof(pid_t);
    for (int i = 0; i < n; i++) {
        if (pids[i] <= 0) continue;
        char name[64] = {0};
        if (proc_name(pids[i], name, sizeof(name)) <= 0) continue;
        if (strcmp(name, CRAC_DAEMON_NAME) == 0) return pids[i];
    }
    return -1;
}

/* posix_spawn crac_daemon, reap the immediate child (it daemonizes and
 * exits almost at once), then poll for its real pid via CRAC_DAEMON_PIDFILE
 * (posix_spawn only hands back the outer, already-exited process's pid). */
static pid_t launch_daemon(void) {
    char path[MAXPATHLEN];
    if (daemon_binary_path(path, sizeof(path)) != 0) {
        fprintf(stderr, "launch_daemon: couldn't resolve own executable path\n");
        return -1;
    }
    unlink(CRAC_DAEMON_PIDFILE); /* drop a stale pidfile from a previous, now-dead daemon */

    pid_t spawned;
    char* argv[] = { path, NULL };
    int rc = posix_spawn(&spawned, path, NULL, NULL, argv, environ);
    if (rc != 0) {
        fprintf(stderr, "launch_daemon: posix_spawn(%s) failed: %s\n", path, strerror(rc));
        return -1;
    }
    int status;
    waitpid(spawned, &status, 0);

    for (int i = 0; i < 50; i++) { /* ~500ms total */
        FILE* pf = fopen(CRAC_DAEMON_PIDFILE, "r");
        if (pf) {
            long pid = 0;
            int got = fscanf(pf, "%ld", &pid);
            fclose(pf);
            if (got == 1 && pid > 0) return (pid_t)pid;
        }
        usleep(10 * 1000);
    }
    fprintf(stderr, "launch_daemon: timed out waiting for %s to write %s\n",
            CRAC_DAEMON_NAME, CRAC_DAEMON_PIDFILE);
    return -1;
}

/* Reuse a live crac_daemon if one exists; launch one otherwise. Never
 * fatal -- returns -1 on failure, capture proceeds regardless. */
static pid_t find_or_launch_daemon(void) {
    pid_t pid = find_running_daemon();
    if (pid > 0) {
        printf("crac_daemon already running (pid=%d)\n", pid);
        return pid;
    }
    pid = launch_daemon();
    if (pid > 0) printf("launched crac_daemon (pid=%d)\n", pid);
    else fprintf(stderr, "find_or_launch_daemon: no crac_daemon available -- "
                          "capture will proceed, but this checkpoint's PAC keys "
                          "may not survive to restore time\n");
    return pid;
}

/* Resume every non-main thread in acts[0, count) */
static void resume_threads(thread_act_array_t acts, mach_msg_type_number_t count, mach_port_t main_port) {
    for (mach_msg_type_number_t i = 0; i < count; i++) {
        if (acts[i] == main_port) continue;
        if (thread_resume(acts[i]) != KERN_SUCCESS) {
            fprintf(stderr, "thread_resume failed for thread[%u]\n", i);
            continue;
        }
        printf("resumed thread[%u] port=0x%x\n", i, acts[i]);
    }
}

int do_capture(const char* path) {
    /* volatile: force a real load on each check below, since a restored
     * thread's GPRs are seeded from what was resident at capture time. */
    volatile int restored_flag = 0;
    uint64_t sentinel = (uint64_t)(uintptr_t)&restored_flag;

    pid_t daemon_pid = find_or_launch_daemon();

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_flags = SA_SIGINFO;
    sa.__sigaction_u.__sa_sigaction = capture_state;
    if (sigaction(SIGUSR1, &sa, NULL) == -1) { perror("sigaction"); return 1; }

    thread_act_array_t acts;
    mach_msg_type_number_t n_acts;
    if (task_threads(mach_task_self(), &acts, &n_acts) != KERN_SUCCESS) {
        fprintf(stderr, "task_threads failed\n");
        return 1;
    }

    printf("found %u threads\n", n_acts);

    /* Freeze every peer BEFORE looking at memory at all: classify_regions()
     * and allocate_region_bufs() below need a quiesced process, not one
     * where a peer can still mmap/munmap/mprotect underneath them between
     * being classified and being memcpy'd. */
    mach_port_t main_port = mach_thread_self();
    for (mach_msg_type_number_t i = 0; i < n_acts; i++) {
        if (acts[i] == main_port) {
            g_main_th_ind = i;
            continue;
        }
        if (thread_suspend(acts[i]) != KERN_SUCCESS) {
            fprintf(stderr, "thread_suspend failed for thread[%u]\n", i);
            resume_threads(acts, i, main_port); /* only what's actually suspended so far */
            vm_deallocate(mach_task_self(), (vm_address_t)acts, sizeof(thread_act_t) * n_acts);
            return 1;
        }
        printf("suspended thread[%u] port=0x%x\n", i, acts[i]);
    }

    if (classify_regions() != 0) {
        resume_threads(acts, n_acts, main_port);
        vm_deallocate(mach_task_self(), (vm_address_t)acts, sizeof(thread_act_t) * n_acts);
        return 1;
    }
    uint64_t total = 0;
    for (uint32_t i = 0; i < g_region_count; i++) {
        total += g_regions[i].len;
        printf("  region[%u] [0x%llx,0x%llx) %.2fMB prot=%u\n", i,
               (uint64_t)g_regions[i].addr,
               (uint64_t)(g_regions[i].addr + g_regions[i].len),
               g_regions[i].len / (1024.0 * 1024.0), g_regions[i].protection);
    }
    printf("classified %u regions, %.2f MB total\n", g_region_count, total / (1024.0 * 1024.0));
    if (allocate_region_bufs() != 0) {
        resume_threads(acts, n_acts, main_port);
        vm_deallocate(mach_task_self(), (vm_address_t)acts, sizeof(thread_act_t) * n_acts);
        return 1;
    }

    if (allocate_thread_buf(n_acts) != 0) {
        vm_deallocate(mach_task_self(), (vm_address_t)acts, sizeof(thread_act_t) * n_acts);
        return 1;
    }

    for (mach_msg_type_number_t i = 0; i < n_acts; i++) {
        if (acts[i] == main_port) continue;
        thread_desc_t* td = &((thread_desc_t*)g_threads)[i];
        mach_msg_type_number_t gcount = ARM_THREAD_STATE64_COUNT;
        mach_msg_type_number_t ncount = ARM_NEON_STATE64_COUNT;
        if (thread_get_state(acts[i], ARM_THREAD_STATE64, (thread_state_t)&td->regs.gregs, &gcount) != KERN_SUCCESS) {
            fprintf(stderr, "thread_get_state(GENERAL) failed for thread[%u]\n", i);
            resume_threads(acts, n_acts, main_port);
            vm_deallocate(mach_task_self(), (vm_address_t)acts, sizeof(thread_act_t) * n_acts);
            return 1;
        }
        if (thread_get_state(acts[i], ARM_NEON_STATE64, (thread_state_t)&td->regs.neon, &ncount) != KERN_SUCCESS) {
            fprintf(stderr, "thread_get_state(NEON) failed for thread[%u]\n", i);
            resume_threads(acts, n_acts, main_port);
            vm_deallocate(mach_task_self(), (vm_address_t)acts, sizeof(thread_act_t) * n_acts);
            return 1;
        }
        td->regs.tpidr = 0; /* TODO: add tpidr */
        td->pthread_addr = (uint64_t)(uintptr_t)pthread_from_mach_thread_np(acts[i]);
        printf("thread[%u] port=0x%x pthread_addr=0x%llx pc=0x%llx sp=0x%llx\n", 
            i, acts[i], (uint64_t)td->pthread_addr, 
            (uint64_t)arm_thread_state64_get_pc_fptr(td->regs.gregs), 
            (uint64_t)arm_thread_state64_get_sp(td->regs.gregs));
    }

    raise(SIGUSR1); /* synchronous: handler runs here, then execution continues below */

    /* A resume seeds PC back to about here with *sentinel already 1. */
    if (restored_flag != 0) {
        printf("resumed from a restore -- not writing a checkpoint again\n");
        return 0;
    }

    printf("captured %u regions, %.2f MB\n", g_region_count, total / (1024.0 * 1024.0));

    thread_desc_t *td = &((thread_desc_t*)g_threads)[g_main_th_ind];
    printf("main thread port=0x%x pthread_addr=0x%llx pc=0x%llx sp=0x%llx\n", 
        main_port, (uint64_t)td->pthread_addr, 
        (uint64_t)arm_thread_state64_get_pc_fptr(td->regs.gregs), 
        (uint64_t)arm_thread_state64_get_sp(td->regs.gregs));

    FILE* f = fopen(path, "wb");
    if (!f) { perror("fopen"); free_region_bufs(); return 1; }
    checkpoint_header_t hdr = {
        .thread_count = n_acts,
        .region_count = g_region_count,
        .capture_used = total,
        .munge = g_munge,
        .sentinel = sentinel,
        .daemon_pid = (int32_t)daemon_pid,
    };
    fwrite(&hdr, sizeof(hdr), 1, f);
    fwrite(g_threads, sizeof(thread_desc_t), n_acts, f);
    fwrite(g_regions, sizeof(region_desc_t), g_region_count, f);
    for (uint32_t i = 0; i < g_region_count; i++) {
        fwrite(g_region_bufs[i], 1, g_regions[i].len, f);
    }
    fclose(f);
    printf("checkpoint written to %s\n", path);

    free_region_bufs();
    free_thread_buf(n_acts);

    resume_threads(acts, n_acts, main_port);
    vm_deallocate(mach_task_self(), (vm_address_t)acts, sizeof(thread_act_t) * n_acts);

    return 0;
}
