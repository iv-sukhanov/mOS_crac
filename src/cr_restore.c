/* AI-assistance disclosure: developed with the assistance of Claude
 * (Anthropic) as a coding assistant, under the author's direction, review,
 * and testing. Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
 */
/* cr_restore.c -- do_restore(): a hybrid of two restore mechanisms this
 * project calls "mode C" (a signal handler rewrites a running thread's
 * state) and "mode D" (thread_set_state() seeds a suspended thread's
 * registers directly). Neither works alone: mode C's sigreturn rejects a
 * PC signed under the wrong process's PAC key; mode D can't set TPIDR_EL0
 * or run code before the thread resumes. The hybrid combines them: GPR+NEON
 * are seeded via thread_set_state() into a suspended worker (pc/lr/sp/fp
 * re-signed under THIS process's key first, resign_regs_for_this_process()),
 * then a SIGUSR1 queued on that still-suspended thread fires the instant it
 * resumes, before real dispatch -- its handler (restore_state()) does only
 * what thread_set_state can't: set TPIDR_EL0, and re-sign the stack's
 * frame-record return addresses (walk_and_resign_stack()).
 *
 * Multithreaded (2026-09-18): one worker per hdr.thread_count entry, mirroring
 * cr_capture.c's own per-thread loop in do_capture() -- see that file for the
 * capture-side counterpart of each step below. restore_state() runs on every
 * worker, not just one, so it needs to know which thread_desc_t is its own:
 * restore_one_thread() smuggles the g_threads[] index through x1 (seeded via
 * thread_set_state() alongside the rest of GPR, read back out of the signal
 * ctx) since x1 isn't part of any ptrauth-signed state and its real captured
 * value is trivial to restore before sigreturn -- see restore_state(). A
 * barrier_woa_t (tests/barrier_woa.h, same one cr_capture.c uses) syncs the
 * coordinating thread (do_restore()'s own caller) with every worker once each
 * has finished restore_state() and is about to sigreturn into its real,
 * restored PC.
 *
 * BUILD: -arch arm64e is mandatory -- see cr_common.h's ptrauth_calls guard.
 * Every captured pc/lr/sp/fp is a real PAC-signed value that must be
 * re-signed on restore, not a plain address.
 *
 * ORDERING:
 *   -> remap all regions                  (munge global -> hdr.munge)
 *   -> for each thread:
 *        sign its pthread struct with hdr.munge
 *        __bsdthread_create(SUSPENDED)
 *        resolve worker port, thread_set_state(GPR+NEON), x1 = index
 *        pthread_kill(SIGUSR1) while suspended
 *        thread_resume()
 *   -> barrier_wait() -- coordinator's own arrival, after every worker's
 *
 * PAC signing domains: register pc/lr use key IA (discriminator "pc"/"lr");
 * sp/fp use key DA ("sp"/"fp"); frame-record LRs on the restored stack use
 * key IB (modifier = frame entry sp), re-signed separately by
 * walk_and_resign_stack().
 *
 * By design, not a limitation: every restored thread (including whichever
 * was "main" at capture time) runs as a __bsdthread_create()'d worker;
 * do_restore()'s own caller is never one of them and just pauses forever
 * once the barrier releases. So when the restored "main" identity's own
 * call stack naturally unwinds into its C-runtime startup glue and that
 * calls exit() -- confirmed 2026-09-18, see NOTES.md -- the whole restore
 * process goes down right then, same as the original process would have.
 * That IS the goal: restore fidelity means the process behaves as if it
 * were the original one, including exiting when the original would have.
 *
 * KNOWN LIMITS: the guard-page/address collision is only mitigated by
 * reserving the driver's __DATA vmsize and running ASLR-off
 * (extend_segment_vmsize.py + spawn_noaslr, see src/Makefile's cr-restore),
 * not solved. Run directly without those two, this fails.
 *
 * The on-disk format (checkpoint_header_t + thread_desc_t[] + region_desc_t[]
 * + bytes) is raw structs with native padding -- not portable across builds
 * or machines.
 */
#include "cr_common.h"

#include <pthread.h>
#include <ptrauth.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <mach/mach_vm.h>
#include <mach/mach.h>
#include <sys/mman.h>
#include <sysexits.h>

/* tests/ convention: referenced relatively, same as cr_capture.c -- see
 * this project's CLAUDE.md on that split. */
#include "../tests/barrier_woa.h"

/* Each worker is created SUSPENDED and has its seeded GPR state -- sp
 * included -- fully applied via thread_set_state() before it ever resumes,
 * so this is never actually run on; defensive headroom only, in case some
 * kernel-side startup work touches it first. Matches cr_capture.c's own
 * TRAMP_STACK_SIZE for its per-thread hijack stacks. */
#define WORKER_STACK_SIZE (16 * 1024)

#define PTHREAD_START_CUSTOM    0x01000000u
#define PTHREAD_START_SUSPENDED 0x20000000u

extern void *__bsdthread_create(void *func, void *func_arg, void *stack,
                                 void *pthread, uint32_t flags);

static region_desc_t   g_regions[MAX_REGIONS];
static uint8_t*        g_restore_buf;
static uint64_t        g_region_off[MAX_REGIONS];
static thread_desc_t*  g_threads;
static barrier_woa_t   g_thread_barrier; /* must be a global -- restore_state()
                                          runs as each worker's own signal
                                          handler, no access to do_restore()'s
                                          own locals */

/* Strip a captured code/data pointer, then re-sign under this process's
 * key. Two functions, not one with a key parameter: the ptrauth intrinsics
 * need a compile-time-constant key. */
static uint64_t strip_and_resign_code(uint64_t raw, uint64_t discriminator) {
    void *stripped = ptrauth_strip((void *)(uintptr_t)raw, ptrauth_key_process_independent_code);
    void *resigned = ptrauth_sign_unauthenticated(stripped, ptrauth_key_process_independent_code, discriminator);
    return (uint64_t)(uintptr_t)resigned;
}

static uint64_t strip_and_resign_data(uint64_t raw, uint64_t discriminator) {
    void *stripped = ptrauth_strip((void *)(uintptr_t)raw, ptrauth_key_process_independent_data);
    void *resigned = ptrauth_sign_unauthenticated(stripped, ptrauth_key_process_independent_data, discriminator);
    return (uint64_t)(uintptr_t)resigned;
}

/* Re-sign a captured arm_thread_state64_t's pc/lr/sp/fp under this
 * process's key, in place. lr is left untouched when IB_SIGNED_LR is set
 * (a real frame-record lr): xnu can't re-derive the original pacibsp sp
 * modifier, so passthrough is the only correct move there. */
static void resign_regs_for_this_process(arm_thread_state64_t *s) {
    uint64_t raw_pc = (uint64_t)(uintptr_t)s->__opaque_pc;
    uint64_t raw_lr = (uint64_t)(uintptr_t)s->__opaque_lr;
    uint64_t raw_sp = (uint64_t)(uintptr_t)s->__opaque_sp;
    uint64_t raw_fp = (uint64_t)(uintptr_t)s->__opaque_fp;

    // TODO: look into __DARWIN_ARM_THREAD_STATE64_FLAGS_NO_PTRAUTH flag later
    bool ib_signed_lr = !!(s->__opaque_flags & __DARWIN_ARM_THREAD_STATE64_FLAGS_IB_SIGNED_LR);

    uint64_t new_pc = strip_and_resign_code(raw_pc, ptrauth_string_discriminator("pc"));
    uint64_t new_lr = ib_signed_lr ? raw_lr : strip_and_resign_code(raw_lr, ptrauth_string_discriminator("lr"));
    uint64_t new_sp = strip_and_resign_data(raw_sp, ptrauth_string_discriminator("sp"));
    uint64_t new_fp = strip_and_resign_data(raw_fp, ptrauth_string_discriminator("fp"));

    s->__opaque_pc = (void *)(uintptr_t)new_pc;
    s->__opaque_lr = (void *)(uintptr_t)new_lr;
    s->__opaque_sp = (void *)(uintptr_t)new_sp;
    s->__opaque_fp = (void *)(uintptr_t)new_fp;
}

static bool is_cache_region(uint64_t addr) {
    return in_shared_cache_range((mach_vm_address_t)addr) || in_shared_cache_submap((mach_vm_address_t)addr);
}

/* Tells if [addr, addr+len) already covered by one existing mapping */
static bool query_existing_mapping(uint64_t addr, uint64_t len, int* out_prot) {
    mach_vm_address_t a = addr;
    mach_vm_size_t size = 0;
    natural_t depth = 32;
    vm_region_submap_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
    kern_return_t kr = mach_vm_region_recurse(mach_task_self(), &a, &size, &depth,
                                               (vm_region_recurse_info_t)&info, &count);
    if (kr != KERN_SUCCESS || a > addr || a + size < addr + len) return false;

    *out_prot = (int)info.protection;
    return true;
}

/* Write one region's bytes at its original address, then its final protection. */
static int remap_one_region(uint32_t i, bool fatal) {
    uint64_t addr = g_regions[i].addr;
    uint64_t len  = g_regions[i].len;
    int prot      = (int)g_regions[i].protection;

    int cur_prot;
    if (query_existing_mapping(addr, len, &cur_prot)) {
        if ((cur_prot & (PROT_READ | PROT_WRITE)) != (PROT_READ | PROT_WRITE) &&
            mprotect((void*)(uintptr_t)addr, len, PROT_READ | PROT_WRITE) != 0) {
            fprintf(stderr, "  mprotect(RW) failed for region[%u] [0x%llx,0x%llx): %s%s\n",
                    i, (uint64_t)addr, (uint64_t)(addr + len), strerror(errno),
                    fatal ? "" : " -- skipped");
            return fatal ? 1 : 0;
        }
        memcpy((void*)(uintptr_t)addr, g_restore_buf + g_region_off[i], len);
    } else {
        void* got = mmap((void*)(uintptr_t)addr, len, PROT_READ | PROT_WRITE,
                         MAP_FIXED | MAP_ANON | MAP_PRIVATE, -1, 0);
        if (got == MAP_FAILED || (uint64_t)(uintptr_t)got != addr) {
            fprintf(stderr, "  region[%u] [0x%llx,0x%llx): %s%s\n", i,
                    (uint64_t)addr, (uint64_t)(addr + len),
                    got == MAP_FAILED ? strerror(errno) : "fixed address not honored",
                    fatal ? "" : " -- skipped");
            return fatal ? 1 : 0;
        }
        printf("  WARNING: region[%u] [0x%llx,0x%llx): writing %llu bytes into NEW mapping\n",
               i, (uint64_t)addr, (uint64_t)(addr + len), (uint64_t)len);
        memcpy(got, g_restore_buf + g_region_off[i], len);
    }

    if (prot != (PROT_READ | PROT_WRITE) && mprotect((void*)(uintptr_t)addr, len, prot) != 0) {
        fprintf(stderr, "  mprotect(%d) failed for region[%u] [0x%llx,0x%llx): %s\n",
                prot, i, (uint64_t)addr, (uint64_t)(addr + len), strerror(errno));
        if (fatal) return 1;
    }
    return 0;
}

static int remap_regions(uint32_t region_count) {
    for (uint32_t i = 0; i < region_count; i++) {
        bool cache = is_cache_region(g_regions[i].addr);
        if (remap_one_region(i, !cache) != 0) return 1;
    }
    return 0;
}

static void* dummy_entry_fn(void* arg) { (void)arg; for (;;) pause(); return NULL; }

/* Re-sign every frame-record return address on the restored stack: the
 * {saved fp, saved lr} records still hold LRs signed by the capturing
 * process. xpaci strip + pacib with modifier fp+0x10, walking outward,
 * stopping at _dyld_start's sentinel frame (fp==0 && lr strips to 0), with
 * a monotonic-fp guard. Raw loads/stores + xpaci/pacib only:
 * async-signal-safe. Returns the number of records rewritten. */
static int walk_and_resign_stack(uint64_t fp) {
    int n = 0;
    if (fp == 0) return 0;
    for (;; n++) {
        uint64_t next_fp = *(uint64_t *)(uintptr_t)fp;
        uint64_t lr      = *(uint64_t *)(uintptr_t)(fp + 0x8);

        __asm__ volatile("xpaci %0" : "+r"(lr));
        if (lr == 0 && next_fp == 0) break;          /* _dyld_start sentinel frame */

        uint64_t modifier = fp + 0x10;
        __asm__ volatile("pacib %0, %1" : "+r"(lr) : "r"(modifier));
        *(uint64_t *)(uintptr_t)(fp + 0x8) = lr;

        if (next_fp <= fp) break;                    /* chain not strictly outward -- bail */
        fp = next_fp;
    }
    return n;
}

/* Runs before a worker executes any real instruction, once per worker (this
 * is every restored thread's signal handler, not just one). Does what
 * thread_set_state() can't: set TPIDR_EL0, re-sign the restored stack's
 * frame-record LRs. x1 arrives holding restore_one_thread()'s smuggled
 * g_threads[] index (seeded via thread_set_state() alongside the rest of
 * GPR) rather than its real captured value -- x1 isn't part of any
 * ptrauth-signed state, so reading the index back out of it here and then
 * overwriting ctx's copy with the real captured value before returning is
 * safe; sigreturn applies whatever this handler leaves in ctx. Then waits
 * at the barrier for every other worker (and do_restore()'s own caller) so
 * nothing resumes real execution before ALL workers have finished this. */
static void restore_state(int sig, siginfo_t* info, void* ctx) {
    (void)sig; (void)info;
    arm_thread_state64_t* ss = &((ucontext_t*)ctx)->uc_mcontext->__ss;
    uint32_t ind = (uint32_t)ss->__x[1];
    thread_desc_t* td = &g_threads[ind];

    __asm__ volatile ("msr tpidr_el0, %0" :: "r" (td->regs.tpidr));

    /* Captured fp arrives DA-signed (process-independent key), so this
     * strip is valid regardless of which process signed it. */
    uint64_t fp = (uint64_t)(uintptr_t)ptrauth_strip(
        (void *)(uintptr_t)td->regs.gregs.__opaque_fp, ptrauth_key_process_independent_data);
    int n = walk_and_resign_stack(fp);

    ss->__x[1] = td->regs.gregs.__x[1]; /* give back x1's real captured value */

    printf("restore_state[%u]: tpidr=0x%llx set; resigned %d frame-record LR(s) from fp=0x%llx\n",
           ind, (uint64_t)td->regs.tpidr, n, fp);

    barrier_wait(&g_thread_barrier);
}

/* Same XOR algebra cr_capture.c's capture_state() runs in reverse (recover
 * hdr.munge from a live signed struct); here, given that already-recovered
 * process-wide munge, sign a not-yet-registered pthread struct at its
 * ORIGINAL (now-remapped) address so __bsdthread_create()'s internal
 * signature check accepts it. */
static void sign_worker_struct(uint64_t pthread_addr, uint64_t munge) {
    uintptr_t sig = sign_for_addr((uintptr_t)pthread_addr) ^ (uintptr_t)munge;
    *(uintptr_t *)(uintptr_t)pthread_addr = sig;
    printf("  signed worker struct at 0x%llx (sig=0x%lx)\n", (uint64_t)pthread_addr, sig);
}

/* task_threads() is the source of truth here -- pthread_mach_thread_np() on
 * a freshly self-signed-but-not-yet-registered struct has shown both
 * correct and bogus results in earlier testing on this project (suspected
 * cause: garbage read as a pthread struct before the decoupled-remapping
 * fix), so it's only ever logged for agreement, never trusted alone.
 * seen[0..*n_seen) is every port already resolved (main + every worker
 * created so far); task_threads() enumerates the whole task, so elimination
 * against that set is how exactly one new port is picked out. Grows
 * seen[] by one entry on success. */
static mach_port_t resolve_new_thread_port(pthread_t worker_pt, mach_port_t* seen, uint32_t* n_seen) {
    thread_act_array_t acts;
    mach_msg_type_number_t n_acts;
    if (task_threads(mach_task_self(), &acts, &n_acts) != KERN_SUCCESS) {
        fprintf(stderr, "  task_threads failed while resolving a new worker's port\n");
        return MACH_PORT_NULL;
    }

    mach_port_t found = MACH_PORT_NULL;
    for (mach_msg_type_number_t i = 0; i < n_acts && found == MACH_PORT_NULL; i++) {
        bool already_seen = false;
        for (uint32_t j = 0; j < *n_seen; j++) {
            if (seen[j] == acts[i]) { already_seen = true; break; }
        }
        if (!already_seen) found = acts[i];
    }
    vm_deallocate(mach_task_self(), (vm_address_t)acts, sizeof(thread_act_t) * n_acts);

    if (found == MACH_PORT_NULL) {
        fprintf(stderr, "  couldn't find the new worker thread's port via task_threads()\n");
        return MACH_PORT_NULL;
    }
    seen[*n_seen] = found;
    (*n_seen)++;

    mach_port_t np_port = pthread_mach_thread_np(worker_pt);
    printf("  worker port (task_threads)=0x%x pthread_mach_thread_np()=0x%x -- %s\n",
           found, np_port, np_port == found ? "agrees" : "DISAGREES");

    return found;
}

/* One captured thread, start to finish -- mirrors cr_capture.c's own
 * per-thread loop in do_capture(); see that file for the capture-side
 * counterpart of each step. stacks[i] is filled in here (caller owns
 * freeing it). */
static int restore_one_thread(uint32_t i, uint64_t munge, mach_port_t* seen_ports, uint32_t* n_seen, void** stacks) {
    thread_desc_t* td = &g_threads[i];
    pthread_t worker_pt = (pthread_t)(uintptr_t)td->pthread_addr;

    /* Raw ptrauth_strip, NOT arm_thread_state64_get_pc_fptr()/get_sp() --
     * those authenticate, and this pc/sp is still signed under the
     * capturing process's (now-dead) key at this point, pre-resign; an
     * authenticating read here faults instead of just returning a value.
     * resign_regs_for_this_process() below reads the same fields the same
     * way for the same reason. */
    printf("thread[%u]: pthread_addr=0x%llx pc=0x%llx sp=0x%llx\n", i,
           (uint64_t)td->pthread_addr,
           (uint64_t)(uintptr_t)ptrauth_strip(
               (void *)(uintptr_t)td->regs.gregs.__opaque_pc, ptrauth_key_process_independent_code),
           (uint64_t)(uintptr_t)ptrauth_strip(
               (void *)(uintptr_t)td->regs.gregs.__opaque_sp, ptrauth_key_process_independent_data));

    sign_worker_struct(td->pthread_addr, munge);

    stacks[i] = mmap(NULL, WORKER_STACK_SIZE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (stacks[i] == MAP_FAILED) {
        fprintf(stderr, "  mmap failed for thread[%u]'s stack: %s\n", i, strerror(errno));
        return 1;
    }
    void* stack_top = (char*)stacks[i] + WORKER_STACK_SIZE;

    errno = 0;
    void* ret = __bsdthread_create(dummy_entry_fn, NULL, stack_top, (void*)(uintptr_t)td->pthread_addr,
                                    PTHREAD_START_CUSTOM | PTHREAD_START_SUSPENDED);
    if (ret == (void*)-1) {
        fprintf(stderr, "  __bsdthread_create failed for thread[%u]: errno=%d (%s)\n", i, errno, strerror(errno));
        return 1;
    }

    mach_port_t worker_port = resolve_new_thread_port(worker_pt, seen_ports, n_seen);
    if (worker_port == MACH_PORT_NULL) return 1;

    /* Seed GPR+NEON into the still-suspended worker, pc/lr/sp/fp re-signed
     * under this process's key first (see file header). x1 is smuggled to
     * this index -- restore_state() reads it and restores the real captured
     * x1 before sigreturn. */
    arm_thread_state64_t seeded_gregs = td->regs.gregs;
    resign_regs_for_this_process(&seeded_gregs);
    seeded_gregs.__x[1] = i;

    if (thread_set_state(worker_port, ARM_THREAD_STATE64,
                          (thread_state_t)&seeded_gregs, ARM_THREAD_STATE64_COUNT) != KERN_SUCCESS) {
        fprintf(stderr, "  thread_set_state(GPR) failed for thread[%u]\n", i);
        return 1;
    }
    if (thread_set_state(worker_port, ARM_NEON_STATE64,
                          (thread_state_t)&td->regs.neon, ARM_NEON_STATE64_COUNT) != KERN_SUCCESS) {
        fprintf(stderr, "  thread_set_state(NEON) failed for thread[%u] (non-fatal)\n", i);
    }

    /* Queued while still suspended -- delivery happens the instant
     * thread_resume() runs, before real dispatch (see file header). */
    int rc = pthread_kill(worker_pt, SIGUSR1);
    printf("  thread[%u]: pthread_kill(SIGUSR1) while suspended => rc=%d\n", i, rc);

    if (thread_resume(worker_port) != KERN_SUCCESS) {
        fprintf(stderr, "  thread_resume failed for thread[%u]\n", i);
        return 1;
    }
    printf("  thread[%u] resumed (port=0x%x)\n", i, worker_port);
    return 0;
}

int do_restore(const char* path) {
    FILE* f = fopen(path, "rb");
    if (!f) { perror("fopen"); return 1; }
    printf("restoring from %s\n", path);

    checkpoint_header_t hdr;
    if (fread(&hdr, sizeof(hdr), 1, f) != 1) { fprintf(stderr, "short read on header\n"); fclose(f); return 1; }
    if (hdr.region_count > MAX_REGIONS) { fprintf(stderr, "region_count too large\n"); fclose(f); return 1; }

    if (alloc_thread_descs(hdr.thread_count, &g_threads) != 0) { fclose(f); return 1; }
    if (fread(g_threads, sizeof(thread_desc_t), hdr.thread_count, f) != hdr.thread_count) {
        fprintf(stderr, "short read on thread descriptors\n");
        free_thread_descs(&g_threads, hdr.thread_count);
        fclose(f);
        return 1;
    }

    if (fread(g_regions, sizeof(region_desc_t), hdr.region_count, f) != hdr.region_count) {
        fprintf(stderr, "short read on region descriptors\n");
        free_thread_descs(&g_threads, hdr.thread_count);
        fclose(f);
        return 1;
    }

    uint64_t region_total = 0;
    for (uint32_t i = 0; i < hdr.region_count; i++) {
        g_region_off[i] = region_total;
        region_total += g_regions[i].len;
    }
    if (region_total != hdr.capture_used) {
        fprintf(stderr, "corrupt checkpoint file\n");
        free_thread_descs(&g_threads, hdr.thread_count);
        fclose(f);
        return 1;
    }

    /* One flat buffer -- no self-aliasing risk on the restore side, so no
     * need for per-region buffers here. */
    g_restore_buf = mmap(NULL, hdr.capture_used, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (g_restore_buf == MAP_FAILED) {
        perror("mmap restore buffer");
        free_thread_descs(&g_threads, hdr.thread_count);
        fclose(f);
        return 1;
    }
    if (fread(g_restore_buf, 1, hdr.capture_used, f) != hdr.capture_used) {
        fprintf(stderr, "short read on capture buffer\n");
        free_thread_descs(&g_threads, hdr.thread_count);
        fclose(f);
        return 1;
    }
    fclose(f);

    printf("read %u threads, %u regions, %.2f MB, munge=0x%llx sentinel=0x%llx daemon_pid=%d\n",
           hdr.thread_count, hdr.region_count, hdr.capture_used / (1024.0 * 1024.0),
           (uint64_t)hdr.munge, (uint64_t)hdr.sentinel, hdr.daemon_pid);

    /* Diagnostic only. kill(pid, 0) is a no-op existence/permission probe.
     * Never fatal -- refusing to restore over a dead anchor would be worse
     * than restoring and maybe crashing. */
    if (hdr.daemon_pid <= 0) {
        printf("no %s was recorded at capture time -- this checkpoint's PAC keys "
               "may not match this process's; restore may crash\n", CRAC_DAEMON_NAME);
    } else if (kill((pid_t)hdr.daemon_pid, 0) == 0) {
        printf("%s (pid=%d) recorded at capture time is still alive -- PAC keys "
               "should match\n", CRAC_DAEMON_NAME, hdr.daemon_pid);
    } else {
        printf("%s (pid=%d) recorded at capture time is NOT running anymore (%s) -- "
               "this checkpoint's PAC keys may have been regenerated since capture; "
               "restore may crash\n",
               CRAC_DAEMON_NAME, hdr.daemon_pid, strerror(errno));
    }

    if (remap_regions(hdr.region_count) != 0) {
        fprintf(stderr, "failed to remap regions\n");
        free_thread_descs(&g_threads, hdr.thread_count);
        return 1;
    }
    printf("regions remapped at their original addresses\n");

    if (hdr.sentinel) {
        *(volatile int *)(uintptr_t)hdr.sentinel = 1;
        printf("sentinel at 0x%llx set to 1\n", (uint64_t)hdr.sentinel);
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_flags = SA_SIGINFO;
    sa.__sigaction_u.__sa_sigaction = restore_state;
    if (sigaction(SIGUSR1, &sa, NULL) == -1) {
        perror("sigaction");
        free_thread_descs(&g_threads, hdr.thread_count);
        return 1;
    }

    /* +1: do_restore()'s own caller also waits, once, after spawning every
     * worker below -- see file header's ORDERING. */
    barrier_create(&g_thread_barrier, hdr.thread_count + 1);

    /* mmap, not malloc, for both of these -- same reasoning as
     * cr_capture.c's per-region buffers: remap_regions() just overwrote
     * this process's heap with the capturing process's raw captured bytes
     * wherever a captured region landed on top of live malloc zone
     * metadata, including its PAC-protected free-list pointers. A small
     * malloc/calloc call here routes through exactly that corrupted
     * small-zone metadata and hits EXC_ARM_PAC_FAIL (confirmed empirically
     * 2026-09-18 -- crash inside libsystem_malloc.dylib's mfm_alloc); the
     * original single-thread restore's one post-remap malloc() never hit
     * this because its size (STACK_SIZE, 256KB) took the large-allocation
     * path, which mmaps directly and never touches zone metadata at all. */
    mach_port_t* seen_ports = mmap(NULL, (hdr.thread_count + 1) * sizeof(mach_port_t),
                                    PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (seen_ports == MAP_FAILED) {
        perror("mmap seen_ports");
        free_thread_descs(&g_threads, hdr.thread_count);
        return 1;
    }
    seen_ports[0] = mach_thread_self();
    uint32_t n_seen = 1;

    void** stacks = mmap(NULL, hdr.thread_count * sizeof(void*),
                          PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (stacks == MAP_FAILED) {
        perror("mmap stacks");
        munmap(seen_ports, (hdr.thread_count + 1) * sizeof(mach_port_t));
        free_thread_descs(&g_threads, hdr.thread_count);
        return 1;
    }

    int rc = 0;
    for (uint32_t i = 0; i < hdr.thread_count; i++) {
        if (restore_one_thread(i, hdr.munge, seen_ports, &n_seen, stacks) != 0) {
            rc = 1;
            break;
        }
    }
    munmap(seen_ports, (hdr.thread_count + 1) * sizeof(mach_port_t));

    if (rc != 0) {
        for (uint32_t i = 0; i < hdr.thread_count; i++) {
            if (stacks[i]) munmap(stacks[i], WORKER_STACK_SIZE);
        }
        munmap(stacks, hdr.thread_count * sizeof(void*));
        free_thread_descs(&g_threads, hdr.thread_count);
        return 1;
    }

    printf("all %u thread(s) spawned -- waiting at barrier\n", hdr.thread_count);
    barrier_wait(&g_thread_barrier); /* coordinator's own arrival */
    printf("every worker has run restore_state() -- releasing them into their restored PCs\n");

    for (uint32_t i = 0; i < hdr.thread_count; i++) {
        munmap(stacks[i], WORKER_STACK_SIZE);
    }
    munmap(stacks, hdr.thread_count * sizeof(void*));
    free_thread_descs(&g_threads, hdr.thread_count);

    /* Execution is on the workers now; without this, main returns and the
     * process tears down before they run. */
    for (;;) pause();

    // Unreachable
    return 0;
}
