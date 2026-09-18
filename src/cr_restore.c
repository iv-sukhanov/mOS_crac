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
 * BUILD: -arch arm64e is mandatory -- see cr_common.h's ptrauth_calls guard.
 * Every captured pc/lr/sp/fp is a real PAC-signed value that must be
 * re-signed on restore, not a plain address.
 *
 * ORDERING:
 *   -> remap all regions                  (munge global -> hdr.munge)
 *   -> sign the worker struct with hdr.munge
 *   -> __bsdthread_create(SUSPENDED)
 *   -> resolve worker port, thread_set_state(GPR+NEON)
 *   -> pthread_kill(SIGUSR1) while suspended
 *   -> thread_resume()
 *
 * PAC signing domains: register pc/lr use key IA (discriminator "pc"/"lr");
 * sp/fp use key DA ("sp"/"fp"); frame-record LRs on the restored stack use
 * key IB (modifier = frame entry sp), re-signed separately by
 * walk_and_resign_stack().
 *
 * KNOWN LIMITS: the resumed worker runs process teardown on a non-main
 * thread; the guard-page/address collision is only mitigated by reserving
 * the driver's __DATA vmsize and running ASLR-off (extend_segment_vmsize.py
 * + spawn_noaslr, see src/Makefile's cr-restore), not solved; one region
 * set, one thread. Run directly without those two, this fails.
 *
 * The on-disk format (checkpoint_header_t + region_desc_t[] + bytes) is raw
 * structs with native padding -- not portable across builds or machines.
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

#define STACK_SIZE (256 * 1024)

#define PTHREAD_START_CUSTOM    0x01000000u
#define PTHREAD_START_SUSPENDED 0x20000000u

extern void *__bsdthread_create(void *func, void *func_arg, void *stack,
                                 void *pthread, uint32_t flags);

static region_desc_t g_regions[MAX_REGIONS];
static uint8_t*      g_restore_buf;
static uint64_t      g_region_off[MAX_REGIONS];

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

/* Runs before the worker executes any real instruction. Does what
 * thread_set_state() can't: set TPIDR_EL0, re-sign the restored stack's
 * frame-record LRs. Then returns; sigreturn applies the seeded context. */
static void restore_state(int sig, siginfo_t* info, void* ctx) {
    (void)sig; (void)info; (void)ctx;
    __asm__ volatile ("msr tpidr_el0, %0" :: "r" (g_regs.tpidr));

    /* Captured fp arrives DA-signed (process-independent key), so this
     * strip is valid regardless of which process signed it. */
    uint64_t fp = (uint64_t)(uintptr_t)ptrauth_strip(
        (void *)(uintptr_t)g_regs.gregs.__opaque_fp, ptrauth_key_process_independent_data);
    int n = walk_and_resign_stack(fp);
    printf("restore_state: tpidr=0x%llx set; resigned %d frame-record LR(s) from fp=0x%llx\n",
           (uint64_t)g_regs.tpidr, n, fp);
}

int do_restore(const char* path) {
    FILE* f = fopen(path, "rb");
    if (!f) { perror("fopen"); return 1; }
    printf("restoring from %s\n", path);

    checkpoint_header_t hdr;
    if (fread(&hdr, sizeof(hdr), 1, f) != 1) { fprintf(stderr, "short read on header\n"); fclose(f); return 1; }
    if (hdr.region_count > MAX_REGIONS) { fprintf(stderr, "region_count too large\n"); fclose(f); return 1; }
    if (fread(g_regions, sizeof(region_desc_t), hdr.region_count, f) != hdr.region_count) {
        fprintf(stderr, "short read on region descriptors\n"); fclose(f); return 1;
    }

    uint64_t region_total = 0;
    for (uint32_t i = 0; i < hdr.region_count; i++) {
        g_region_off[i] = region_total;
        region_total += g_regions[i].len;
    }
    if (region_total != hdr.capture_used) { fprintf(stderr, "corrupt checkpoint file\n"); fclose(f); return 1; }

    /* One flat buffer -- no self-aliasing risk on the restore side, so no
     * need for per-region buffers here. */
    g_restore_buf = mmap(NULL, hdr.capture_used, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (g_restore_buf == MAP_FAILED) { perror("mmap restore buffer"); fclose(f); return 1; }
    if (fread(g_restore_buf, 1, hdr.capture_used, f) != hdr.capture_used) {
        fprintf(stderr, "short read on capture buffer\n"); fclose(f); return 1;
    }
    fclose(f);
    // g_regs = hdr.regs;

    printf("read %u regions, %.2f MB, pthread_addr=0x%llx munge=0x%llx sentinel=0x%llx daemon_pid=%d\n",
           hdr.region_count, hdr.capture_used / (1024.0 * 1024.0),
           (uint64_t)hdr.pthread_addr, (uint64_t)hdr.munge,
           (uint64_t)hdr.sentinel, hdr.daemon_pid);

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

    if (remap_regions(hdr.region_count) != 0) { fprintf(stderr, "failed to remap regions\n"); return 1; }
    printf("regions remapped at their original addresses\n");

    uintptr_t worker_addr = (uintptr_t)hdr.pthread_addr;
    uintptr_t sig = sign_for_addr(worker_addr) ^ (uintptr_t)hdr.munge;
    *(uintptr_t *)worker_addr = sig;
    printf("signed worker struct: munge=0x%llx sig=0x%lx\n", (uint64_t)hdr.munge, sig);

    void* stack = malloc(STACK_SIZE);
    if (!stack) { perror("malloc stack"); return 1; }
    void* stack_top = (char*)stack + STACK_SIZE;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_flags = SA_SIGINFO;
    sa.__sigaction_u.__sa_sigaction = restore_state;
    if (sigaction(SIGUSR1, &sa, NULL) == -1) { perror("sigaction"); return 1; }

    errno = 0;
    void* ret = __bsdthread_create(dummy_entry_fn, NULL, stack_top, (void*)worker_addr,
                                    PTHREAD_START_CUSTOM | PTHREAD_START_SUSPENDED);
    if (ret == (void*)-1) {
        fprintf(stderr, "__bsdthread_create failed: errno=%d (%s)\n", errno, strerror(errno));
        return 1;
    }
    printf("__bsdthread_create returned %p (suspended)\n", ret);

    pthread_t worker_pt = (pthread_t)(uintptr_t)hdr.pthread_addr;

    /* Resolve the worker's Mach port via task_threads() -- exactly two
     * threads here (main + suspended worker); pthread_mach_thread_np() on
     * the freshly self-signed struct returns a bogus fixed port instead. */
    mach_port_t main_port = mach_thread_self();
    thread_act_array_t acts;
    mach_msg_type_number_t n_acts;
    if (task_threads(mach_task_self(), &acts, &n_acts) != KERN_SUCCESS) {
        fprintf(stderr, "task_threads failed\n"); return 1;
    }
    mach_port_t worker_port = MACH_PORT_NULL;
    for (mach_msg_type_number_t i = 0; i < n_acts; i++) {
        if (acts[i] != main_port) { worker_port = acts[i]; break; }
    }
    vm_deallocate(mach_task_self(), (vm_address_t)acts, sizeof(thread_act_t) * n_acts);
    mach_port_deallocate(mach_task_self(), main_port);
    if (worker_port == MACH_PORT_NULL) {
        fprintf(stderr, "couldn't find the worker thread's port via task_threads()\n");
        return 1;
    }
    printf("worker port = 0x%x\n", worker_port);

    if (hdr.sentinel) {
        *(volatile int *)(uintptr_t)hdr.sentinel = 1;
        printf("sentinel at 0x%llx set to 1\n", (uint64_t)hdr.sentinel);
    }

    /* Seed GPR+NEON into the still-suspended worker, pc/lr/sp/fp re-signed
     * under this process's key first (see file header). */
    printf("resign_regs: __opaque_flags=0x%x IB_SIGNED_LR=%d\n",
           g_regs.gregs.__opaque_flags,
           !!(g_regs.gregs.__opaque_flags & __DARWIN_ARM_THREAD_STATE64_FLAGS_IB_SIGNED_LR));
    arm_thread_state64_t seeded_gregs = g_regs.gregs;
    resign_regs_for_this_process(&seeded_gregs);

    kern_return_t kr_gpr = thread_set_state(worker_port, ARM_THREAD_STATE64,
                                             (thread_state_t)&seeded_gregs, ARM_THREAD_STATE64_COUNT);
    if (kr_gpr != KERN_SUCCESS) {
        fprintf(stderr, "thread_set_state(GPR) failed: %d\n", kr_gpr);
        return 1;
    }
    kern_return_t kr_neon = thread_set_state(worker_port, ARM_NEON_STATE64,
                                              (thread_state_t)&g_regs.neon, ARM_NEON_STATE64_COUNT);
    if (kr_neon != KERN_SUCCESS) {
        fprintf(stderr, "thread_set_state(NEON) failed: %d (non-fatal)\n", kr_neon);
    }
    printf("thread_set_state(GPR+NEON) applied to suspended worker\n");

    /* Queue the signal on the still-suspended thread -- delivery happens
     * the instant thread_resume() runs, before real dispatch. */
    int rc = pthread_kill(worker_pt, SIGUSR1);
    printf("pthread_kill(worker, SIGUSR1) while suspended => rc=%d\n", rc);

    kern_return_t kr = thread_resume(worker_port);
    if (kr != KERN_SUCCESS) {
        printf("thread_resume failed\n");
        return 1;
    }
    printf("thread_resume succeeded -- worker should now run the queued signal handler\n");

    /* Execution is on the worker now; without this, main returns and the
     * process tears down before the worker runs. */
    for (;;) pause();

    // Unreachable
    return 0;
}
