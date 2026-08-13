#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <mach/mach.h>
#include <mach/thread_state.h>
#include <errno.h>
#include <signal.h>
#include <stdatomic.h>
#include <unistd.h>

#define ITERN 9
#define ITER_CAPT 5

typedef struct regs {
    uint64_t pc, sp, cpsr, fp, lr, pad;
    uint64_t x[29];
    arm_neon_state64_t neon;
    uint64_t tpidr;
} regs_t;

static regs_t regs;
static _Atomic uint32_t counter;
static atomic_bool captured = false;
static atomic_bool done = false;

static double elapsed_ms(struct timespec* start) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (now.tv_sec - start->tv_sec) * 1000.0 + (now.tv_nsec - start->tv_nsec) / 1e6;
}

static int wait_for_flag(atomic_bool* flag, int budget_ms) {
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    while (!atomic_load(flag)) {
        if (elapsed_ms(&start) > budget_ms) return -1;
        usleep(500);
    }
    return 0;
}

static void* worker_fn(void* arg) {
    printf("Worker thread started.\n");

    for (int i = 0; i < ITERN; i++) {
        uint32_t current = atomic_fetch_add(&counter, 1);
        uint64_t tpidr;
        __asm__ volatile ("mrs %0, tpidr_el0" : "=r" (tpidr));
        // write(STDOUT_FILENO, "#\n", 2);
        printf("Counter: %u from thread with port=%x errno=%d tpidr=%llx\n", current,
            mach_thread_self(), errno, tpidr);

        if (current == ITER_CAPT) {
            printf("Counter reached %d (port=%x), sending the signal.\n", ITER_CAPT, mach_thread_self());

            if (raise(SIGUSR1) == -1) {
                perror("raise");
                return NULL;
            }
            // Only a freshly-seeded thread (mode A/B/C) ever reaches this line.
            // The original thread that called raise() never returns from it —
            // action_usr1_fn suspends it for good instead of returning here,
            // so it can't race the seeded thread over this same stack.
        }
    }

    atomic_store(&done, true);
    return NULL;
}

static void* worker_state_set_fn(void* arg) {
    raise(SIGUSR2);
    return NULL;
}

void action_usr1_fn(int sig, siginfo_t* info, void* ctx) {
    arm_thread_state64_t state = ((ucontext_t*)ctx)->uc_mcontext->__ss;
    regs.pc = (uint64_t)arm_thread_state64_get_pc(state);
    regs.sp = (uint64_t)arm_thread_state64_get_sp(state);
    regs.fp = (uint64_t)arm_thread_state64_get_fp(state);
    regs.lr = (uint64_t)arm_thread_state64_get_lr(state);
    regs.cpsr = (uint64_t)(state.__cpsr);
    regs.pad = (uint64_t)(state.__pad);
    memcpy(regs.x, state.__x, sizeof(regs.x));
    regs.neon = ((ucontext_t*)ctx)->uc_mcontext->__ns;
    __asm__ volatile ("mrs %0, tpidr_el0" : "=r" (regs.tpidr));

    atomic_store(&captured, true);
    char buf[] = "got signal, captured regs (incl. NEON+TLS); parking original thread for good\n";
    write(STDOUT_FILENO, buf, sizeof(buf));

    // Suspend the interrupted (original) thread for real, instead of letting
    // it loop back into worker_fn where it'd race the newly-seeded thread
    // over the same stack. thread_suspend on yourself isn't guaranteed to
    // take effect synchronously (the kernel only checks the suspend count at
    // the next kernel entry/preemption, not mid-instruction) — the pause()
    // loop below is the actual guarantee; thread_suspend is belt-and-
    // suspenders so a stray future wakeup still can't schedule this thread
    // without an explicit thread_resume.
    thread_suspend(mach_thread_self());
    for (;;) pause();
}

void action_usr2_fn(int sig, siginfo_t* info, void* ctx) {
    arm_thread_state64_t *state = &((ucontext_t*)ctx)->uc_mcontext->__ss;
    state->__pc = regs.pc;
    state->__sp = regs.sp;
    state->__fp = regs.fp;
    state->__lr = regs.lr;
    state->__cpsr = regs.cpsr;
    state->__pad = regs.pad;
    memcpy(state->__x, regs.x, sizeof(regs.x));
    ((ucontext_t*)ctx)->uc_mcontext->__ns = regs.neon;
    // Safe to set directly here, unlike modes A/B: this handler runs ON the
    // pthread that's about to resume with this state, so TPIDR_EL0 (writable
    // from EL0/userspace, unlike TPIDRRO_EL0) just gets set on ourselves
    // before sigreturn applies the rest.
    __asm__ volatile ("msr tpidr_el0, %0" :: "r" (regs.tpidr));

    char buf[] = "got signal and set the regs (incl. NEON+TLS)\n";
    write(STDOUT_FILENO, buf, sizeof(buf));
}

int main(int argc, char** argv) {

    int mode = 0;
    if (argc > 1 && strcmp(argv[1], "b") == 0) {
        mode = 1;
    } else if (argc > 1 && strcmp(argv[1], "c") == 0) {
        mode = 2;
    }

    setvbuf(stdout, NULL, _IONBF, 0); // unbuffered — a crash mid-run must not eat prior output
    printf("Running in mode %s\n.\n", mode == 0 ? "a" : mode == 1 ? "b" : "c");

    pthread_t worker_thread;
    atomic_init(&counter, 0);
    atomic_init(&captured, false);
    atomic_init(&done, false);
    struct sigaction sa_usr1, sa_usr2;
    memset(&sa_usr1, 0, sizeof(sa_usr1));
    sa_usr1.sa_flags = SA_SIGINFO;
    sa_usr1.__sigaction_u.__sa_sigaction = action_usr1_fn;

    memset(&sa_usr2, 0, sizeof(sa_usr2));
    sa_usr2.sa_flags = SA_SIGINFO;
    sa_usr2.__sigaction_u.__sa_sigaction = action_usr2_fn;

    if (sigaction(SIGUSR1, &sa_usr1, NULL) == -1) {
        perror("sigaction1");
        return -1;
    }

    if (sigaction(SIGUSR2, &sa_usr2, NULL) == -1) {
        perror("sigaction2");
        return -1;
    }

    if (pthread_create(&worker_thread, NULL, worker_fn, NULL) != 0) {
        perror("pthread_create");
        return -1;
    }
    // Original thread parks itself for good the moment it hits SIGUSR1 (see
    // action_usr1_fn) — nothing will ever join it, so detach instead.
    pthread_detach(worker_thread);

    wait_for_flag(&captured, 2000);

    kern_return_t kr;
    arm_thread_state64_t state;
    state.__cpsr = regs.cpsr;
    state.__fp = regs.fp;
    state.__lr = regs.lr;
    state.__sp = regs.sp;
    state.__pc = regs.pc;
    state.__pad = regs.pad;
    memcpy(state.__x, regs.x, sizeof(regs.x));

    if (mode == 0) {
        thread_act_t child = MACH_PORT_NULL;
        kr = thread_create_running(
            mach_task_self(),
            ARM_THREAD_STATE64,
            (thread_state_t)&state,
            ARM_THREAD_STATE64_COUNT,
            &child
        );
        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "thread_create_running failed: %d\n", kr);
            return -1;
        }
        // ponytail: the thread is already running by the time this second
        // call lands, so there's a real (if short) window where it executes
        // with default/zero NEON state — thread_create_running only takes
        // one flavor at creation. Upgrade path: point the seeded PC at a
        // trampoline stub that self-seeds NEON+TLS as its first instructions
        // (the shape mode C gets for free via the signal handler).
        kr = thread_set_state(child, ARM_NEON_STATE64, (thread_state_t)&regs.neon, ARM_NEON_STATE64_COUNT);
        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "thread_set_state(NEON) failed: %d\n", kr);
        }
        // Same TLS gap as mode B below — no public Mach flavor to seed
        // TPIDR_EL0 remotely; left unset, tpidr=... in the loop's own print
        // makes the gap directly observable instead of silent.
        mach_port_deallocate(mach_task_self(), child);
    } else if (mode == 1) {
        mach_port_t new_thread;
        kr = thread_create(mach_task_self(), &new_thread);
        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "thread_create failed: %d\n", kr);
            return -1;
        }

        kr = thread_set_state(
            new_thread,
            ARM_THREAD_STATE64,
            (thread_state_t)&state,
            ARM_THREAD_STATE64_COUNT
        );
        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "thread_set_state failed: %d\n", kr);
            return -1;
        }

        // Thread is still suspended here, so unlike mode A this seeds NEON
        // race-free — nothing can run with the wrong state before resume.
        kr = thread_set_state(new_thread, ARM_NEON_STATE64, (thread_state_t)&regs.neon, ARM_NEON_STATE64_COUNT);
        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "thread_set_state(NEON) failed: %d\n", kr);
        }

        kr = thread_resume(new_thread);
        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "thread_resume failed: %d\n", kr);
            return -1;
        }
        mach_port_deallocate(mach_task_self(), new_thread);
    } else {
        pthread_t worker_state_set_thread;
        if (pthread_create(&worker_state_set_thread, NULL, worker_state_set_fn, NULL) != 0) {
            perror("pthread_create for state set");
            return -1;
        }
        pthread_detach(worker_state_set_thread);
    }

    if (wait_for_flag(&done, 5000) == -1) {
        fprintf(stderr, "Timed out waiting for the resumed thread to finish.\n");
        return -1;
    }

    printf("Resumed thread finished. Final counter value: %u\n", atomic_load(&counter));

    return 0;
}
