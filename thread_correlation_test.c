/*
 * Milestone-0 test (see NOTES.md "Next step" / gap #1): does a Mach thread
 * port returned by task_threads() correlate back to a pthread_t, and can we
 * suspend + read/write a sibling thread's registers purely at the Mach
 * layer (no signals, no pthread_kill)?
 *
 * Spawns N worker pthreads, records each one's *known-good* forward mapping
 * (pthread_t -> mach thread port, via the documented pthread_mach_thread_np),
 * then from the main thread enumerates all task threads via task_threads()
 * and tries the *reverse*, undocumented direction (mach port -> pthread_t
 * via pthread_from_mach_thread_np) to see if it round-trips. Also exercises
 * thread_suspend/thread_get_state/thread_set_state/thread_resume on a
 * sibling purely via its Mach port, as the candidate alternative to
 * minicriu's signal-based self-interrupt.
 *
 * Build: make -f Makefile.test thread_correlation_test  (or see Makefile)
 * Run:   ./thread_correlation_test
 */
#include <mach/mach.h>
#include <mach/thread_act.h>
#include <mach/mach_types.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <unistd.h>

#define NWORKERS 3

typedef struct {
    pthread_t pt;
    mach_port_t mach_port;   /* ground truth: pthread_mach_thread_np(pt) */
} worker_info_t;

static worker_info_t workers[NWORKERS];
static atomic_int ready_count = 0;
static atomic_bool stop = false;

static void *worker_fn(void *arg) {
    int idx = (int)(intptr_t)arg;
    workers[idx].pt = pthread_self();
    workers[idx].mach_port = pthread_mach_thread_np(pthread_self());
    atomic_fetch_add(&ready_count, 1);
    /* busy-spin so the thread has a live, running state to suspend/inspect */
    volatile long counter = 0;
    while (!atomic_load(&stop)) counter++;
    return NULL;
}

int main(void) {
    pthread_t tids[NWORKERS];
    for (int i = 0; i < NWORKERS; i++) {
        if (pthread_create(&tids[i], NULL, worker_fn, (void *)(intptr_t)i) != 0) {
            fprintf(stderr, "pthread_create failed\n");
            return 1;
        }
    }
    while (atomic_load(&ready_count) < NWORKERS) usleep(1000);

    mach_port_t self_port = pthread_mach_thread_np(pthread_self());
    printf("main thread: pthread_t=%p mach_port=0x%x\n", (void *)pthread_self(), self_port);
    for (int i = 0; i < NWORKERS; i++) {
        printf("worker[%d]: pthread_t=%p mach_port=0x%x\n",
               i, (void *)workers[i].pt, workers[i].mach_port);
    }

    /* --- Part A: task_threads() enumeration + reverse correlation --- */
    thread_act_array_t thread_list;
    mach_msg_type_number_t thread_count;
    kern_return_t kr = task_threads(mach_task_self(), &thread_list, &thread_count);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "task_threads failed: %d\n", kr);
        return 1;
    }
    printf("\ntask_threads() returned %u threads\n", thread_count);

    int matched = 0, mismatched = 0, nulls = 0;
    mach_port_t suspend_target = MACH_PORT_NULL;
    for (mach_msg_type_number_t i = 0; i < thread_count; i++) {
        mach_port_t port = thread_list[i];
        pthread_t reverse = pthread_from_mach_thread_np(port);

        const char *who = "unknown";
        if (port == self_port) who = "main";
        for (int w = 0; w < NWORKERS; w++) {
            if (port == workers[w].mach_port) who = "worker";
        }

        if (reverse == NULL) {
            nulls++;
            printf("  port 0x%x (%s): pthread_from_mach_thread_np -> NULL\n", port, who);
        } else {
            int ok = 0;
            if (reverse == pthread_self() && port == self_port) ok = 1;
            for (int w = 0; w < NWORKERS; w++) {
                if (reverse == workers[w].pt && port == workers[w].mach_port) ok = 1;
            }
            if (ok) {
                matched++;
                printf("  port 0x%x (%s): pthread_from_mach_thread_np -> %p MATCH\n",
                       port, who, (void *)reverse);
            } else {
                mismatched++;
                printf("  port 0x%x (%s): pthread_from_mach_thread_np -> %p MISMATCH\n",
                       port, who, (void *)reverse);
            }
        }

        /* pick a worker (not self) as the suspend/inspect target for Part B */
        if (suspend_target == MACH_PORT_NULL && port != self_port) {
            for (int w = 0; w < NWORKERS; w++) {
                if (port == workers[w].mach_port) suspend_target = port;
            }
        }
    }
    printf("summary: %d matched, %d mismatched, %d NULL (of %u)\n",
           matched, mismatched, nulls, thread_count);

    /* --- Part B: suspend + get/set state purely via Mach port --- */
    if (suspend_target != MACH_PORT_NULL) {
        printf("\nsuspending worker port 0x%x via Mach only (no signals)...\n", suspend_target);
        kr = thread_suspend(suspend_target);
        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "thread_suspend failed: %d\n", kr);
        } else {
#if defined(__arm64__) || defined(__aarch64__)
            arm_thread_state64_t state;
            mach_msg_type_number_t state_count = ARM_THREAD_STATE64_COUNT;
            kr = thread_get_state(suspend_target, ARM_THREAD_STATE64,
                                   (thread_state_t)&state, &state_count);
            if (kr == KERN_SUCCESS) {
                printf("  thread_get_state OK: pc=0x%llx sp=0x%llx\n",
                       (unsigned long long)arm_thread_state64_get_pc(state),
                       (unsigned long long)arm_thread_state64_get_sp(state));
                /* round-trip: set the same state back, should be a no-op */
                kr = thread_set_state(suspend_target, ARM_THREAD_STATE64,
                                       (thread_state_t)&state, state_count);
                printf("  thread_set_state (round-trip, no-op) -> %s\n",
                       kr == KERN_SUCCESS ? "OK" : "FAILED");
            } else {
                fprintf(stderr, "  thread_get_state failed: %d\n", kr);
            }
#else
            printf("  (x86_64 thread_get_state path not exercised on this machine)\n");
#endif
            kr = thread_resume(suspend_target);
            printf("  thread_resume -> %s\n", kr == KERN_SUCCESS ? "OK" : "FAILED");
        }
    } else {
        printf("\nno worker port identified to suspend (Part A correlation may have failed)\n");
    }

    vm_deallocate(mach_task_self(), (vm_address_t)thread_list,
                  thread_count * sizeof(thread_act_t));

    atomic_store(&stop, true);
    for (int i = 0; i < NWORKERS; i++) pthread_join(tids[i], NULL);

    /* pass/fail: every worker must have matched, and the suspend/get-state
     * round trip must have succeeded, or this run tells us the candidate
     * approach doesn't hold and we need a different one (see NOTES.md). */
    int ok = (matched == NWORKERS + 1 /* workers + main */) && (suspend_target != MACH_PORT_NULL);
    printf("\n%s\n", ok ? "PASS" : "FAIL (see output above)");
    return ok ? 0 : 1;
}
