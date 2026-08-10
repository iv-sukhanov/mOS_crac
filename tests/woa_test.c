#include <stdio.h>
#include <stdlib.h>
#include <os/os_sync_wait_on_address.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <time.h>
#include "barrier_woa.h"

#ifndef NTHREADS
#define NTHREADS 3
#endif

#ifndef STRESS_ITERATIONS
#define STRESS_ITERATIONS 200
#endif

static int val;
static barrier_woa_t barrier;

static double elapsed_ms(struct timespec *start) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (now.tv_sec - start->tv_sec) * 1000.0 + (now.tv_nsec - start->tv_nsec) / 1e6;
}

/* bounded spin-wait for a flag: avoids both a fixed-sleep race (main might
 * check before the worker actually gets there) and an unbounded wait.
 * returns 0 if the flag became true within budget_ms, -1 on timeout. */
static int wait_for_flag(_Atomic bool *flag, int budget_ms) {
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    while (!atomic_load(flag)) {
        if (elapsed_ms(&start) > budget_ms) return -1;
        usleep(500);
    }
    return 0;
}

/* ============================= test 1 ============================= */
/* mismatched expected value => os_sync_wait_on_address returns immediately;
 * matching value => genuinely blocks until someone wakes it. Verified by
 * elapsed time, not just by eyeballing print order. */

static double t1_elapsed[NTHREADS];

void* t1_wait_fn(void *args) {
    int ind = (int)(intptr_t)args;
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);

    int rw = os_sync_wait_on_address(&val, ind, sizeof(val), OS_SYNC_WAIT_ON_ADDRESS_NONE);
    t1_elapsed[ind] = elapsed_ms(&start);
    printf("  thread #%d: rv=%d errno=%d elapsed=%.0fms\n", ind, rw, errno, t1_elapsed[ind]);
    return NULL;
}

static int test_1(void) {
    printf("\n=== test 1: value-mismatch => immediate return ===\n");
    pthread_t threads[NTHREADS];
    val = 1;
    for (int i = 0; i < NTHREADS; i++) pthread_create(&threads[i], NULL, t1_wait_fn, (void*)(intptr_t)i);

    sleep(3);
    os_sync_wake_by_address_all(&val, sizeof(val), OS_SYNC_WAKE_BY_ADDRESS_NONE);
    for (int i = 0; i < NTHREADS; i++) pthread_join(threads[i], NULL);

    int pass = 1;
    for (int i = 0; i < NTHREADS; i++) {
        int should_block = (i == 1);                 /* only thread 1's expected value (1) matches val */
        int did_block = t1_elapsed[i] > 1500.0;       /* 3s sleep vs. "immediate" */
        if (did_block != should_block) {
            printf("  FAIL thread #%d: expected %s, got elapsed=%.0fms\n",
                   i, should_block ? "blocked ~3s" : "immediate", t1_elapsed[i]);
            pass = 0;
        }
    }
    printf("test 1: %s\n", pass ? "PASS" : "FAIL");
    return pass;
}

/* ============================= test 2 ============================= */
/* (2a) a thread's own os_sync_wait_on_address gets interrupted by a signal,
 * and (2b) the signal handler itself calls barrier_wait -> internally
 * os_sync_wait_on_address / wake_by_address_all -- the actual open
 * async-signal-safety question, not just "does EINTR fire". */

static _Atomic bool t2_about_to_wait;
static _Atomic bool t2_recovered_ok;

void* t2_worker_fn(void *args) {
    (void)args;
    barrier_wait(&barrier);                          /* round 1: rendezvous with main */

    atomic_store(&t2_about_to_wait, true);
    errno = 0;
    int rv = os_sync_wait_on_address(&val, 0, sizeof(val), OS_SYNC_WAIT_ON_ADDRESS_NONE);
    int saved_errno = errno;
    printf("  worker: interrupted wait returned rv=%d errno=%d\n", rv, saved_errno);
    atomic_store(&t2_recovered_ok, rv == -1 && saved_errno == EINTR);
    return NULL;
}

void t2_signal_action(int sig, siginfo_t *info, void *ctx) {
    (void)sig; (void)info; (void)ctx;
    char msg[] = "  handler: delivered, calling barrier_wait (round 2) from inside the handler\n";
    write(STDOUT_FILENO, msg, sizeof(msg) - 1);
    barrier_wait(&barrier);                           /* the thing under test */
}

static int test_2(void) {
    printf("\n=== test 2: signal interrupts a blocked wait; handler calls the primitive ===\n");
    val = 0;
    barrier_create(&barrier, 2);
    atomic_store(&t2_about_to_wait, false);
    atomic_store(&t2_recovered_ok, false);

    struct sigaction new_usr1 = { .sa_flags = SA_SIGINFO, .__sigaction_u.__sa_sigaction = t2_signal_action }, old;
    sigaction(SIGUSR1, &new_usr1, &old);

    pthread_t thread;
    pthread_create(&thread, NULL, t2_worker_fn, NULL);

    int r1 = barrier_wait(&barrier);                  /* main's round 1 */
    if (wait_for_flag(&t2_about_to_wait, 2000) != 0) {
        printf("test 2: FAIL (worker never reached the blocking wait)\n");
        pthread_join(thread, NULL);
        return 0;
    }

    pthread_kill(thread, SIGUSR1);
    int r2 = barrier_wait(&barrier);                  /* main's round 2, released by the handler */
    pthread_join(thread, NULL);

    int pass = (r1 == 0) && (r2 == 0) && atomic_load(&t2_recovered_ok);
    printf("test 2: %s (r1=%d r2=%d recovered=%d)\n", pass ? "PASS" : "FAIL",
           r1, r2, atomic_load(&t2_recovered_ok));
    return pass;
}

/* ============================= test 3 ============================= */
/* stress: repeat test 2's scenario many times with jittered signal timing,
 * and a bounded wait on the worker's own blocking call so a real safety bug
 * surfaces as a counted, timed-out failure instead of the whole process
 * just hanging. */

static _Atomic bool t3_about_to_wait;
static _Atomic bool t3_recovered_ok;
static _Atomic bool t3_timed_out;

void* t3_worker_fn(void *args) {
    (void)args;
    barrier_wait(&barrier);
    atomic_store(&t3_about_to_wait, true);

    errno = 0;
    int rv = os_sync_wait_on_address_with_timeout(&val, 0, sizeof(val),
                                                   OS_SYNC_WAIT_ON_ADDRESS_NONE,
                                                   OS_CLOCK_MACH_ABSOLUTE_TIME,
                                                   2000000000ULL /* 2s */);
    int saved_errno = errno;
    if (rv == -1 && saved_errno == ETIMEDOUT) {
        atomic_store(&t3_timed_out, true);
        return NULL;
    }
    atomic_store(&t3_recovered_ok, rv == -1 && saved_errno == EINTR);
    return NULL;
}

static int test_3(void) {
    printf("\n=== test 3: stress (%d iterations, jittered signal timing) ===\n", STRESS_ITERATIONS);
    srand((unsigned)time(NULL));
    int failures = 0;

    struct sigaction new_usr1 = { .sa_flags = SA_SIGINFO, .__sigaction_u.__sa_sigaction = t2_signal_action }, old;
    sigaction(SIGUSR1, &new_usr1, &old);

    for (int iter = 0; iter < STRESS_ITERATIONS; iter++) {
        val = 0;
        barrier_create(&barrier, 2);
        atomic_store(&t3_about_to_wait, false);
        atomic_store(&t3_recovered_ok, false);
        atomic_store(&t3_timed_out, false);

        pthread_t thread;
        pthread_create(&thread, NULL, t3_worker_fn, NULL);

        int r1 = barrier_wait(&barrier);
        int ready = wait_for_flag(&t3_about_to_wait, 1000);

        usleep(rand() % 3000);        /* jitter: vary where the signal lands relative to the worker */
        if (ready == 0) pthread_kill(thread, SIGUSR1);

        int r2 = barrier_wait(&barrier);
        /* ponytail: this join has no timeout of its own -- if the handler
         * call really is unsafe and deadlocks somewhere other than the
         * bounded wait above, this iteration (and the whole test) hangs
         * here instead of reporting a clean failure. Upgrade path if that
         * ever needs covering too: pthread_detach + a flag-polling
         * watchdog around the join itself, abandoning the stuck thread
         * and moving to the next iteration. */
        pthread_join(thread, NULL);

        int ok = (ready == 0) && (r1 == 0) && (r2 == 0)
                 && atomic_load(&t3_recovered_ok) && !atomic_load(&t3_timed_out);
        if (!ok) {
            failures++;
            printf("  iter %d: FAIL (ready=%d r1=%d r2=%d recovered=%d timed_out=%d)\n",
                   iter, ready, r1, r2, atomic_load(&t3_recovered_ok), atomic_load(&t3_timed_out));
        }
    }

    printf("test 3: %d/%d iterations passed\n", STRESS_ITERATIONS - failures, STRESS_ITERATIONS);
    return failures == 0;
}

int main(void) {
    int p1 = test_1();
    int p2 = test_2();
    int p3 = test_3();

    printf("\n=== summary: test1=%s test2=%s test3=%s ===\n",
           p1 ? "PASS" : "FAIL", p2 ? "PASS" : "FAIL", p3 ? "PASS" : "FAIL");
    return (p1 && p2 && p3) ? 0 : 1;
}
