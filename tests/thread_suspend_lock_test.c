#include <stdio.h>
#include <pthread.h>
#include <mach/mach.h>
#include <mach/thread_act.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static _Atomic bool holding_lock = false;
static _Atomic bool stop = false;

static double elapsed_ms(struct timespec *start) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (now.tv_sec - start->tv_sec) * 1000.0 + (now.tv_nsec - start->tv_nsec) / 1e6;
}

static int wait_for_flag(_Atomic bool *flag, int budget_ms) {
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    while (!atomic_load(flag)) {
        if (elapsed_ms(&start) > budget_ms) return -1;
        usleep(500);
    }
    return 0;
}

static int trylock_bounded(pthread_mutex_t *m, int budget_ms) {
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    while (pthread_mutex_trylock(m) != 0) {
        if (elapsed_ms(&start) > budget_ms) return -1;
        usleep(1000);
    }
    return 0;
}

void* worker_fn(void *arg) {
    (void)arg;
    pthread_mutex_lock(&lock);              /* stand-in: caught here, e.g. mid-malloc holding its arena lock */
    atomic_store(&holding_lock, true);
    printf("worker: acquired the lock, now sitting on it (suspend-vulnerable window)\n");
    while (!atomic_load(&stop)) usleep(1000);
    pthread_mutex_unlock(&lock);
    printf("worker: released the lock, exiting\n");
    return NULL;
}

int main(void) {
    pthread_t worker;
    pthread_create(&worker, NULL, worker_fn, NULL);

    if (wait_for_flag(&holding_lock, 2000) != 0) {
        fprintf(stderr, "worker never acquired the lock -- test inconclusive\n");
        return 1;
    }

    mach_port_t worker_port = pthread_mach_thread_np(worker);
    printf("main: suspending the worker WHILE it holds the lock...\n");
    kern_return_t kr = thread_suspend(worker_port);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "thread_suspend failed: %d\n", kr);
        return 1;
    }

    printf("main: worker suspended. Attempting to acquire the SAME lock now\n"
           "      (stand-in: checkpoint code needing a lock the frozen thread holds)...\n");

    int got_it = (trylock_bounded(&lock, 5000) == 0);

    if (got_it) {
        printf("\nRESULT: lock acquired -- no deadlock observed here.\n"
               "        (Unexpected given the hypothesis -- worth re-examining why.)\n");
        pthread_mutex_unlock(&lock);
    } else {
        printf("\nRESULT: CONFIRMED -- acquiring a lock held by a thread_suspend'd thread deadlocks.\n");
    }

    /* cleanup: resume the worker regardless, so it can release the lock and exit */
    thread_resume(worker_port);
    atomic_store(&stop, true);
    pthread_join(worker, NULL);

    if (!got_it) {
        /* prove the earlier timeout was specifically about the suspend+lock
         * interaction, not a broken trylock loop or an unrelated bug --
         * the same lock should now be acquirable immediately. */
        int final = trylock_bounded(&lock, 2000);
        printf("post-resume lock attempt: %s\n",
               final == 0 ? "succeeded immediately, as expected" : "still failed (unexpected!)");
        if (final == 0) pthread_mutex_unlock(&lock);
    }

    return 0;
}
