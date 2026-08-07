#include <stdio.h>
#include <mach/semaphore.h>
#include <mach/task.h>
#include <mach/mach.h>
#include <stdatomic.h>
#include <pthread.h>
#include <math.h>
#include <unistd.h>
#include <os/os_sync_wait_on_address.h>
#include <errno.h>

#define NTHREADS 3

typedef struct {
    semaphore_t semaphore;
    _Atomic uint32_t count;
    uint32_t thread_number;
} barrier_sem_t;

typedef struct {
    _Atomic uint32_t gen;
    _Atomic uint32_t count;
    uint32_t thread_number;
} barrier_woa_t;

static barrier_sem_t barrier;

int barrier_create_sem(task_t task, barrier_sem_t *barrier, uint32_t thread_number) {
    
    if (barrier == NULL) {
        fprintf(stderr, "a NULL barrier passed to barrier_create_sem\n");
        return -1;
    }

    kern_return_t kr = semaphore_create(task, &barrier->semaphore, SYNC_POLICY_FIFO, 0);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "failed to crete barrier sem: %d (hex 0x%x)\n", kr, kr);
        return -1;
    }
    barrier->count = 0;
    barrier->thread_number = thread_number;

    return 0;
}

int barrier_destroy_sem(task_t task, barrier_sem_t *barrier) {
    kern_return_t kr = semaphore_destroy(task, barrier->semaphore);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "failed to destroy barrier sem: %d (hex 0x%x)\n", kr, kr);
        return -1;
    }

    return 0;
}

int barrier_wait_sem(barrier_sem_t *barrier) {
    
    kern_return_t kr;
    uint32_t old = atomic_fetch_add(&barrier->count, 1);
    if (old + 1 == barrier->thread_number) {
        atomic_store(&barrier->count, 0);
        kr = semaphore_signal_all(barrier->semaphore);
        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "failed to wake up all threads: %d (hex 0x%x)", kr, kr);
            return -1;
        }

        return 0;
    }

    kr = semaphore_wait(barrier->semaphore);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "failed to wait on semaphore: %d (hex 0x%x)", kr, kr);
        return -1;
    }

    return 0;
}

void barrier_init_woa(barrier_woa_t *barrier, uint32_t thread_number) {
    barrier->count = 0;
    barrier->gen = 0;
    barrier->thread_number = thread_number;
}

int barrier_wait_woa(barrier_woa_t *barrier) {
    uint32_t my_gen = atomic_load(&barrier->gen);
    uint32_t old = atomic_fetch_add(&barrier->count, 1);

    if (old + 1 == barrier->thread_number) {
        atomic_store(&barrier->count, 0);
        atomic_fetch_add(&barrier->gen, 1);
        if (os_sync_wake_by_address_all(&barrier->gen, sizeof(barrier->gen), OS_SYNC_WAKE_BY_ADDRESS_NONE) != 0) {
            fprintf(stderr, "failed to wake: %d\n", errno);
            return -1;
        }
    }
    
    while (atomic_load(&barrier->gen) == my_gen) {
        if (os_sync_wait_on_address(&barrier->gen, my_gen, sizeof(barrier->gen), OS_SYNC_WAKE_BY_ADDRESS_NONE) != 0 &&
            errno != EINTR && errno != EFAULT) 
        {
            fprintf(stderr, "failed to wait: %d\n", errno);
            return -1;
        }
    }
}

void* thread_fn(void* args) {
    int ind = (int)(intptr_t)args;
    
    if (barrier_wait_sem(&barrier) != 0) {
        printf("error calling a barrier\n");
        return NULL;
    }

    sleep(ind*2);

    printf("thread #%d is ready to be released\n", ind);

    if (barrier_wait_sem(&barrier) != 0) {
        printf("error calling a barrier\n");
        return NULL;
    }

    printf("thread released: %d\n", ind);
    return NULL;
}

int main(void) {
    if (barrier_create_sem(mach_task_self(), &barrier, NTHREADS + 1) == -1) {
        fprintf(stderr, "cannot create a barrier");
        return -1;
    }

    pthread_t threads[NTHREADS];
    for (int i = 0; i < NTHREADS; i++) {
        int rc = pthread_create(&threads[i], NULL, thread_fn, (void*)(intptr_t)i);
        if (rc != 0) {
            printf("cannot create a pthread: %d\n", rc);
            return 1;
        }
    }
    printf("created all threads, now, time to execute\n");
    barrier_wait_sem(&barrier);

    printf("main thread waits for the threads\n");

    barrier_wait_sem(&barrier);
    printf("main thread passed\n");

    for (int i = 0; i < NTHREADS; i++) pthread_join(threads[i], NULL);
    barrier_destroy_sem(mach_task_self(), &barrier);

    return 0;
}