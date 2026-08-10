#ifndef BARRIER_WOA_H
#define BARRIER_WOA_H

#include <stdatomic.h>
#include <os/os_sync_wait_on_address.h>
#include <errno.h>
#include <stdio.h>

typedef struct {
    _Atomic uint32_t gen;
    _Atomic uint32_t count;
    uint32_t thread_number;
} barrier_woa_t;

static int barrier_create(barrier_woa_t *barrier, uint32_t thread_number) {
    barrier->count = 0;
    barrier->gen = 0;
    barrier->thread_number = thread_number;
    
    return 0;
}

static int barrier_wait(barrier_woa_t *barrier) {
    uint32_t my_gen = atomic_load(&barrier->gen);
    uint32_t old = atomic_fetch_add(&barrier->count, 1);

    if (old + 1 == barrier->thread_number) {
        atomic_store(&barrier->count, 0);
        atomic_fetch_add(&barrier->gen, 1);
        if (os_sync_wake_by_address_all(&barrier->gen, sizeof(barrier->gen), OS_SYNC_WAKE_BY_ADDRESS_NONE) != 0) {
            fprintf(stderr, "failed to wake: %d\n", errno);
            return -1;
        }

        return 0;
    }
    
    while (atomic_load(&barrier->gen) == my_gen) {
        if (os_sync_wait_on_address(&barrier->gen, my_gen, sizeof(barrier->gen), OS_SYNC_WAIT_ON_ADDRESS_NONE) == -1 &&
            errno != EINTR && errno != EFAULT) 
        {
            fprintf(stderr, "failed to wait: %d\n", errno);
            return -1;
        }
    }

    return 0;
}

#endif