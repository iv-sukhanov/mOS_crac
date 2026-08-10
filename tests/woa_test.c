#include <stdio.h>
#include <os/os_sync_wait_on_address.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include "barrier_woa.h"

#ifndef NTHREADS
#define NTHREADS 3
#endif

static int val;
static barrier_woa_t barrier;

void* wait_thread_fn(void *args) {
    int ind = (int)(intptr_t)(args);

    int rw = os_sync_wait_on_address(&val, ind, sizeof(val), OS_SYNC_WAIT_ON_ADDRESS_NONE);
    printf("woke up (thread #%d): the return value - %d, errno - %d\n", ind, rw, errno);

    return 0;
}

void* signal_interrupt_fn(void *args) {
    printf("thread created and waiting...\n");
    barrier_wait(&barrier);
    int rv = os_sync_wait_on_address(&val, 0, sizeof(val), OS_SYNC_WAIT_ON_ADDRESS_NONE);
    printf("wait function returned: rv=%d, errno=%d, EINTR=%d\n", rv, errno, EINTR);
}

void signal_action(int sig, siginfo_t *info, void *ctx) {
    char buf[] = "the signal was delivered\n";
    write(STDOUT_FILENO, buf, sizeof(buf));
    
    char buf2[] = "callind barrier\n";
    write(STDOUT_FILENO, buf2, sizeof(buf2));
    barrier_wait(&barrier);

    char buf3[] = "released, sigaction returns\n";
    write(STDOUT_FILENO, buf3, sizeof(buf3));
}

void test_1() {
    pthread_t threads[NTHREADS];
    val = 1;
    for (int i = 0; i < NTHREADS; i++) {
        pthread_create(&threads[i], NULL, wait_thread_fn, (void*)(intptr_t)i);
    }

    sleep(3);
    int rw = os_sync_wake_by_address_all(&val, sizeof(val), OS_SYNC_WAKE_BY_ADDRESS_NONE);
    printf("main: the return value - %d, errno - %d\n", rw, errno);
    
    for (int i = 0; i < NTHREADS; i++) pthread_join(threads[i], NULL);
}

void test_2() {

    val = 0;
    barrier_create(&barrier, 2);
    
    struct sigaction new_usr1 = {
        .sa_flags = SA_SIGINFO,
        .__sigaction_u.__sa_sigaction = signal_action
    }, old;
    sigaction(SIGUSR1, &new_usr1, &old);
    
    pthread_t thread;
    pthread_create(&thread, NULL, signal_interrupt_fn, NULL);

    barrier_wait(&barrier);

    sleep(1);

    pthread_kill(thread, SIGUSR1);

    sleep(3);

    barrier_wait(&barrier);

    pthread_join(thread, NULL);
}

int main() {
    test_2();

    return 0;
}