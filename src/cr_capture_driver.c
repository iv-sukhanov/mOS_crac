/* AI-assistance disclosure: developed with the assistance of Claude
 * (Anthropic) as a coding assistant, under the author's direction, review,
 * and testing. Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
 */
/* Minimal driver exercising cr_capture.c's do_capture(). Linked against
 * cr_capture.o + cr_common.o -- see src/Makefile. */
#include "cr_common.h"
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

void* second_thread_fn(void* arg) {
        (void)arg;
        sleep(1);
        for (int i = 0; i < 5; i++) {
                printf("second thread: %d\n", i);
        }
        printf("second thread: exiting normally\n");
        return NULL;
    }

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 2) { fprintf(stderr, "usage: %s <file>\n", argv[0]); return 2; }
    
    pthread_t second_thread;
    if (pthread_create(&second_thread, NULL, second_thread_fn, NULL) != 0) {
        perror("pthread_create");
        return 1;
    }

    mach_port_t main_port = pthread_mach_thread_np(pthread_self());
    mach_port_t second_port = pthread_mach_thread_np(second_thread);
    printf("main thread: main port=0x%x, second thread port=0x%x\n", main_port, second_port);
    
    int rc = do_capture(argv[1]);

    printf("do_capture returned %d\n", rc);

    if (rc != 0) {
        fprintf(stderr, "do_capture failed: %d\n", rc);
        return rc;
    }

    main_port = pthread_mach_thread_np(pthread_self());
    second_port = pthread_mach_thread_np(second_thread);
    printf("main thread: after do_capture: main port=0x%x, second thread port=0x%x\n", main_port, second_port);

    thread_act_array_t acts;
    mach_msg_type_number_t n_acts;
    if (task_threads(mach_task_self(), &acts, &n_acts) != KERN_SUCCESS) {
        fprintf(stderr, "task_threads failed\n");
        return 1;
    }

    for (mach_msg_type_number_t i = 0; i < n_acts; i++) {
        pthread_t worker_pt = pthread_from_mach_thread_np(acts[i]);
        uint64_t tid;
        pthread_threadid_np(worker_pt, &tid);
        printf("  thread[%u] pthread=%p port=0x%x tid=%llu\n", i, (void*)(intptr_t)worker_pt, acts[i], tid);
    }

    sleep(5);

    printf("main thread: waiting for second thread to exit\n");
    pthread_join(second_thread, NULL);
    printf("main thread: exiting normally\n");
    return 0;
}
