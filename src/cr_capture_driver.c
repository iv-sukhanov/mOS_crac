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
        for (;;) sleep(30);
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
    
    return do_capture(argv[1]);
}
