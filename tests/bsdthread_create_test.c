/* EXPERIMENT (2026-08-17, docs/006 follow-up): does calling __bsdthread_create
 * directly -- bypassing pthread_create()'s own _pthread_allocate() /
 * _pthread_struct_init() -- with a *caller-chosen* `pthread` address (not a
 * fresh allocation libpthread picks itself) actually work, and does the
 * kernel really point the new thread's TPIDRRO_EL0 at that exact address?
 *
 * This is deliberately the narrowest, cheapest version of the question --
 * a zeroed scratch buffer standing in for a real captured struct pthread,
 * no attempt yet at the "restore + repair after thread_start" plan from
 * the chat discussion. If this crashes, the crash site itself is the
 * answer: it tells us what thread_start actually needs before it can run,
 * which the closed-since-10.8 kext gives no other way to find out.
 *
 * __bsdthread_create/__bsdthread_register are not in any public header
 * (confirmed absent from this SDK) but are genuinely exported symbols
 * (confirmed via `nm -gU libsystem_kernel.dylib`) -- same private-but-real
 * category as _POSIX_SPAWN_DISABLE_ASLR elsewhere in this project.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>

#define PTHREAD_START_CUSTOM 0x01000000u

extern void *__bsdthread_create(void *func, void *func_arg, void *stack,
                                 void *pthread, uint32_t flags);

#define SCRATCH_SIZE (64 * 1024)
#define STACK_SIZE   (256 * 1024)

static uint64_t g_chosen_pthread_addr;
static volatile int g_result = -1; /* -1=not run yet, 0=mismatch, 1=match */

/* Deliberately hand-rolled write(), no printf/errno here -- if TPIDRRO_EL0
 * isn't set up correctly yet, we don't want the very check for that to be
 * the thing that crashes first. */
static void new_thread_fn(void *arg) {
    (void)arg;
    uint64_t tpidrro;
    __asm__ volatile ("mrs %0, tpidrro_el0" : "=r" (tpidrro));
    uint64_t derived = (tpidrro & ~7ULL) - 0xE0;
    int match = (derived == g_chosen_pthread_addr);

    char buf[160];
    int n = 0;
    const char* parts[] = {
        "new_thread_fn reached. tpidrro_el0=0x", NULL,
        " derived=0x", NULL,
        " chosen=0x", NULL,
        match ? " MATCH\n" : " MISMATCH\n", NULL
    };
    uint64_t vals[3] = { tpidrro, derived, g_chosen_pthread_addr };
    int vi = 0;
    for (int i = 0; parts[i]; i += 2) {
        for (const char* p = parts[i]; *p; p++) buf[n++] = *p;
        if (i < 6) {
            uint64_t v = vals[vi++];
            char hex[17]; int hn = 0;
            if (v == 0) hex[hn++] = '0';
            while (v) { int d = v & 0xF; hex[hn++] = d < 10 ? (char)('0'+d) : (char)('a'+d-10); v >>= 4; }
            while (hn > 0) buf[n++] = hex[--hn];
        }
    }
    write(STDOUT_FILENO, buf, n);

    g_result = match ? 1 : 0;
    for (;;) pause();
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    void* pthread_scratch = malloc(SCRATCH_SIZE);
    void* stack = malloc(STACK_SIZE);
    if (!pthread_scratch || !stack) { perror("malloc"); return 1; }
    memset(pthread_scratch, 0, SCRATCH_SIZE);

    g_chosen_pthread_addr = (uint64_t)(uintptr_t)pthread_scratch;
    void* stack_top = (char*)stack + STACK_SIZE;

    printf("chosen pthread addr = %p, stack_top = %p\n", pthread_scratch, stack_top);

    errno = 0;
    void* ret = __bsdthread_create((void*)new_thread_fn, NULL, stack_top,
                                    pthread_scratch, PTHREAD_START_CUSTOM);
    if (ret == (void*)-1) {
        fprintf(stderr, "__bsdthread_create failed: errno=%d (%s)\n", errno, strerror(errno));
        return 1;
    }
    printf("__bsdthread_create returned %p\n", ret);

    for (int i = 0; i < 100 && g_result == -1; i++) usleep(50000);

    printf("result: %s\n",
           g_result == 1 ? "MATCH -- TPIDRRO_EL0 correctly points at the chosen address" :
           g_result == 0 ? "MISMATCH -- thread ran but TPIDRRO_EL0 points elsewhere" :
                            "TIMED OUT -- new_thread_fn never ran (crashed inside thread_start?)");
    return g_result == 1 ? 0 : 1;
}
