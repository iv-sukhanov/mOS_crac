/* Follow-up experiment (2026-08-24): does __bsdthread_create() accept a
 * REAL, validly-signed struct pthread -- borrowed from an already-running,
 * genuinely pthread_create()'d thread in this SAME process -- rather than a
 * zeroed scratch buffer?
 *
 * 2026-08-17's version of this test (a zeroed buffer standing in for a
 * captured struct pthread) failed with SIGTRAP inside _pthread_start's PAC
 * check (autdb) -- unsurprising, a zeroed first field obviously isn't
 * validly signed. The real open question that left: does a struct whose
 * signature genuinely *is* valid for this process (because it belongs to a
 * real thread this same process's own pthread_create() already made) get
 * past that check? This isolates exactly that, cheaply, before thinking
 * about how a restore driver could ever get a validly-signed struct for a
 * *captured* thread specifically.
 *
 * Not remotely a real design even if this passes: two live threads sharing
 * one struct pthread (same TSD array, same errno slot, same stack-bounds
 * fields) would corrupt each other the moment either did anything beyond
 * the bare minimum. This only answers "does the PAC check alone pass" --
 * kept deliberately narrow, both threads do almost nothing after checking
 * in.
 *
 * __bsdthread_create is not in any public header (confirmed absent from
 * this SDK) but is a genuinely exported symbol (confirmed via `nm -gU
 * libsystem_kernel.dylib`) -- same private-but-real category as
 * _POSIX_SPAWN_DISABLE_ASLR elsewhere in this project.
 */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>

#define PTHREAD_START_CUSTOM 0x01000000u

extern void *__bsdthread_create(void *func, void *func_arg, void *stack,
                                 void *pthread, uint32_t flags);

#define STACK_SIZE (256 * 1024)

/* The real, kernel-validated thread whose struct pthread we're about to
 * borrow. Prints its own identity normally (printf/pthread_self() are both
 * completely safe here -- this is a genuine, correctly-created pthread,
 * nothing borrowed yet), then just sits, keeping that struct alive and
 * untouched by anything else. */
static volatile uint64_t g_real_thread_addr;
static volatile int g_real_thread_ready = 0;

static void* real_thread_fn(void* arg) {
    (void)arg;
    uint64_t tpidrro;
    __asm__ volatile ("mrs %0, tpidrro_el0" : "=r" (tpidrro));
    pthread_t self = pthread_self();
    printf("real_thread_fn: pthread_self()=%p tpidrro_el0=0x%llx, pausing forever...\n",
           (void*)self, tpidrro);
    g_real_thread_addr = (uint64_t)(uintptr_t)self;
    g_real_thread_ready = 1;
    for (;;) pause();
    return NULL; /* unreachable */
}

static volatile int g_result = -1; /* -1=not run yet, 0=mismatch, 1=match */

/* Deliberately hand-rolled write(), no printf/errno here -- if TPIDRRO_EL0
 * isn't set up correctly yet, we don't want the very check for that to be
 * the thing that crashes first. Same idiom as 2026-08-17's version. */
static void new_thread_fn(void *arg) {
    (void)arg;
    uint64_t tpidrro;
    __asm__ volatile ("mrs %0, tpidrro_el0" : "=r" (tpidrro));
    uint64_t derived = (tpidrro & ~7ULL) - 0xE0;
    int match = (derived == g_real_thread_addr);

    char buf[160];
    int n = 0;
    const char* parts[] = {
        "new_thread_fn reached. tpidrro_el0=0x", NULL,
        " derived=0x", NULL,
        " borrowed=0x", NULL,
        match ? " MATCH\n" : " MISMATCH\n", NULL
    };
    uint64_t vals[3] = { tpidrro, derived, g_real_thread_addr };
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

    pthread_t real_thread;
    if (pthread_create(&real_thread, NULL, real_thread_fn, NULL) != 0) { perror("pthread_create"); return 1; }
    for (int i = 0; i < 100 && !g_real_thread_ready; i++) usleep(10000);
    if (!g_real_thread_ready) { fprintf(stderr, "real thread never checked in\n"); return 1; }

    void* stack = malloc(STACK_SIZE);
    if (!stack) { perror("malloc"); return 1; }
    void* stack_top = (char*)stack + STACK_SIZE;

    printf("borrowing REAL pthread struct at 0x%llx for __bsdthread_create\n",
           (unsigned long long)g_real_thread_addr);

    errno = 0;
    void* ret = __bsdthread_create((void*)new_thread_fn, NULL, stack_top,
                                    (void*)(uintptr_t)g_real_thread_addr, PTHREAD_START_CUSTOM);
    if (ret == (void*)-1) {
        fprintf(stderr, "__bsdthread_create failed: errno=%d (%s)\n", errno, strerror(errno));
        return 1;
    }
    printf("__bsdthread_create returned %p\n", ret);

    for (int i = 0; i < 100 && g_result == -1; i++) usleep(50000);

    printf("result: %s\n",
           g_result == 1 ? "MATCH -- TPIDRRO_EL0 correctly points at the borrowed (real) address" :
           g_result == 0 ? "MISMATCH -- thread ran but TPIDRRO_EL0 points elsewhere" :
                            "TIMED OUT -- new_thread_fn never ran (crashed inside thread_start? PAC trap?)");
    return g_result == 1 ? 0 : 1;
}
