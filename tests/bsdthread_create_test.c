/* Follow-up (2026-08-24, third round): does PAC's signature depend on the
 * struct pthread's own storage *address*, not just process identity (i.e.
 * the PAC key)? Earlier today: a real struct borrowed *in place* (same
 * process, same address) passed PAC; a real struct copied to a genuinely
 * different *process* traps. This isolates the address variable alone --
 * same process (same PAC key), same bytes, but physically relocated to a
 * different address before calling __bsdthread_create. If PAC's
 * discriminator/salt incorporates the pointer's own storage location (a
 * standard PAC defense against copying a valid signature somewhere else),
 * this should trap identically to the cross-process case. If it doesn't,
 * it should pass.
 */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <sys/mman.h>

#define PTHREAD_START_CUSTOM 0x01000000u
#define CAPTURE_LEN (16 * 1024)
#define STACK_SIZE  (256 * 1024)

extern void *__bsdthread_create(void *func, void *func_arg, void *stack,
                                 void *pthread, uint32_t flags);

static volatile uint64_t g_real_addr;
static volatile int g_real_ready = 0;

static void* real_thread_fn(void* arg) {
    (void)arg;
    pthread_t self = pthread_self();
    uint64_t tpidrro;
    __asm__ volatile ("mrs %0, tpidrro_el0" : "=r" (tpidrro));
    printf("real_thread_fn: pthread_self()=%p tpidrro_el0=0x%llx\n", (void*)self, tpidrro);
    g_real_addr = (uint64_t)(uintptr_t)self;
    g_real_ready = 1;
    for (;;) pause();
    return NULL; /* unreachable */
}

static volatile int g_result = -1;

/* Same hand-rolled-write idiom as the earlier tests: if TPIDRRO_EL0 isn't
 * valid yet, don't let checking that be the thing that crashes first. */
static void moved_thread_fn(void *arg) {
    (void)arg;
    uint64_t tpidrro;
    __asm__ volatile ("mrs %0, tpidrro_el0" : "=r" (tpidrro));
    char buf[96];
    int n = 0;
    const char* msg = "moved_thread_fn reached, tpidrro_el0=0x";
    for (const char* p = msg; *p; p++) buf[n++] = *p;
    uint64_t v = tpidrro;
    char hex[17]; int hn = 0;
    if (v == 0) hex[hn++] = '0';
    while (v) { int d = v & 0xF; hex[hn++] = d < 10 ? (char)('0'+d) : (char)('a'+d-10); v >>= 4; }
    while (hn > 0) buf[n++] = hex[--hn];
    buf[n++] = '\n';
    write(STDOUT_FILENO, buf, n);
    g_result = 1;
    for (;;) pause();
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    long page_size = sysconf(_SC_PAGESIZE);

    pthread_t t;
    if (pthread_create(&t, NULL, real_thread_fn, NULL) != 0) { perror("pthread_create"); return 1; }
    for (int i = 0; i < 100 && !g_real_ready; i++) usleep(10000);
    if (!g_real_ready) { fprintf(stderr, "thread never checked in\n"); return 1; }

    uint64_t struct_addr = g_real_addr;
    uint64_t region_start = struct_addr & ~((uint64_t)page_size - 1);
    uint64_t region_end = struct_addr + CAPTURE_LEN;
    uint64_t region_len = ((region_end - region_start) + (uint64_t)page_size - 1) & ~((uint64_t)page_size - 1);
    uint64_t offset_in_region = struct_addr - region_start;

    printf("original struct_addr=0x%llx region=[0x%llx,0x%llx)\n",
           (unsigned long long)struct_addr, (unsigned long long)region_start,
           (unsigned long long)(region_start + region_len));

    /* Ordinary (non-fixed) mmap -- the OS picks a genuinely different
     * address, guaranteed not to collide with the original. Same process,
     * same PAC key throughout; only the struct's storage address changes. */
    void* new_region = mmap(NULL, region_len, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (new_region == MAP_FAILED) { perror("mmap new region"); return 1; }
    memcpy(new_region, (void*)(uintptr_t)region_start, region_len);
    uint64_t new_struct_addr = (uint64_t)(uintptr_t)new_region + offset_in_region;

    printf("moved struct to new_struct_addr=0x%llx (new region [0x%llx,0x%llx))\n",
           (unsigned long long)new_struct_addr, (unsigned long long)(uintptr_t)new_region,
           (unsigned long long)((uintptr_t)new_region + region_len));

    void* stack = malloc(STACK_SIZE);
    if (!stack) { perror("malloc stack"); return 1; }
    void* stack_top = (char*)stack + STACK_SIZE;

    printf("calling __bsdthread_create with the MOVED struct (same process, different address)...\n");
    fflush(stdout);

    errno = 0;
    void* ret = __bsdthread_create((void*)moved_thread_fn, NULL, stack_top,
                                    (void*)(uintptr_t)new_struct_addr, PTHREAD_START_CUSTOM);
    if (ret == (void*)-1) {
        fprintf(stderr, "__bsdthread_create failed: errno=%d (%s) -- rejected before PAC even runs\n",
                errno, strerror(errno));
        return 1;
    }
    printf("__bsdthread_create returned %p -- waiting to see what happens...\n", ret);
    fflush(stdout);

    for (int i = 0; i < 100 && g_result == -1; i++) usleep(50000);
    printf("result: %s\n",
           g_result == 1 ? "ran without crashing (compare the tpidrro_el0 above against original/new addresses)" :
                            "TIMED OUT -- crashed or never ran (check exit signal)");
    return 0;
}
