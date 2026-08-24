/* Fourth round, 2026-08-24/25: does self-computing a PAC signature (rather
 * than replaying one) let a relocated struct pthread pass BOTH of
 * _pthread_validate_signature's checks -- the hardware autdb and the
 * software `decoded_addr == current_addr` comparison -- for a NEW address?
 *
 * Mechanism (see docs/007): sig = sign_unauth(addr, key B, "pthread.signature")
 * ^ munge_token. Earlier round (still in git history) moved a real struct to
 * a new address WITHOUT touching its sig field -- PAC itself passed (same
 * process, same key), but the software check failed ("PThread Corruption"),
 * because the old sig still decoded to the OLD address.
 *
 * This time: recover munge_token from a real, live, validly-signed thread
 * (munge = live->sig ^ sign_unauth(live_addr, ...) -- pure algebra, no
 * privileged access needed), then compute a FRESH sig for the struct's NEW
 * address and overwrite the copied struct's sig field with it before
 * calling __bsdthread_create. If this passes, struct-pthread identity can
 * be re-established at an address of OUR choosing, in-process, without
 * borrowing signed bytes from anywhere -- untested until now.
 */
#include <pthread.h>
#include <ptrauth.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <sys/mman.h>
#include <mach/mach.h>

#if !__has_feature(ptrauth_calls)
#error "build with -arch arm64e -- ptrauth intrinsics aren't available otherwise"
#endif

#define PTHREAD_START_CUSTOM 0x21000000u
#define CAPTURE_LEN (16 * 1024)
#define STACK_SIZE  (256 * 1024)

extern void *__bsdthread_create(void *func, void *func_arg, void *stack,
                                 void *pthread, uint32_t flags);

/* Same (addr, key, discriminator) triple as libpthread's own
 * _pthread_init_signature/_pthread_validate_signature (docs/007). */
static uintptr_t sign_for_addr(uintptr_t addr) {
    return (uintptr_t)ptrauth_sign_unauthenticated(
        (void *)addr, ptrauth_key_process_dependent_data,
        ptrauth_string_discriminator("pthread.signature"));
}

static volatile uint64_t g_real_addr;
static volatile int g_real_ready = 0;

static void* real_thread_fn(void* arg) {
    (void)arg;
    
    pthread_t self = pthread_self();
    mach_port_t mp = pthread_mach_thread_np(self);
    
    uint64_t tpidrro;
    __asm__ volatile ("mrs %0, tpidrro_el0" : "=r" (tpidrro));
    
    printf("real_thread_fn: pthread_self()=%p, mach_port=0x%x, tpidrro_el0=0x%llx\n", (void*)self, (void*)mp, tpidrro);
    g_real_addr = (uint64_t)(uintptr_t)self;
    g_real_ready = 1;
    for (;;) pause();
    return NULL; /* unreachable */
}

static volatile int g_result = -1;

/* Hand-rolled write, not printf: if identity still isn't fully valid,
 * don't let checking that be the thing that crashes first. */
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

    /* Step 1: recover munge_token algebraically from the live, genuinely
     * pthread_create()'d thread -- no need to find where the OS actually
     * seeds it (docs/007's apple[] check came back empty on this build). */
    uintptr_t stored_sig = *(uintptr_t *)(uintptr_t)struct_addr;
    uintptr_t munge = stored_sig ^ sign_for_addr(struct_addr);
    printf("recovered munge_token=0x%lx (from live struct at 0x%llx, sig=0x%lx)\n",
           munge, (unsigned long long)struct_addr, stored_sig);

    /* Step 2: copy the real struct's page(s) to a genuinely different
     * address, same as the previous round -- gives us a plausible rest-of-
     * struct (tsd, thread_id, etc.), not just a correct sig field. */
    uint64_t region_start = struct_addr & ~((uint64_t)page_size - 1);
    uint64_t region_end = struct_addr + CAPTURE_LEN;
    uint64_t region_len = ((region_end - region_start) + (uint64_t)page_size - 1) & ~((uint64_t)page_size - 1);
    uint64_t offset_in_region = struct_addr - region_start;

    void* new_region = mmap(NULL, region_len, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (new_region == MAP_FAILED) { perror("mmap new region"); return 1; }
    memcpy(new_region, (void*)(uintptr_t)region_start, region_len);
    uint64_t new_struct_addr = (uint64_t)(uintptr_t)new_region + offset_in_region;

    /* Step 3: the actual new lever -- self-compute a valid sig for the
     * struct's NEW address and overwrite the copied (stale-for-here) one. */
    uintptr_t new_sig = sign_for_addr(new_struct_addr) ^ munge;
    *(uintptr_t *)(uintptr_t)new_struct_addr = new_sig;

    printf("moved struct to new_struct_addr=0x%llx, self-signed sig=0x%lx\n",
           (unsigned long long)new_struct_addr, new_sig);

    void* stack = malloc(STACK_SIZE);
    if (!stack) { perror("malloc stack"); return 1; }
    void* stack_top = (char*)stack + STACK_SIZE;

    printf("calling __bsdthread_create with the self-signed struct...\n");
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

    mach_port_t main = mach_thread_self(), th1 = pthread_mach_thread_np(t), new_th = MACH_PORT_NULL;
    thread_act_array_t act_list;
    mach_msg_type_number_t act_number;
    task_threads(mach_task_self(), &act_list, &act_number);

    for (uint32_t i = 0; i < act_number; i++) {
        if (act_list[i] != main && act_list[i] != th1) {
            new_th = act_list[i];
            break;
        }
    }

    vm_deallocate(mach_task_self(), (vm_address_t)act_list, act_number * sizeof(thread_act_t));
    sleep(3);
    printf("resuming the new thread (mach_port=0x%x) -- if it crashes, check exit signal / crash report\n", (void*)new_th);
    thread_resume(new_th);

    for (int i = 0; i < 100 && g_result == -1; i++) usleep(50000);
    printf("result: %s\n",
           g_result == 1 ? "PASSED -- self-signed struct survived _pthread_start at its new address" :
                            "TIMED OUT -- crashed or never ran (check exit signal / crash report)");
    return 0;
}
