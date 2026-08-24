/* Follow-up to bsdthread_create_test.c (2026-08-24): the earlier same-
 * process test showed __bsdthread_create() accepts a validly-signed struct
 * pthread and creates a real thread from it -- but that thread ran the
 * function the struct was *originally* created with, not the one we asked
 * for (the start routine apparently comes from a field inside the struct,
 * not fresh from the syscall's own arguments).
 *
 * This tests the actually load-bearing question 2026-08-17 answered from
 * research (Darwin's PAC key material is drawn per-task from
 * early_random(), so "a signature created with Process 1's B key cannot be
 * verified by Process 2") but never empirically verified with a real
 * captured struct -- only with a zeroed one, which fails for an obvious,
 * unrelated reason. Genuinely capture a real struct pthread from one
 * process, restore it byte-for-byte in a completely separate one, and see
 * what actually happens:
 *
 *   - EINVAL/etc. from __bsdthread_create itself: rejected before PAC is
 *     even checked.
 *   - SIGTRAP (a `brk` inside _pthread_start, matching 2026-08-17's
 *     disassembly of the autdb failure): PAC itself is the wall, confirmed
 *     empirically now, not just by reasoning about the key derivation.
 *   - SIGBUS/SIGSEGV: PAC passed (or isn't hit on this path at all) and the
 *     crash is instead the struct's stale start-routine field pointing at
 *     an address with no meaning in this process -- a genuinely different,
 *     and more interesting, failure to have found.
 *
 * Two modes in one binary, selected by argv[1]:
 *   capture <file>  -- create a real thread, dump its struct pthread's
 *                      memory (one page, generous headroom -- the true
 *                      size isn't documented) to <file>.
 *   reuse <file>    -- read it back (in a separate process launch), map it
 *                      at the *same* address via MAP_FIXED, and try to
 *                      __bsdthread_create() a new thread from it.
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
#define CAPTURE_LEN (16 * 1024)   /* one page -- generous, true struct size undocumented */
#define STACK_SIZE  (256 * 1024)

extern void *__bsdthread_create(void *func, void *func_arg, void *stack,
                                 void *pthread, uint32_t flags);

typedef struct {
    uint64_t source_pid;
    uint64_t struct_addr;   /* the real pthread_self() address -- NOT page-aligned in general */
    uint64_t region_start;  /* floor_to_page(struct_addr) -- what actually gets mmap(MAP_FIXED)'d */
    uint64_t region_len;    /* page-aligned span captured, covering struct_addr..struct_addr+CAPTURE_LEN */
} header_t;

static volatile uint64_t g_thread_addr;
static volatile int g_thread_ready = 0;

static void* real_thread_fn(void* arg) {
    (void)arg;
    pthread_t self = pthread_self();
    uint64_t tpidrro;
    __asm__ volatile ("mrs %0, tpidrro_el0" : "=r" (tpidrro));
    printf("real_thread_fn: pthread_self()=%p tpidrro_el0=0x%llx\n", (void*)self, tpidrro);
    g_thread_addr = (uint64_t)(uintptr_t)self;
    g_thread_ready = 1;
    for (;;) pause();
    return NULL; /* unreachable */
}

static int do_capture(const char* path) {
    pthread_t t;
    if (pthread_create(&t, NULL, real_thread_fn, NULL) != 0) { perror("pthread_create"); return 1; }
    for (int i = 0; i < 100 && !g_thread_ready; i++) usleep(10000);
    if (!g_thread_ready) { fprintf(stderr, "thread never checked in\n"); return 1; }

    long page_size = sysconf(_SC_PAGESIZE);
    uint64_t struct_addr = g_thread_addr;
    /* mmap(MAP_FIXED) requires a page-aligned addr -- struct_addr itself
     * generally isn't (it's an arbitrary offset back from TPIDRRO_EL0, no
     * reason to land on a page boundary), so capture the whole containing
     * page(s) instead and remember struct_addr's real position within it. */
    uint64_t region_start = struct_addr & ~((uint64_t)page_size - 1);
    uint64_t region_end = struct_addr + CAPTURE_LEN;
    uint64_t region_len = ((region_end - region_start) + (uint64_t)page_size - 1) & ~((uint64_t)page_size - 1);

    header_t hdr = {
        .source_pid = (uint64_t)getpid(), .struct_addr = struct_addr,
        .region_start = region_start, .region_len = region_len,
    };
    FILE* f = fopen(path, "wb");
    if (!f) { perror("fopen"); return 1; }
    fwrite(&hdr, sizeof(hdr), 1, f);
    fwrite((void*)(uintptr_t)region_start, 1, region_len, f);
    fclose(f);
    printf("captured pid=%llu struct_addr=0x%llx region=[0x%llx,0x%llx) -> %s\n",
           (unsigned long long)hdr.source_pid, (unsigned long long)hdr.struct_addr,
           (unsigned long long)hdr.region_start, (unsigned long long)(hdr.region_start + hdr.region_len), path);
    return 0;
}

/* Never actually expected to run -- the struct's own recorded start
 * routine (from the *capturing* process) is what __bsdthread_create /
 * _pthread_start will actually use, per 2026-08-24's same-process finding.
 * Exists only so the compiler has a real function to pass. */
static void new_thread_fn(void *arg) {
    (void)arg;
    const char msg[] = "new_thread_fn: actually ran (unexpected!)\n";
    write(STDOUT_FILENO, msg, sizeof(msg) - 1);
    for (;;) pause();
}

static int do_reuse(const char* path) {
    FILE* f = fopen(path, "rb");
    if (!f) { perror("fopen"); return 1; }
    header_t hdr;
    if (fread(&hdr, sizeof(hdr), 1, f) != 1) { fprintf(stderr, "short read on header\n"); fclose(f); return 1; }
    uint8_t* buf = malloc(hdr.region_len);
    if (!buf || fread(buf, 1, hdr.region_len, f) != hdr.region_len) {
        fprintf(stderr, "short read on struct bytes\n"); fclose(f); return 1;
    }
    fclose(f);

    printf("reusing struct from pid=%llu struct_addr=0x%llx region=[0x%llx,0x%llx) (this process pid=%d)\n",
           (unsigned long long)hdr.source_pid, (unsigned long long)hdr.struct_addr,
           (unsigned long long)hdr.region_start, (unsigned long long)(hdr.region_start + hdr.region_len), getpid());

    void* got = mmap((void*)(uintptr_t)hdr.region_start, hdr.region_len, PROT_READ | PROT_WRITE,
                      MAP_FIXED | MAP_ANON | MAP_PRIVATE, -1, 0);
    if (got == MAP_FAILED) {
        perror("mmap at captured region");
        return 1;
    }
    if ((uint64_t)(uintptr_t)got != hdr.region_start) {
        fprintf(stderr, "mmap did not honor the fixed address: got %p, wanted 0x%llx\n",
                got, (unsigned long long)hdr.region_start);
        return 1;
    }
    memcpy(got, buf, hdr.region_len);
    free(buf);

    void* stack = malloc(STACK_SIZE);
    if (!stack) { perror("malloc stack"); return 1; }
    void* stack_top = (char*)stack + STACK_SIZE;

    printf("calling __bsdthread_create with the restored (foreign) struct...\n");
    fflush(stdout);

    errno = 0;
    void* ret = __bsdthread_create((void*)new_thread_fn, NULL, stack_top,
                                    (void*)(uintptr_t)hdr.struct_addr, PTHREAD_START_CUSTOM);
    if (ret == (void*)-1) {
        fprintf(stderr, "__bsdthread_create failed: errno=%d (%s) -- rejected before PAC even runs\n",
                errno, strerror(errno));
        return 1;
    }
    printf("__bsdthread_create returned %p -- a thread was created, waiting to see what it does...\n", ret);
    fflush(stdout);

    sleep(3); /* if it's going to crash, this is long enough to see it */
    printf("no crash within 3s\n");
    return 0;
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 3) {
        fprintf(stderr, "usage: %s capture|reuse <file>\n", argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "capture") == 0) return do_capture(argv[2]);
    if (strcmp(argv[1], "reuse") == 0) return do_reuse(argv[2]);
    fprintf(stderr, "unknown mode %s\n", argv[1]);
    return 2;
}
