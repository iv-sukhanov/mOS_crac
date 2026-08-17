#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <mach/thread_state.h>
#include <mach/mach_vm.h>
#include <signal.h>
#include "barrier_woa.h"

#define PAGE_SIZE_ASSUMED 16384
#define STACK_CHUNK_BYTES (8 * PAGE_SIZE_ASSUMED)   /* 128KB */
#define CODE_CHUNK_BYTES  (4 * PAGE_SIZE_ASSUMED)   /* 64KB */
#define WORKER_ITERS 100000000ULL

typedef struct regs {
    arm_thread_state64_t gregs;
    arm_neon_state64_t neon;
    uint64_t tpidr;
} regs_t;

typedef struct {
    uint64_t stack_addr, stack_len;   /* page-aligned */
    uint64_t code_addr,  code_len;    /* page-aligned */
    uint64_t stack_checksum;
    regs_t   regs;
} checkpoint_header_t;

static long g_pagesize;
static barrier_woa_t g_barrier;
static regs_t g_regs;
static uint64_t g_stack_addr, g_stack_len;
static uint64_t g_code_addr, g_code_len;
static uint8_t stack_chunk_buf[STACK_CHUNK_BYTES];
static uint8_t code_chunk_buf[CODE_CHUNK_BYTES];

uint64_t floor_to_page(uint64_t addr) {
    return addr & ~(uint64_t)(g_pagesize - 1);
}

static uint64_t probe_contiguous_len(uint64_t start, uint64_t budget) {
    uint64_t total = 0;
    uint64_t addr = start;
    while (total < budget) {
        mach_vm_address_t a = addr;
        mach_vm_size_t size = 0;
        natural_t depth = 32;
        vm_region_submap_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        kern_return_t kr = mach_vm_region_recurse(mach_task_self(), &a, &size, &depth,
                                                   (vm_region_recurse_info_t)&info, &count);
        if (kr != KERN_SUCCESS) break;   /* no more regions at all */
        if ((uint64_t)a != addr) break;  /* gap right here -- stop, don't jump over it */
        uint64_t take = size;
        if (total + take > budget) take = budget - total;
        total += take;
        if (take < size) break; /* hit budget mid-region */
        addr += size;
    }
    return total;
}

void capture_state(int sig, siginfo_t* info, void* ctx) {
    (void)sig; (void)info;
    g_regs.gregs = ((ucontext_t*)ctx)->uc_mcontext->__ss;
    g_regs.neon = ((ucontext_t*)ctx)->uc_mcontext->__ns;
    __asm__ volatile ("mrs %0, tpidr_el0" : "=r" (g_regs.tpidr));

    g_stack_addr = floor_to_page(g_regs.gregs.__sp);
    g_stack_len  = probe_contiguous_len(g_stack_addr, STACK_CHUNK_BYTES);
    if (g_stack_len == 0) g_stack_len = (uint64_t)g_pagesize; /* couldn't confirm bounds -- smallest safe guess */
    if (g_stack_len > sizeof(stack_chunk_buf)) g_stack_len = sizeof(stack_chunk_buf);
    memcpy(stack_chunk_buf, (void*)(uintptr_t)g_stack_addr, g_stack_len);

    g_code_addr = floor_to_page(g_regs.gregs.__pc);
    g_code_len  = probe_contiguous_len(g_code_addr, CODE_CHUNK_BYTES);
    if (g_code_len == 0) g_code_len = (uint64_t)g_pagesize;
    if (g_code_len > sizeof(code_chunk_buf)) g_code_len = sizeof(code_chunk_buf);
    memcpy(code_chunk_buf, (void*)(uintptr_t)g_code_addr, g_code_len);

    barrier_wait(&g_barrier);
}

static void* worker_fn(void* arg) {
    (void)arg;
    printf("worker started %d\n", getpid());
    barrier_wait(&g_barrier);
    
    volatile uint64_t counter = 0;
    volatile uint32_t hits = 0;
    char msg[] = "reached 100000000ULL iters, restarting\n";
    for (;;) {
        counter++;
        if (counter == WORKER_ITERS) {
            write(STDOUT_FILENO, msg, sizeof(msg) - 1);
            counter = 0;
            hits++;
        }

        if (hits == 3) {
            printf("worker exiting %d\n", getpid());
            _exit(0);
        }
    }
    
    return NULL; /* unreachable */
}

static uint64_t simple_checksum(const void* buf, size_t len) {
    const uint8_t *p = buf;
    uint64_t sum = 0;
    for (size_t i = 0; i < len; i++) sum = sum * 31 + p[i];
    
    return sum;
}

static int do_checkpoint(const char* path) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_flags = SA_SIGINFO;
    sa.__sigaction_u.__sa_sigaction = capture_state;
    if (sigaction(SIGUSR1, &sa, NULL) == -1) { perror("sigaction"); return 1; }

    pthread_t worker;
    if (pthread_create(&worker, NULL, worker_fn, NULL) != 0) { perror("pthread_create"); return 1; }

    barrier_wait(&g_barrier);
    usleep(150000);

    if (pthread_kill(worker, SIGUSR1) != 0) { perror("pthread_kill"); return 1; }

    barrier_wait(&g_barrier);

    uint64_t checksum = simple_checksum(stack_chunk_buf, g_stack_len);

    FILE* f = fopen(path, "wb");
    if (!f) { perror("fopen"); return 1; }
    checkpoint_header_t hdr = {
        .stack_addr = g_stack_addr, .stack_len = g_stack_len,
        .code_addr  = g_code_addr,  .code_len  = g_code_len,
        .stack_checksum = checksum,
        .regs = g_regs,
    };
    fwrite(&hdr, sizeof(hdr), 1, f);
    fwrite(stack_chunk_buf, 1, g_stack_len, f);
    fwrite(code_chunk_buf, 1, g_code_len, f);
    fclose(f);

    printf("checkpoint written to %s\n", path);
    printf("  stack [0x%llx, 0x%llx] checksum=0x%llx\n",
           g_stack_addr, g_stack_addr + g_stack_len, checksum);
    printf("  code  [0x%llx, 0x%llx]\n",
           g_code_addr, g_code_addr + g_code_len);
    printf("  pc=0x%llx sp=0x%llx\n",
           g_regs.gregs.__pc, g_regs.gregs.__sp);
    
    pthread_detach(worker); /* let it run to completion on its own; we no longer need it */
    
    return 0;
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\n", argv[0]);
        return 2;
    }

    g_pagesize = sysconf(_SC_PAGESIZE);
    barrier_create(&g_barrier, 2);

    return do_checkpoint(argv[1]);
}