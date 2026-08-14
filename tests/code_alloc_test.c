#include <stdio.h>
#include <signal.h>
#include <mach/thread_state.h>
#include <mach/mach_vm.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>

static long g_pagesize;
static uint64_t pc_r;
static uint64_t pc;


uint64_t floor_to_page(uint64_t addr) {
    return addr & ~(uint64_t)(g_pagesize - 1);
}

int do_checkpoint(const char* path) {
    printf("writing PC page: 0x%llx (pc=%llx)\n", pc_r, pc);

    FILE* f = fopen(path, "wb");
    if (!f) { perror("fopen"); return 1; }
    if (fwrite(&pc_r, sizeof(pc_r), 1, f) != 1) { perror("fwrite"); return 1; }
    fclose(f);
    
    printf("checkpoint written to %s (SUCCESS)\n", path);
    return 0;
}

bool is_range_free(uint64_t addr, uint64_t len) {
    mach_vm_address_t region_addr = addr;
    for (;;) {
        mach_vm_address_t a = region_addr;
        mach_vm_size_t region_size = 0;
        natural_t depth = 32;
        vm_region_submap_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        kern_return_t kr = mach_vm_region_recurse(mach_task_self(), &a, &region_size,
                                          &depth, (vm_region_info_t)&info,
                                          &count);
        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "mach_vm_region failed: %s\n", mach_error_string(kr));
            return false;
        }
        if (a >= addr + len) {
            printf("range [0x%llx, 0x%llx) is free\n", (uint64_t)addr, (uint64_t)(addr + len));
            return true; /* reached the end of the range without finding a collision */
        }
        if (a + region_size > addr) {
            printf("collision: target [0x%llx,0x%llx] overlaps existing region "
                    "[0x%llx,0x%llx] protection=%d is_submap=%d depth=%u object_id=%u share_mode=%d behavior=%d\n",
                    (uint64_t)addr, (uint64_t)(addr + len),
                    (uint64_t)a, (uint64_t)(a + region_size), info.protection,
                    info.is_submap, depth, info.object_id, info.share_mode, info.behavior);
            return false; /* found a collision */
        }
        region_addr += region_size;
    }
}

void handler(int signum) {
    printf("received signal %d, resuming\n", signum);
}

/* depth=0: don't descend into submaps -- shows the raw top-level map entry,
 * which mach_vm_region_recurse at depth=32 (is_range_free above) may have
 * already resolved past or dissolved. If the two disagree, that's the
 * submap-boundary artifact the 2026-08-11 nesting_depth investigation
 * already taught us to expect from this API. */
void dump_shallow(uint64_t addr, uint64_t len) {
    mach_vm_address_t a = addr;
    mach_vm_size_t region_size = 0;
    natural_t depth = 0;
    vm_region_submap_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
    kern_return_t kr = mach_vm_region_recurse(mach_task_self(), &a, &region_size,
                                      &depth, (vm_region_info_t)&info, &count);
    if (kr != KERN_SUCCESS) {
        printf("  DIAG depth=0 probe: mach_vm_region_recurse failed: %s\n", mach_error_string(kr));
        return;
    }
    printf("  DIAG depth=0 probe: region [0x%llx,0x%llx] protection=%d is_submap=%d "
           "object_id=%u share_mode=%d behavior=%d (target [0x%llx,0x%llx])\n",
           (uint64_t)a, (uint64_t)(a + region_size), info.protection, info.is_submap,
           info.object_id, info.share_mode, info.behavior, (uint64_t)addr, (uint64_t)(addr + len));
}

/* Directly tests the proximity-to-own-__TEXT hypothesis, controlled rather
 * than relying on ASLR to hand us varying distances across many launches.
 * Sweeps a range of KNOWN offsets (in pages) above and below this
 * process's own __TEXT page, in a single run, and for each: checks the
 * scanner's "is it free" verdict, then actually attempts mmap(MAP_FIXED)
 * there. If proximity is really the deciding factor, failures should
 * cluster at small |offset| and successes should appear once far enough
 * away, regardless of what the scanner alone says. */
void sweep_distance(void) {
    uint64_t own_page = floor_to_page((uint64_t)&do_checkpoint); /* already declared above main() */
    printf("own __TEXT page: 0x%llx\n\n", (unsigned long long)own_page);

    int64_t offsets[] = {
        1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
        -1, -2, -4, -8, -16, -32, -64, -128, -256, -512, -1024, -2048, -4096, -8192, -16384, -32768, -65536
    };
    size_t n = sizeof(offsets) / sizeof(offsets[0]);

    for (size_t i = 0; i < n; i++) {
        int64_t off_pages = offsets[i];
        uint64_t candidate = (uint64_t)((int64_t)own_page + off_pages * (int64_t)g_pagesize);

        printf("--- offset %+lld pages (0x%llx) ---\n", (long long)off_pages, (unsigned long long)candidate);
        bool clean = is_range_free(candidate, g_pagesize);

        if (!clean) {
            /* Never blindly mmap a known collision -- at small offsets this
             * is our OWN process's adjacent __DATA_CONST/GOT page, and
             * MAP_FIXED-ing over memory our own next library call still
             * needs crashes immediately (confirmed the hard way: this exact
             * loop crashed here before this guard existed, same "don't
             * unmap what your own code depends on" hazard as
             * submap_exec_test.c on 2026-08-12). */
            printf("RESULT offset=%+lld clean=0 mmap=SKIPPED\n\n", (long long)off_pages);
            continue;
        }

        void *got = mmap((void*)(uintptr_t)candidate, g_pagesize, PROT_READ | PROT_WRITE,
                          MAP_FIXED | MAP_ANON | MAP_PRIVATE, -1, 0);
        bool ok = (got != MAP_FAILED) && ((uint64_t)(uintptr_t)got == candidate);
        printf("RESULT offset=%+lld clean=1 mmap=%s\n\n",
               (long long)off_pages, ok ? "SUCCESS" : "FAIL");
        if (ok) {
            munmap(got, (size_t)g_pagesize); /* give it back -- don't let an early success affect later probes */
        }
    }
}

int check_map(const char* path) {
    
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.__sigaction_u.__sa_handler = handler;

    sigaction(SIGINT, &sa, NULL);

    FILE* f = fopen(path, "rb");
    if (!f) { perror("fopen"); return 1; }
    uint64_t read_pc_r;
    if (fread(&read_pc_r, sizeof(read_pc_r), 1, f) != 1) { perror("fread"); return 1; }
    fclose(f);
    printf("read PC page: 0x%llx, own pc region: 0x%llx, pc=%llx\n", read_pc_r, pc_r, pc);


    
    printf("mmap()ing PC page: 0x%lx\n%s\n", (unsigned long)read_pc_r,
           is_range_free(read_pc_r, g_pagesize) ? "  target range is free" : "  target range COLLISION");
    dump_shallow(read_pc_r, g_pagesize);

    printf("pid of the process: %d\n", getpid());
    pause();

    void *got = mmap((void*)(uintptr_t)read_pc_r, g_pagesize, PROT_READ | PROT_WRITE,
                   MAP_FIXED | MAP_ANON | MAP_PRIVATE, -1, 0);
    if (got == MAP_FAILED) { 
        perror("mmap"); 
    } else if ((uint64_t)(uintptr_t)got != read_pc_r) {
        fprintf(stderr, "MAP_FIXED did not honor the PC page address\n"); return 1;
    } else {
        printf("SUCCESS! mmap()ed PC page at 0x%lx\n", (uintptr_t)got);
    }


    return 0;
}

int main (int argc, char* argv[]) {

    if (argc < 2) {
        fprintf(stderr, "usage: %s checkpoint|restore <file> | sweep\n", argv[0]);
        return 2;
    }

    setvbuf(stdout, NULL, _IONBF, 0); /* a crash mid-run must not eat prior output */

    g_pagesize = sysconf(_SC_PAGESIZE);
    printf("page size: %ld\n", (long)g_pagesize);

    if (strcmp(argv[1], "sweep") == 0) {
        sweep_distance();
        return 0;
    }

    if (argc < 3) {
        fprintf(stderr, "usage: %s checkpoint|restore <file> | sweep\n", argv[0]);
        return 2;
    }

    if (strcmp(argv[1], "checkpoint") == 0) {
        pc = (uint64_t)&main;
        pc_r = floor_to_page(pc);
        return do_checkpoint(argv[2]);
    }
    if (strcmp(argv[1], "restore") == 0) {
        pc = (uint64_t)&main;
        pc_r = floor_to_page(pc);
        return check_map(argv[2]);
    }
    fprintf(stderr, "unknown command: %s\n", argv[1]);
    return 2;
}