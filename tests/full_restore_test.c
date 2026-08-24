#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <mach/thread_state.h>
#include <sys/mman.h>
#include <errno.h>
#include <signal.h>

#define MAX_REGIONS       256
#define CAPTURE_BUF_BYTES (512u * 1024 * 1024)  // 512MB

typedef struct regs {
    arm_thread_state64_t gregs;
    arm_neon_state64_t neon;
    uint64_t tpidr;
} regs_t;

typedef struct {
    uint64_t addr, len;      /* page-aligned, as reported by the kernel */
    uint32_t protection;     /* VM_PROT_* bits -- same values as PROT_* */
    uint32_t _pad;
} region_desc_t;

/* Must match full_capture_test.c's checkpoint_header_t byte-for-byte. */
typedef struct {
    uint32_t region_count;
    uint32_t _pad;
    uint64_t capture_used;      /* bytes actually copied into g_capture_buf */
    regs_t   regs;
} checkpoint_header_t;

static regs_t g_regs;
static region_desc_t g_regions[MAX_REGIONS];
/* An explicit mmap(), not a static/BSS array (2026-08-25 -- found the hard
 * way while building thread_restore_test.c, which copied this file's shape
 * verbatim): a static array here can land at *any* address the linker
 * happens to choose, with nothing excluding it from remap_regions()'s own
 * MAP_FIXED targets the way should_capture() excludes the capture side's
 * own scratch buffer (full_capture_test.c, 2026-08-21). Unlike the guard-
 * page/shared-cache collisions, MAP_FIXED overwriting this buffer doesn't
 * fail with ENOMEM -- it's an ordinary mapping, so MAP_FIXED just silently
 * replaces it, corrupting g_capture_buf's own bytes mid-copy if a captured
 * region's original address happens to overlap wherever this buffer landed.
 * An explicit mmap() is a genuinely separate vm_map entry (confirmed
 * 2026-08-21 to land tens of MB away from everything else), making that
 * collision far less likely -- not impossible, same as any other address,
 * but no longer trivially likely to be right next to our own image. */
static uint8_t* g_capture_buf;
static const uint64_t g_capture_buf_cap = CAPTURE_BUF_BYTES;

static int remap_regions(uint32_t region_count) {
    uint64_t offset = 0;
    for (uint32_t i = 0; i < region_count; i++) {
        uint64_t addr = g_regions[i].addr;
        uint64_t len = g_regions[i].len;
        int prot = (int)g_regions[i].protection;

        /* mmap RW unconditionally, memcpy the captured bytes in, *then*
         * mprotect to the region's real recorded protection -- mapping
         * straight to the final (possibly read-only, or r-x for code)
         * protection and then memcpy()ing into it would fault. Same shape
         * as sim_noaslr_restore_test.c's code-chunk restore. */
        void* got = mmap((void*)(uintptr_t)addr, len, PROT_READ | PROT_WRITE,
                         MAP_FIXED | MAP_ANON | MAP_PRIVATE, -1, 0);
        if (got == MAP_FAILED) {
            int saved_errno = errno;
            fprintf(stderr, "mmap failed for region[%u] [0x%llx,0x%llx): %s\n",
                    i, addr, addr + len, strerror(saved_errno));
            if (saved_errno == ENOMEM) {
                /* The known MALLOC-guard-page collision (NOTES.md 2026-08-14
                 * onward) -- with a whole process's worth of fixed-address
                 * regions instead of just two, this is now the common case,
                 * not the rare one (measured 2026-08-21: 0/8 attempts
                 * succeeded without retrying). Exit EX_TEMPFAIL so
                 * `spawn_noaslr -r <n>` retries in a fresh process, same
                 * convention sim_noaslr_restore_test.c already uses. */
                fprintf(stderr, "  exiting EX_TEMPFAIL for a retry wrapper to try a fresh process\n");
                exit(EX_TEMPFAIL);
            }
            return 1; /* not the known collision signature -- a real bug, don't retry */
        }
        if ((uint64_t)(uintptr_t)got != addr) {
            fprintf(stderr, "mmap did not honor the fixed address for region[%u]: got 0x%llx, expected 0x%llx\n",
                    i, (uint64_t)(uintptr_t)got, (uint64_t)addr);
            return 1;
        }

        memcpy(got, g_capture_buf + offset, len);
        offset += len;

        if (prot != (PROT_READ | PROT_WRITE) && mprotect(got, len, prot) != 0) {
            fprintf(stderr, "mprotect failed for region[%u] [0x%llx,0x%llx): %s\n",
                    i, addr, addr + len, strerror(errno));
            return 1;
        }
    }
    return 0;
}

void restore_state(int sig, siginfo_t* info, void* ctx) {
    (void)sig; (void)info;
    ((ucontext_t*)ctx)->uc_mcontext->__ss = g_regs.gregs;
    ((ucontext_t*)ctx)->uc_mcontext->__ns = g_regs.neon;
    __asm__ volatile ("msr tpidr_el0, %0" :: "r" (g_regs.tpidr));
}

static int do_restore(const char* path) {
    FILE* f = fopen(path, "rb");
    if (!f) { perror("fopen"); return 1; }
    printf("restoring from %s\n", path);

    checkpoint_header_t hdr;
    if (fread(&hdr, sizeof(hdr), 1, f) != 1) { 
        fprintf(stderr, "short read on header\n"); 
        fclose(f); 
        return 1; 
    }
    if (hdr.region_count > MAX_REGIONS) {
        fprintf(stderr, "region count %u exceeds MAX_REGIONS %u\n", hdr.region_count, MAX_REGIONS);
        fclose(f);
        return 1;
    }
    if (hdr.capture_used > g_capture_buf_cap) {
        fprintf(stderr, "capture_used %llu exceeds buffer capacity %llu\n", hdr.capture_used, g_capture_buf_cap);
        fclose(f);
        return 1;
    }
    if (fread(g_regions, sizeof(region_desc_t), hdr.region_count, f) != hdr.region_count) {
        fprintf(stderr, "short read on region descriptors\n");
        fclose(f);
        return 1;
    }
    /* Cross-check hdr.capture_used against what the region list itself
     * implies -- catches a corrupt/mismatched file instead of trusting a
     * single stored number blindly. */
    uint64_t region_total = 0;
    for (uint32_t i = 0; i < hdr.region_count; i++) region_total += g_regions[i].len;
    if (region_total != hdr.capture_used) {
        fprintf(stderr, "capture_used (%llu) doesn't match sum of region lengths (%llu) -- corrupt file?\n",
                hdr.capture_used, region_total);
        fclose(f);
        return 1;
    }
    if (fread(g_capture_buf, 1, hdr.capture_used, f) != hdr.capture_used) {
        fprintf(stderr, "short read on capture buffer\n");
        fclose(f);
        return 1;
    }
    fclose(f);

    printf("read %u regions, %.2f MB, pc=0x%llx sp=0x%llx\n",
           hdr.region_count, hdr.capture_used / 1048576.0,
           hdr.regs.gregs.__pc, hdr.regs.gregs.__sp);

    if (remap_regions(hdr.region_count) != 0) {
        fprintf(stderr, "failed to remap regions\n");
        return 1;
    }

    g_regs = hdr.regs;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_flags = SA_SIGINFO;
    sa.__sigaction_u.__sa_sigaction = restore_state;
    if (sigaction(SIGUSR1, &sa, NULL) == -1) { perror("sigaction"); return 1; }

    raise(SIGUSR1); // Trigger the signal to restore state

    fprintf(stderr, "restore_state should not return\n");
    return 1; // If we reach here, something went wrong
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\n", argv[0]);
        return 2;
    }

    g_capture_buf = mmap(NULL, CAPTURE_BUF_BYTES, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (g_capture_buf == MAP_FAILED) { perror("mmap capture buffer"); return 1; }

    return do_restore(argv[1]);

}