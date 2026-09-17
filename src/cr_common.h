/* AI-assistance disclosure: developed with the assistance of Claude
 * (Anthropic) as a coding assistant, under the author's direction, review,
 * and testing. Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
 */
/* cr_common.h -- shared wire format and cross-cutting helpers for the
 * macOS/arm64e checkpoint & restore prototype. The contract between
 * cr_capture.c and cr_restore.c: change a struct here and both sides
 * rebuild against the same layout instead of drifting apart.
 */
#ifndef CR_COMMON_H
#define CR_COMMON_H

#if !__has_feature(ptrauth_calls)
#error "build with -arch arm64e -- every checkpoint/restore file needs real PAC"
#endif

#include <stdbool.h>
#include <stdint.h>
#include <mach/thread_state.h>
#include <mach/mach_vm.h>

#define MAX_REGIONS 256

/* crac_daemon's process name (tests/crac_daemon.c), the PAC-key anchor. */
#define CRAC_DAEMON_NAME "crac_daemon"

typedef struct regs {
    arm_thread_state64_t gregs;
    arm_neon_state64_t neon;
    uint64_t tpidr;
} regs_t;

typedef struct {
    uint64_t addr, len;
    uint32_t protection;
} region_desc_t;

typedef struct {
    regs_t   regs;
    uint64_t pthread_addr;
} thread_desc_t;

/* On-disk layout: this header, then thread_desc_t[thread_count], then
 * region_desc_t[region_count], then the flat capture buffer
 * (capture_used bytes). */
typedef struct {
    uint32_t thread_count;
    uint32_t region_count;
    uint64_t capture_used;  // total bytes across all regions
    uint64_t munge;         // capturing process's live pthread munge
    uint64_t sentinel;
    int32_t  daemon_pid;    // crac_daemon pid alive at capture time
} checkpoint_header_t;

/* Same (addr, key, discriminator) triple as libpthread's own signature
 * helpers -- must match exactly for the munge XOR-recovery to work. */
uintptr_t sign_for_addr(uintptr_t addr);

/* Shared-cache detection, used by both capture (skip immutable cache pages)
 * and restore (pick which remap pass handles a region). */
bool in_shared_cache_submap(mach_vm_address_t addr);
bool in_shared_cache_range(mach_vm_address_t addr);

/* The two public entry points -- one per driver binary. */
int do_capture(const char* path);
int do_restore(const char* path);

#endif /* CR_COMMON_H */
