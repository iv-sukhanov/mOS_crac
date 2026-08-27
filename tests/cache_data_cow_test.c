/* Does mmap(MAP_FIXED) (and the VM-primitive escalation battery already
 * used against the malloc guard page, NOTES.md 2026-08-17) behave
 * differently against a shared-cache __DATA page that's already been
 * copy-on-write-privatized (external_pager=0), vs. one still backed by the
 * cache file (external_pager=1)? That's the distinction 2026-08-21's
 * full_restore_test.c EACCES finding rests on -- "regular, file-backed
 * shared cache is overridable" is already established (docs/003); this
 * probes the privatized case specifically.
 *
 * First cut of this file tried self-triggering a CoW (read a candidate's
 * first byte, write it straight back) and testing that -- both the
 * pristine and the self-CoW'd page overrode cleanly, no EACCES either way.
 * Turned out to be probing the wrong state: the self-triggered page still
 * read external_pager=1 afterward (only `pages_shared_now_private` had
 * moved), but Ivan's fresh repro of the real bug confirms the actual
 * failing region reads external_pager=0 -- a different, apparently more
 * thorough kind of privatization than one in-place same-value store
 * produces. This version goes straight at that: the *exact* address from
 * a live repro (`mmap failed for region[15] [0x2e48d8000,0x2e48dc000):
 * Permission denied`, Ivan, this session), plus a general scan for any
 * naturally-occurring external_pager=0 cache-range page (dyld's own
 * startup binding privatizes some before main() ever runs -- confirmed
 * empirically by the first cut's control scan finding only a handful of
 * external_pager=1 survivors process-wide).
 */
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/task.h>
#include <mach-o/dyld_images.h>

/* Ivan's live repro this session, same boot session (the cache's address
 * is boot-session-stable, docs/003) -- if that holds, this exact address
 * should land on the same real, already-privatized page in this process
 * too, not just in full_restore_test.c's. */
#define KNOWN_FAILING_ADDR 0x2e48d8000ull
#define KNOWN_FAILING_LEN  0x4000ull

/* __pthread_head's real address, this session (2026-08-26): disassembling
 * pthread_kill (lldb) shows it walking a linked list rooted at a fixed
 * global -- `adrp x8, 443089; ldr x8, [x8, #0x20]`, then following [x8,#0x10]
 * next-pointers, returning ESRCH (3) if the target is never found. That
 * page (443089) also holds a symbol lldb still resolves, _pthread_list_lock
 * (`adrp x0, 443089; add x0, x0, #0x6c`) -- `p/x &_pthread_list_lock` gave
 * 0x1f616406c, so the list head is at that address minus (0x6c - 0x20).
 * Same boot session as everything else in this file -- expected stable. */
#define PTHREAD_LIST_LOCK_ADDR 0x1f616406cull
#define PTHREAD_HEAD_ADDR      (PTHREAD_LIST_LOCK_ADDR - 0x6c + 0x20)
#define PTHREAD_HEAD_LEN       0x8ull /* one pointer */

/* Verbatim from full_capture_test.c (2026-08-21) -- same address-range
 * check, reused rather than re-derived. */
#define CACHE_SPAN_BYTES (8ull * 1024 * 1024 * 1024)
static bool in_shared_cache_range(mach_vm_address_t addr) {
    task_dyld_info_data_t info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    if (task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&info, &count) != KERN_SUCCESS) return false;
    struct dyld_all_image_infos* infos = (struct dyld_all_image_infos*)(uintptr_t)info.all_image_info_addr;
    uint64_t base = (uint64_t)infos->sharedCacheBaseAddress;
    return base != 0 && (uint64_t)addr >= base && (uint64_t)addr < base + CACHE_SPAN_BYTES;
}

static bool region_at(mach_vm_address_t addr, mach_vm_address_t* out_addr, mach_vm_size_t* out_size,
                       vm_region_submap_info_data_64_t* out_info) {
    mach_vm_address_t a = addr;
    mach_vm_size_t size = 0;
    natural_t depth = 32;
    mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
    kern_return_t kr = mach_vm_region_recurse(mach_task_self(), &a, &size, &depth,
                                               (vm_region_recurse_info_t)out_info, &count);
    if (kr != KERN_SUCCESS) return false;
    *out_addr = a;
    *out_size = size;
    return true;
}

/* depth=0 (don't descend) -- if `addr` is still inside a nested submap,
 * this reports the submap's own boundary (is_submap=1), not the leaf
 * content depth=32 resolves to. Distinguishes "still nested in the cache's
 * own submap structure" from "fully detached, now an ordinary top-level
 * entry" -- the same technique as full_capture_test.c's
 * in_shared_cache_submap(), just surfaced here for direct comparison. */
static void print_nesting(const char* label, mach_vm_address_t addr) {
    mach_vm_address_t a = addr;
    mach_vm_size_t size = 0;
    natural_t depth = 0;
    vm_region_submap_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
    kern_return_t kr = mach_vm_region_recurse(mach_task_self(), &a, &size, &depth,
                                               (vm_region_recurse_info_t)&info, &count);
    if (kr != KERN_SUCCESS) { printf("  [%s] depth=0 query failed: kr=%d\n", label, kr); return; }
    printf("  [%s] depth=0: is_submap=%d boundary=[0x%llx,0x%llx)\n",
           label, info.is_submap, a, a + size);
}

/* VM_REGION_FLAG_JIT_ENABLED/TPRO_ENABLED (mach/vm_region.h) -- TPRO
 * ("Transparent Page-level Read-Only") is a newer, distinct hardening
 * mechanism from the VM_FLAGS_PERMANENT sealing already confirmed on
 * malloc's guard page (NOTES.md 2026-08-17): a region can be marked so
 * writes are only permitted through a special, deliberate unlock call
 * (os_thread_self_restrict_tpro_to_rw()), not through ordinary VM
 * primitives at all -- which would explain both "mprotect still refuses"
 * (same observable outcome as VM_FLAGS_PERMANENT) and the *different*
 * kern_return_t codes measured for the OVERWRITE variants (this session's
 * finding) -- a genuinely different mechanism landing on a similar-looking
 * refusal, not the same flag re-triggering. */
static void print_info(const char* label, mach_vm_address_t addr, mach_vm_size_t size,
                        const vm_region_submap_info_data_64_t* info) {
    printf("[%s] addr=0x%llx size=0x%llx protection=%d external_pager=%d "
           "share_mode=%u pages_shared_now_private=%u user_tag=%u flags=0x%x (JIT=%d TPRO=%d) "
           "in_cache_range=%d\n",
           label, addr, size, info->protection, info->external_pager, info->share_mode,
           info->pages_shared_now_private, info->user_tag, info->flags,
           (info->flags & VM_REGION_FLAG_JIT_ENABLED) != 0,
           (info->flags & VM_REGION_FLAG_TPRO_ENABLED) != 0,
           in_shared_cache_range(addr));
}

/* Full leaf-level scan (depth=32, like full_capture_test.c's
 * classify_regions()) for the first writable, cache-range page whose
 * external_pager matches `want_pager` -- reused for both the "already
 * privatized" and "still file-backed" searches, one predicate. */
static bool find_first(bool want_pager, mach_vm_size_t max_size, mach_vm_address_t* out_addr,
                        mach_vm_size_t* out_size, vm_region_submap_info_data_64_t* out_info) {
    mach_vm_address_t addr = 0;
    for (;;) {
        mach_vm_address_t a; mach_vm_size_t size;
        vm_region_submap_info_data_64_t info;
        if (!region_at(addr, &a, &size, &info)) return false;
        if ((info.protection & VM_PROT_WRITE) && (bool)info.external_pager == want_pager
            && size <= max_size && in_shared_cache_range(a)) {
            *out_addr = a; *out_size = size; *out_info = info;
            return true;
        }
        addr = a + size;
    }
}

/* Same escalation battery as sim_noaslr_restore_test.c's
 * try_reclaim_stuck_range() (2026-08-17/21), reused here against a
 * shared-cache page instead of a malloc guard page. Every step's result
 * gets printed regardless, stopping only once one actually succeeds. */
static const char* run_battery(mach_vm_address_t addr, mach_vm_size_t len) {
    mach_vm_address_t a;
    kern_return_t kr;

    void* got = mmap((void*)(uintptr_t)addr, (size_t)len, PROT_READ | PROT_WRITE,
                      MAP_FIXED | MAP_ANON | MAP_PRIVATE, -1, 0);
    printf("  try mmap(MAP_FIXED): %s\n", got != MAP_FAILED ? "ok" : strerror(errno));
    if (got != MAP_FAILED) return "mmap(MAP_FIXED)";

    a = addr;
    kr = mach_vm_allocate(mach_task_self(), &a, len, VM_FLAGS_FIXED);
    printf("  try mach_vm_allocate(FIXED): kr=%d\n", kr);
    if (kr == KERN_SUCCESS) return "mach_vm_allocate(VM_FLAGS_FIXED)";

    a = addr;
    kr = mach_vm_allocate(mach_task_self(), &a, len, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE);
    printf("  try mach_vm_allocate(FIXED|OVERWRITE): kr=%d\n", kr);
    if (kr == KERN_SUCCESS) return "mach_vm_allocate(VM_FLAGS_FIXED|VM_FLAGS_OVERWRITE)";

    a = addr;
    kr = mach_vm_map(mach_task_self(), &a, len, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                      MACH_PORT_NULL, 0, FALSE,
                      VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE,
                      VM_INHERIT_DEFAULT);
    printf("  try mach_vm_map(FIXED|OVERWRITE): kr=%d\n", kr);
    if (kr == KERN_SUCCESS) return "mach_vm_map(VM_FLAGS_FIXED|VM_FLAGS_OVERWRITE)";

    uint8_t probe_bytes[16] = {0};
    kr = mach_vm_write(mach_task_self(), addr, (vm_offset_t)probe_bytes, sizeof(probe_bytes));
    printf("  try mach_vm_write (no mprotect first): kr=%d\n", kr);
    if (kr == KERN_SUCCESS) return "mach_vm_write (bypassing protection)";

    int mp = mprotect((void*)(uintptr_t)addr, (size_t)len, PROT_READ | PROT_WRITE);
    printf("  try mprotect(RW): rc=%d errno=%d (%s)\n", mp, mp == 0 ? 0 : errno, mp == 0 ? "ok" : strerror(errno));
    if (mp == 0) {
        got = mmap((void*)(uintptr_t)addr, (size_t)len, PROT_READ | PROT_WRITE,
                    MAP_FIXED | MAP_ANON | MAP_PRIVATE, -1, 0);
        printf("  try mmap(MAP_FIXED) after mprotect(RW): %s\n", got != MAP_FAILED ? "ok" : strerror(errno));
        if (got != MAP_FAILED) return "mmap(MAP_FIXED) after mprotect(RW)";
    }

    return NULL;
}

/* Does ordinary pthread machinery (create + join a real thread) still work
 * after an override attempt? A "success" return code from mach_vm_allocate
 * alone isn't trusted at face value here -- same standard as everywhere
 * else this session. Bounded by alarm() so a genuine corruption hangs this
 * check instead of the whole process. */
static void alarm_handler(int sig) { (void)sig; _exit(2); }
static void* liveness_thread_fn(void* arg) { (void)arg; return NULL; }

/* First cut used liveness_thread_fn (returns immediately) as the sentinel
 * for the __pthread_head before/after check -- got ESRCH even BEFORE
 * touching anything, because it had almost certainly already finished and
 * deregistered by the time pthread_kill ran (joinable keeps the exit
 * status retrievable, evidently not the same as still being *live* in
 * __pthread_head). This one blocks until explicitly told to stop, so it
 * stays genuinely registered for the whole test. */
static atomic_int g_stop_sentinel = 0;
static void* sentinel_thread_fn(void* arg) {
    (void)arg;
    while (!atomic_load(&g_stop_sentinel)) usleep(10000);
    return NULL;
}
static void check_pthread_still_works(const char* label) {
    signal(SIGALRM, alarm_handler);
    alarm(5);
    pthread_t t;
    int rc = pthread_create(&t, NULL, liveness_thread_fn, NULL);
    if (rc == 0) rc = pthread_join(t, NULL);
    alarm(0);
    printf("liveness check after %s: pthread_create+join %s (rc=%d)\n",
           label, rc == 0 ? "PASSED -- pthread machinery still works" : "FAILED", rc);
}

static void test_one(const char* label, mach_vm_address_t addr, mach_vm_size_t size,
                      const vm_region_submap_info_data_64_t* info) {
    printf("\n=== %s ===\n", label);
    print_info(label, addr, size, info);
    print_nesting(label, addr);
    const char* r = run_battery(addr, size);
    printf("RESULT: %s\n", r ? r : "EVERY METHOD FAILED");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    /* Optional pause before anything gets touched, so vmmap can be run
     * externally against this process's still-pristine state -- same
     * convention as sim_noaslr_restore_test.c's MOS_CRAC_PAUSE_ON_COLLISION. */
    if (getenv("MOS_CRAC_PAUSE")) {
        printf("PAUSED: pid=%d -- run: vmmap -interleaved %d\n", getpid(), getpid());
        pause();
    }

    /* 1. The exact address from Ivan's live repro this session. */
    vm_region_submap_info_data_64_t known_info;
    mach_vm_address_t known_addr; mach_vm_size_t known_size;
    if (region_at(KNOWN_FAILING_ADDR, &known_addr, &known_size, &known_info)
        && known_addr <= KNOWN_FAILING_ADDR && KNOWN_FAILING_ADDR < known_addr + known_size) {
        test_one("known failing address (region[15] from full_restore_test.c)",
                  KNOWN_FAILING_ADDR, KNOWN_FAILING_LEN, &known_info);

        /* vmmap showed r--/r-- for this page -- max_protection excludes
         * WRITE entirely. Every battery step above asked for RW. If that's
         * the whole story (not a special hardening flag, just an ordinary
         * protection ceiling), a READ-ONLY override should succeed cleanly. */
        void* got = mmap((void*)(uintptr_t)KNOWN_FAILING_ADDR, (size_t)KNOWN_FAILING_LEN,
                          PROT_READ, MAP_FIXED | MAP_ANON | MAP_PRIVATE, -1, 0);
        printf("  try mmap(MAP_FIXED, PROT_READ only): %s\n", got != MAP_FAILED ? "ok" : strerror(errno));

        /* Even more targeted: mprotect(PROT_READ) -- a no-op re-assertion
         * of the protection this entry ALREADY has (r--/r-- per vmmap), not
         * an attempted increase. If this still fails, the entry itself is
         * unconditionally sealed against any modification, independent of
         * protection semantics entirely -- not just "asked for too much". */
        int mp = mprotect((void*)(uintptr_t)KNOWN_FAILING_ADDR, (size_t)KNOWN_FAILING_LEN, PROT_READ);
        printf("  try mprotect(PROT_READ, a no-op re-assertion): rc=%d errno=%d (%s)\n",
               mp, mp == 0 ? 0 : errno, mp == 0 ? "ok" : strerror(errno));
    } else {
        printf("known failing address 0x%llx isn't inside a mapped region here "
               "(cache slide differs from that repro's process -- not boot-session-stable "
               "after all, or something else moved) -- skipping\n", KNOWN_FAILING_ADDR);
    }

    /* 1b. __pthread_head itself -- the actual thing gap #1 needs. A fresh
     * create+join *after* the override isn't decisive on its own -- it'd
     * look identical whether we corrupted nothing, or wiped the list to
     * empty and it just re-populates fine from there. The real test:
     * register a thread *before* the override, confirm pthread_kill(sig=0
     * -- existence check, delivers nothing) finds it, override, then check
     * again -- this is the actual scenario restore needs (does a pre-
     * existing registration survive), not just "can new threads register." */
    pthread_t sentinel;
    pthread_create(&sentinel, NULL, sentinel_thread_fn, NULL);
    usleep(20000); /* let it actually start and register before checking */
    check_pthread_still_works("(before touching __pthread_head -- control)");

    /* Sanity check the derivation itself before drawing any conclusion from
     * overriding it: does the raw 8 bytes at PTHREAD_HEAD_ADDR actually look
     * like a real struct pthread pointer -- does it match pthread_self()
     * (main, definitely registered) or sentinel (just confirmed registered
     * above)? If it matches neither, the address is probably wrong, not
     * "unsealed". */
    uintptr_t head_value = *(volatile uintptr_t*)(uintptr_t)PTHREAD_HEAD_ADDR;
    printf("raw value at derived __pthread_head address: 0x%lx "
           "(pthread_self()=%p, sentinel=%p) -- %s\n",
           head_value, (void*)pthread_self(), (void*)sentinel,
           head_value == (uintptr_t)pthread_self() || head_value == (uintptr_t)sentinel
               ? "MATCHES a known-registered thread -- looks like the real list head"
               : "matches neither -- derivation is probably wrong");
    int before_kill = pthread_kill(sentinel, 0);
    printf("pthread_kill(sentinel, 0) before override: rc=%d (%s)\n",
           before_kill, before_kill == 0 ? "found" : strerror(before_kill));

    vm_region_submap_info_data_64_t head_info;
    mach_vm_address_t head_addr; mach_vm_size_t head_size;
    if (region_at(PTHREAD_HEAD_ADDR, &head_addr, &head_size, &head_info)
        && head_addr <= PTHREAD_HEAD_ADDR && PTHREAD_HEAD_ADDR < head_addr + head_size) {
        /* Battery-test the actual 16KB page CONTAINING PTHREAD_HEAD_ADDR --
         * NOT head_addr, which is the *whole containing region's* start
         * (turned out to be a ~24.6MB coalesced region here, not a single
         * page; a first cut used head_addr+0x4000 and silently tested an
         * unrelated page ~2.7MB before the real one, which is why the
         * value read back unchanged -- we'd never actually touched it). */
        mach_vm_address_t head_page = PTHREAD_HEAD_ADDR & ~0x3fffull;
        test_one("__pthread_head itself", head_page, 0x4000, &head_info);
        uintptr_t head_value_after = *(volatile uintptr_t*)(uintptr_t)PTHREAD_HEAD_ADDR;
        printf("raw value at derived __pthread_head address AFTER override: 0x%lx "
               "(was 0x%lx before) -- %s\n",
               head_value_after, head_value,
               head_value_after == head_value ? "UNCHANGED -- override didn't actually land here"
                                               : "CHANGED -- override really did overwrite it");
        check_pthread_still_works("overriding __pthread_head's page");
        int after_kill = pthread_kill(sentinel, 0);
        printf("pthread_kill(sentinel, 0) AFTER override: rc=%d (%s) -- %s\n",
               after_kill, strerror(after_kill),
               after_kill == before_kill
                   ? "SAME as before -- sentinel's registration survived (or the override never really touched the real list)"
                   : "CHANGED -- the override broke the sentinel's registration");
    } else {
        printf("\n__pthread_head address 0x%llx isn't inside a mapped region here -- "
               "derivation may be stale\n", (unsigned long long)PTHREAD_HEAD_ADDR);
    }
    atomic_store(&g_stop_sentinel, 1);
    pthread_join(sentinel, NULL);

    /* 2. General population: any writable, cache-range page dyld itself
     * already privatized before main() ran, vs. one still file-backed. */
    mach_vm_address_t addr; mach_vm_size_t size;
    vm_region_submap_info_data_64_t info;
    /* Capped at 256KB -- the earlier uncapped run grabbed an ~8.75MB live
     * region as the "still file-backed" control and overriding it crashed
     * the process (docs/003's known "touching live shared-cache pages can
     * hang or crash" hazard) before the RESULT line ever printed. A small
     * cap keeps the comparison useful without courting that again. */
    #define MAX_CANDIDATE_SIZE (256ull * 1024)
    if (find_first(/*want_pager=*/false, MAX_CANDIDATE_SIZE, &addr, &size, &info)) {
        test_one("general: already-privatized (external_pager=0) cache page", addr, size, &info);
    } else {
        printf("\nno naturally-privatized (external_pager=0) writable cache-range page found under 256KB\n");
    }
    if (find_first(/*want_pager=*/true, MAX_CANDIDATE_SIZE, &addr, &size, &info)) {
        test_one("general: still file-backed (external_pager=1) cache page", addr, size, &info);
    } else {
        printf("\nno still-pristine (external_pager=1) writable cache-range page found under 256KB\n");
    }

    /* Baseline: an ordinary heap page, for contrast on user_tag/flags. */
    void* heap_ptr = malloc(64);
    vm_region_submap_info_data_64_t heap_info;
    mach_vm_address_t heap_addr; mach_vm_size_t heap_size;
    if (region_at((mach_vm_address_t)(uintptr_t)heap_ptr, &heap_addr, &heap_size, &heap_info)) {
        printf("\n");
        print_info("baseline: ordinary heap page (not cache-derived, not battery-tested)",
                    heap_addr, heap_size, &heap_info);
    }

    return 0;
}
