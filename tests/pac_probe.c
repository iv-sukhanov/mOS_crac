/* PAC A-key process-invariance probe (2026-09-10).
 *
 * Question this answers: is `PACIZA <fixed shared-cache addr>` reproducible
 * across two ASLR-disabled launches of this same binary? If the IA key
 * register is a per-boot shared constant (the assumption the whole
 * checkpoint/restore approach rested on) -> identical every run. If it is
 * per-process random -> the PAC field differs every run.
 *
 * Used to bisect, across macOS versions in throwaway VMs, when ad-hoc
 * arm64e binaries stopped getting a shared A key (NOTES.md 2026-09-10).
 *
 * Build BOTH ways; run each under spawn_noaslr a few times and diff:
 *   clang -g -O0 -arch arm64e -o /tmp/pac_probe_e pac_probe.c
 *   clang -g -O0 -arch arm64  -o /tmp/pac_probe_a pac_probe.c
 *
 * Reading the output:
 *   cache_base / &stackvar identical across runs  -> ASLR really is pinned
 *   PACIZA(printf) identical across runs          -> shared (per-boot) A key
 *   PACIZA(printf) differs every run              -> per-process A key
 *   plain-arm64 build: PAC instructions are no-ops (input returned as-is)
 */
#include <stdio.h>
#include <stdint.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach/task.h>
#include <mach-o/dyld_images.h>

__attribute__((noinline)) static void anchor(void) { }

static uint64_t xpaci_of(uint64_t v) { __asm__ volatile("xpaci %0" : "+r"(v)); return v; }

int main(void) {
    /* 1. this binary's own __TEXT function pointers, raw values */
    uint64_t pmain   = (uint64_t)(uintptr_t)(void *)main;
    uint64_t panchor = (uint64_t)(uintptr_t)(void *)anchor;

    /* 2. a shared-cache libSystem function address, stripped to a bare VA */
    void *praw_printf = dlsym(RTLD_DEFAULT, "printf");
    uint64_t bare_printf = xpaci_of((uint64_t)(uintptr_t)praw_printf);

    /* 3. PACIZA(bare_printf): IA key, modifier 0 -- the "process-independent"
     *    signing the approach assumed was stable across processes. */
    uint64_t paciza_printf = bare_printf;
    __asm__ volatile("paciza %0" : "+r"(paciza_printf));

    /* 4. PACIA(bare_printf, 0): same key via the named-key instruction with an
     *    explicit zero modifier -- must match #3 exactly. */
    uint64_t pacia0_printf = bare_printf;
    __asm__ volatile("pacia %0, %1" : "+r"(pacia0_printf) : "r"((uint64_t)0));

    /* 5. PACDZA(bare_printf): DA key, modifier 0 -- the sp/fp bucket. */
    uint64_t pacdza_printf = bare_printf;
    __asm__ volatile("pacdza %0" : "+r"(pacdza_printf));

    /* 6. C-level function pointer as the compiler signs it. */
    uint64_t cfp_printf = (uint64_t)(uintptr_t)(void *)printf;

    /* 7. shared cache base + a stack address, to prove ASLR really is off */
    task_dyld_info_data_t di;
    mach_msg_type_number_t cnt = TASK_DYLD_INFO_COUNT;
    uint64_t cache_base = 0;
    if (task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&di, &cnt) == KERN_SUCCESS) {
        struct dyld_all_image_infos *ii =
            (struct dyld_all_image_infos *)(uintptr_t)di.all_image_info_addr;
        cache_base = (uint64_t)ii->sharedCacheBaseAddress;
    }
    int stackvar = 0;

    printf("main            = 0x%016llx\n", pmain);
    printf("anchor          = 0x%016llx\n", panchor);
    printf("&stackvar       = 0x%016llx\n", (uint64_t)(uintptr_t)&stackvar);
    printf("cache_base      = 0x%016llx\n", cache_base);
    printf("printf raw      = 0x%016llx\n", (uint64_t)(uintptr_t)praw_printf);
    printf("printf bare VA  = 0x%016llx\n", bare_printf);
    printf("PACIZA(printf)  = 0x%016llx\n", paciza_printf);
    printf("PACIA(printf,0) = 0x%016llx\n", pacia0_printf);
    printf("PACDZA(printf)  = 0x%016llx\n", pacdza_printf);
    printf("&printf (C fp)  = 0x%016llx\n", cfp_printf);
    return 0;
}
