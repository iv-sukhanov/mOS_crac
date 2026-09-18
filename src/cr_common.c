/* AI-assistance disclosure: developed with the assistance of Claude
 * (Anthropic) as a coding assistant, under the author's direction, review,
 * and testing. Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
 */
/* cr_common.c -- the two helpers cr_capture.c and cr_restore.c both call
 * identically: the pthread-signature helper and shared-cache detection.
 * See cr_common.h. */
#include "cr_common.h"

#include <ptrauth.h>
#include <mach/mach.h>
#include <mach/task.h>
#include <mach-o/dyld_images.h>
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

uintptr_t sign_for_addr(uintptr_t addr) {
    return (uintptr_t)ptrauth_sign_unauthenticated(
        (void *)addr, ptrauth_key_process_dependent_data,
        ptrauth_string_discriminator("pthread.signature"));
}

bool in_shared_cache_submap(mach_vm_address_t addr) {
    mach_vm_address_t a = addr;
    mach_vm_size_t size = 0;
    natural_t depth = 0;
    vm_region_submap_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
    kern_return_t kr = mach_vm_region_recurse(mach_task_self(), &a, &size, &depth,
                                               (vm_region_recurse_info_t)&info, &count);
    return kr == KERN_SUCCESS && info.is_submap;
}

/* Generous over-estimate of the shared cache's extent (~5.6 GB of cache
 * files on this machine; 8 GB with headroom). Over-guessing only ever
 * over-captures a little cache-adjacent memory, never misses something. */
#define CACHE_SPAN_BYTES (8ull * 1024 * 1024 * 1024)
bool in_shared_cache_range(mach_vm_address_t addr) {
    task_dyld_info_data_t info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    if (task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&info, &count) != KERN_SUCCESS) return false;
    struct dyld_all_image_infos* infos = (struct dyld_all_image_infos*)(uintptr_t)info.all_image_info_addr;
    uint64_t base = (uint64_t)infos->sharedCacheBaseAddress;
    return base != 0 && (uint64_t)addr >= base && (uint64_t)addr < base + CACHE_SPAN_BYTES;
}

int alloc_thread_descs(uint32_t thread_count, thread_desc_t** out) {
    *out = mmap(NULL, (size_t)thread_count * sizeof(thread_desc_t),
                PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (*out == MAP_FAILED) {
        fprintf(stderr, "mmap failed for thread buffer (%llu bytes): %s\n",
                (unsigned long long)((size_t)thread_count * sizeof(thread_desc_t)), strerror(errno));
        *out = NULL;
        return 1;
    }
    return 0;
}

void free_thread_descs(thread_desc_t** out, uint32_t thread_count) {
    if (*out) {
        munmap(*out, (size_t)thread_count * sizeof(thread_desc_t));
        *out = NULL;
    }
}
