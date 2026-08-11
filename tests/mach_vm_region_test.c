#include <mach/mach_vm.h>
#include <mach/mach.h>
#include <stdio.h>

int main() {
    
    mach_vm_address_t address = 0;
    mach_vm_size_t size = 0;
    for (;;) {

        /* reset every iteration: the kernel returns this as an out-param
         * (how much nesting budget an entry actually consumed, 0 for a
         * plain leaf) -- carrying a stale value into the next call starves
         * a later, unrelated submap of budget to descend into. */
        natural_t depth = 32;
        vm_region_submap_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        kern_return_t kr = mach_vm_region_recurse(mach_task_self(), &address, &size, &depth, (vm_region_recurse_info_t)&info, &count);

        if (kr == KERN_INVALID_ADDRESS) {
            break;
        }

        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "got error reading the region: %d\n", kr);
            return 1;
        }

        printf("==================\n");
        printf("found memory region from 0x%llx to 0x%llx (size 0x%llx)\n", address, address + size, size);
        printf("  protection: %d\n", info.protection);
        printf("  max protection: %d\n", info.max_protection);
        printf("  inheritance: %d\n", info.inheritance);
        printf("  offset: 0x%llx\n", info.offset);
        printf("  user tag: %d\n", info.user_tag);
        printf("  pages resident: %d\n", info.pages_resident);
        printf("  pages shared now private: %d\n", info.pages_shared_now_private);
        printf("  pages swapped out: %d\n", info.pages_swapped_out);
        printf("  pages dirtied: %d\n", info.pages_dirtied);
        printf("  ref count: %d\n", info.ref_count);
        printf("  shadow depth: %d\n", info.shadow_depth);
        printf("  external pager: %d\n", info.external_pager);
        printf("  share mode: %d\n", info.share_mode);
        printf("  is submap: %d\n", info.is_submap);
        printf("  behavior: %d\n", info.behavior);
        printf("  object id: %d\n", info.object_id);
        printf("  user wired count: %d\n", info.user_wired_count);
        printf("  flags: %d\n", info.flags);
        printf("  pages reusable: %d\n", info.pages_reusable);
        printf("  object id full: %llu\n", info.object_id_full);
        printf("==================\n");

        address += size;
    }

    return 0;
}