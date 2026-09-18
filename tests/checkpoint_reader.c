/* checkpoint_reader.c -- read-only dump of a cr_capture checkpoint file's
 * header, thread, and region metadata (2026-09-18). Never touches the region
 * buffer bytes themselves; just enough to eyeball what a restore would act
 * on and catch an obviously-corrupt capture before trying it. Layout must
 * track src/cr_common.h's on-disk format comment exactly.
 */
#include <stdio.h>
#include <stdlib.h>
#include <mach/vm_prot.h>
#include "../src/cr_common.h"

static void print_prot(uint32_t prot) {
    printf("%c%c%c",
        (prot & VM_PROT_READ)    ? 'r' : '-',
        (prot & VM_PROT_WRITE)   ? 'w' : '-',
        (prot & VM_PROT_EXECUTE) ? 'x' : '-');
}

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <checkpoint file>\n", argv[0]);
        return 1;
    }

    FILE* f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 1; }

    checkpoint_header_t hdr;
    if (fread(&hdr, sizeof(hdr), 1, f) != 1) {
        fprintf(stderr, "short read on header\n");
        fclose(f);
        return 1;
    }

    printf("== header ==\n");
    printf("thread_count=%u region_count=%u capture_used=%llu bytes (~%.2f MB) munge=0x%llx "
        "sentinel=0x%llx daemon_pid=%d\n",
        hdr.thread_count, hdr.region_count,
        hdr.capture_used, hdr.capture_used / (1024.0 * 1024.0),
           hdr.munge,
           hdr.sentinel, hdr.daemon_pid);

    thread_desc_t* threads = malloc(sizeof(thread_desc_t) * hdr.thread_count);
    if (fread(threads, sizeof(thread_desc_t), hdr.thread_count, f) != hdr.thread_count) {
        fprintf(stderr, "short read on threads\n");
        free(threads);
        return 1;
    }

    printf("== threads (%u) ==\n", hdr.thread_count);
    for (uint32_t i = 0; i < hdr.thread_count; i++) {
        thread_desc_t* td = &threads[i];
        printf("thread[%u] pthread_addr=0x%llx pc=0x%llx sp=0x%llx\n",
            i, td->pthread_addr,
            (uint64_t)arm_thread_state64_get_pc_fptr(td->regs.gregs),
            (uint64_t)arm_thread_state64_get_sp(td->regs.gregs));
    }

    region_desc_t* regions = malloc(sizeof(region_desc_t) * hdr.region_count);
    if (fread(regions, sizeof(region_desc_t), hdr.region_count, f) != hdr.region_count) {
        fprintf(stderr, "short read on regions\n");
        free(threads);
        free(regions);
        return 1;
    }

    printf("== regions (%u) ==\n", hdr.region_count);
    uint64_t sum_len = 0;
    for (uint32_t i = 0; i < hdr.region_count; i++) {
        region_desc_t* rd = &regions[i];
        printf("region[%u] addr=0x%llx len=0x%llx (%.2f MB) prot=",
            i, rd->addr, rd->len,
            rd->len / (1024.0 * 1024.0));
        print_prot(rd->protection);
        printf("\n");
        sum_len += rd->len;
    }

    long data_start = ftell(f);
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    uint64_t bytes_left = (uint64_t)(file_size - data_start);

    printf("== sanity ==\n");
    printf("sum(region.len)=%llu vs capture_used=%llu -- %s\n",
        sum_len, hdr.capture_used,
        sum_len == hdr.capture_used ? "OK" : "MISMATCH");
    printf("bytes left in file=%llu vs capture_used=%llu -- %s\n",
        bytes_left, hdr.capture_used,
        bytes_left == hdr.capture_used ? "OK" : "MISMATCH");

    free(threads);
    free(regions);
    fclose(f);
    return 0;
}
