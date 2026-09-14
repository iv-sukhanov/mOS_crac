/* region_reserver_test.c -- append a new LC_SEGMENT_64 (pure VM reservation,
 * no file backing, same shape as __PAGEZERO) into an existing Mach-O
 * executable's headerpad slack, one page above __LINKEDIT's mapped end.
 * Requires the target built with -headerpad room (e.g.
 * `clang ... -Wl,-headerpad,0x1000`). Needs an ad-hoc re-sign afterward:
 * `codesign -s - -f <path>`.
 *
 * Full reasoning trail (why append-not-splice, why above-__LINKEDIT-not-
 * into-it, the SIGKILL/page-alignment bug, the codesign fileoff+filesize
 * rule): NOTES.md 2026-09-11 and 2026-09-14.
 */
#include <mach-o/loader.h>
#include <mach/vm_prot.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef OUTPUT_FILENAME
#define OUTPUT_FILENAME "modified_macho"
#endif

#define SEGMENTS_TO_APPEND 1
#define BUFFER_SIZE (64 * 1024)
#define RESERVATION_PAD_PAGES 1 /* gap above __LINKEDIT's end before the reservation starts */

static void fill_segment_command(struct segment_command_64* seg_cmd, uint64_t vmaddr,
                                  uint64_t vmsize, uint32_t initprot, uint32_t maxprot) {
    memset(seg_cmd, 0, sizeof(*seg_cmd));
    seg_cmd->cmd = LC_SEGMENT_64;
    seg_cmd->cmdsize = sizeof(*seg_cmd);
    memcpy(seg_cmd->segname, "__RESERVED", sizeof("__RESERVED"));
    seg_cmd->vmaddr = vmaddr;
    seg_cmd->vmsize = vmsize;
    seg_cmd->fileoff = 0; /* no file backing */
    seg_cmd->filesize = 0;
    seg_cmd->maxprot = maxprot;
    seg_cmd->initprot = initprot;
    seg_cmd->nsects = 0;
    seg_cmd->flags = 0;
}

static int write_all(FILE* f, const void* buf, size_t n) {
    if (n == 0) return 0;
    if (fwrite(buf, 1, n, f) != n) {
        fprintf(stderr, "short write (%zu bytes)\n", n);
        return -1;
    }
    return 0;
}

static int copy_remaining_file(FILE* src, FILE* dest) {
    uint8_t buffer[BUFFER_SIZE];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), src)) > 0) {
        if (write_all(dest, buffer, bytes_read) != 0) return -1;
    }
    if (ferror(src)) { perror("fread"); return -1; }
    return 0;
}

int main(int argc, char* argv[]) {
    FILE* f_in = NULL;
    FILE* f_out = NULL;
    uint8_t* cmds_buf = NULL;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <mach-o executable, built with sufficient -headerpad>\n", argv[0]);
        return 1;
    }

    f_in = fopen(argv[1], "rb");
    if (!f_in) { perror("fopen"); return 1; }

    struct mach_header_64 mh;
    if (fread(&mh, sizeof(mh), 1, f_in) != 1) {
        fprintf(stderr, "short read on mach_header_64\n");
        goto fail;
    }
    if (mh.magic != MH_MAGIC_64 || mh.filetype != MH_EXECUTE) {
        fprintf(stderr, "not a thin 64-bit Mach-O executable\n");
        goto fail;
    }

    uint32_t orig_sizeofcmds = mh.sizeofcmds;
    cmds_buf = malloc(orig_sizeofcmds);
    if (!cmds_buf || fread(cmds_buf, 1, orig_sizeofcmds, f_in) != orig_sizeofcmds) {
        fprintf(stderr, "short read on load commands\n");
        goto fail;
    }

    struct segment_command_64* linkedit = NULL;
    long first_content_off = -1; /* lowest real file offset any section/segment uses */

    for (uint32_t off = 0; off < orig_sizeofcmds;) {
        struct load_command* lc = (struct load_command*)(cmds_buf + off);
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64* seg = (struct segment_command_64*)lc;
            if (strncmp(seg->segname, "__LINKEDIT", sizeof(seg->segname)) == 0) {
                linkedit = seg;
            }
            if (seg->nsects == 0) {
                if (seg->filesize > 0 &&
                    (first_content_off < 0 || (long)seg->fileoff < first_content_off)) {
                    first_content_off = (long)seg->fileoff;
                }
            } else {
                struct section_64* sec = (struct section_64*)(seg + 1);
                for (uint32_t s = 0; s < seg->nsects; s++) {
                    if (sec[s].offset > 0 &&
                        (first_content_off < 0 || (long)sec[s].offset < first_content_off)) {
                        first_content_off = (long)sec[s].offset;
                    }
                }
            }
        }
        off += lc->cmdsize;
    }
    if (!linkedit) {
        fprintf(stderr, "no __LINKEDIT segment found -- unexpected Mach-O shape\n");
        goto fail;
    }

    long sys_page_size = getpagesize();
    if (sys_page_size <= 0) {
        fprintf(stderr, "getpagesize() returned nonsense (%ld)\n", sys_page_size);
        goto fail;
    }
    uint64_t page_size = (uint64_t)sys_page_size;
    uint64_t reserved_vm_size = page_size; /* one page per appended segment */

    uint64_t linkedit_end = linkedit->vmaddr + linkedit->vmsize;
    if (linkedit_end % page_size != 0) {
        fprintf(stderr, "__LINKEDIT's mapped end 0x%llx isn't page-aligned (page size %llu) "
                "-- unexpected Mach-O shape\n",
                (unsigned long long)linkedit_end, (unsigned long long)page_size);
        goto fail;
    }
    uint64_t new_vmaddr = linkedit_end + RESERVATION_PAD_PAGES * page_size;
    printf("new segment at vmaddr 0x%llx (size 0x%llx), %d page(s) above __LINKEDIT's end (0x%llx)\n",
           (unsigned long long)new_vmaddr, (unsigned long long)reserved_vm_size,
           RESERVATION_PAD_PAGES, (unsigned long long)linkedit_end);

    size_t new_cmds_size = SEGMENTS_TO_APPEND * sizeof(struct segment_command_64);
    long insertion_end = (long)sizeof(mh) + (long)orig_sizeofcmds + (long)new_cmds_size;
    if (first_content_off >= 0 && insertion_end > first_content_off) {
        fprintf(stderr,
                "not enough headerpad slack: new command(s) would end at file offset %ld, "
                "but real content starts at %ld -- rebuild the target with a bigger "
                "-headerpad and try again\n",
                insertion_end, first_content_off);
        goto fail;
    }

    f_out = fopen(OUTPUT_FILENAME, "wb");
    if (!f_out) { perror("fopen"); goto fail; }

    mh.ncmds += SEGMENTS_TO_APPEND;
    mh.sizeofcmds += (uint32_t)new_cmds_size;

    struct segment_command_64 new_seg;
    fill_segment_command(&new_seg, new_vmaddr, reserved_vm_size,
                          VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE);

    /* header + every original command unmodified + new command appended last */
    if (write_all(f_out, &mh, sizeof(mh)) != 0 ||
        write_all(f_out, cmds_buf, orig_sizeofcmds) != 0 ||
        write_all(f_out, &new_seg, sizeof(new_seg)) != 0) {
        goto fail;
    }
    free(cmds_buf);
    cmds_buf = NULL;

    /* our command consumes new_cmds_size bytes of the (zero-filled) headerpad
     * slack rather than growing the file -- skip that much before copying
     * the rest, so output file size == input file size exactly. */
    if (fseek(f_in, (long)new_cmds_size, SEEK_CUR) != 0) {
        perror("fseek");
        goto fail;
    }
    if (copy_remaining_file(f_in, f_out) != 0) goto fail;

    fclose(f_in);
    fclose(f_out);
    printf("wrote %s -- remember to re-sign: codesign -s - -f %s\n", OUTPUT_FILENAME, OUTPUT_FILENAME);
    return 0;

fail:
    if (f_in) fclose(f_in);
    if (f_out) fclose(f_out);
    free(cmds_buf);
    return 1;
}
