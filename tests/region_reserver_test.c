/* region_reserver_test.c -- append a new LC_SEGMENT_64 (a pure VM
 * reservation, no file backing, same shape as __PAGEZERO) into an existing
 * Mach-O executable's headerpad slack.
 *
 * REQUIRES the target to have been built with enough -headerpad room --
 * e.g. `clang ... -Wl,-headerpad,0x1000` (see NOTES.md 2026-09-11). Without
 * that, there's ~32 bytes of slack in a typical build, nowhere near enough
 * for one segment_command_64 (72 bytes), and this refuses to run rather
 * than corrupt the file.
 *
 * Correctness constraints this respects (NOTES.md 2026-09-11, 2026-09-14):
 *   - the ORIGINAL load commands are copied byte-for-byte, unshifted, at
 *     their original relative file position -- any change to an existing
 *     segment's/section's fileoff/offset would desync it from the
 *     already-compiled code that references it (adrp/add pairs, GOT/
 *     auth_ptr fixups, symbol values -- all computed at link time against
 *     the ORIGINAL file layout). __LINKEDIT itself is no exception here --
 *     nothing about it is patched either (see next bullet);
 *   - the new segment's vmaddr is immediately above __LINKEDIT's own
 *     mapped end (vmaddr + vmsize), plus a small pad, rather than carving
 *     into __LINKEDIT's own range and pushing its vmaddr forward. That
 *     address is free simply because __LINKEDIT is the highest-vmaddr
 *     segment the linker emits -- nothing else claims the space right
 *     past it. This means __LINKEDIT is NOT touched at all: no need to
 *     reason about whether moving its vmaddr is safe (it would be --
 *     dyld always reads __LINKEDIT's location fresh from its load
 *     command, unlike __TEXT/__DATA_CONST/__DATA, which have compiled-in
 *     adrp/add references baked against their original addresses -- see
 *     extend_segment_vmsize.py -- but zero touching beats reasoning about
 *     why touching would've been fine);
 *   - the new command is simply APPENDED as the last entry in the
 *     load-command list -- after __LINKEDIT's own command, not spliced in
 *     before it. NOTES.md 2026-09-11 traced codesign's actual validation
 *     rule to Apple's own source (macho++.cpp MachO::validateStructure()):
 *     `seg64->fileoff + seg64->filesize == file length` for __LINKEDIT
 *     specifically, nothing about command-list or vmaddr ordering -- two
 *     hypotheses to the contrary ("__LINKEDIT must stay last by vmaddr",
 *     "must be grouped with the other LC_SEGMENT_64s") were each tested
 *     and found WRONG that session. Since list order provably doesn't
 *     matter, appending is preferred over splicing: one straight-through
 *     write instead of a three-way split around __LINKEDIT's position;
 *   - the new segment's vmsize is exactly one page, from getpagesize() at
 *     runtime -- 0x4000 on Apple Silicon, not a hardcoded guess -- so its
 *     vmaddr and __LINKEDIT's own (untouched) mapped end both stay
 *     page-aligned (vm_map/mmap require it; a 2026-09-11 SIGKILL/137
 *     mystery, root-caused 2026-09-14, was exactly this: a hardcoded
 *     0x1000 on a 0x4000-page host). This is a DIFFERENT quantity from
 *     the headerpad slack check below: that one counts free bytes in the
 *     FILE for the new load command struct itself (72 bytes), unrelated
 *     to how much VM address space the new segment reserves;
 *   - the new segment is fileoff=0/filesize=0 (no file backing), so it
 *     costs nothing on disk and needs no content to copy correctly.
 *
 * The binary needs an ad-hoc re-sign afterward (`codesign -s - -f <path>`),
 * same as extend_segment_vmsize.py -- printed as a reminder, not done here.
 */
#include <mach-o/loader.h>
#include <mach/vm_prot.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> /* getpagesize() */

#ifndef OUTPUT_FILENAME
#define OUTPUT_FILENAME "modified_macho"
#endif

#define SEGMENTS_TO_APPEND 1
#define BUFFER_SIZE (64 * 1024)
/* Extra gap, in pages, left between __LINKEDIT's mapped end and where the
 * new reservation starts -- arbitrary safety margin (not load-bearing on
 * any known constraint), bump here if one is ever found to be needed. */
#define RESERVATION_PAD_PAGES 1

static void fill_segment_command(struct segment_command_64* seg_cmd, uint64_t vmaddr,
                                  uint64_t vmsize, uint32_t initprot, uint32_t maxprot) {
    memset(seg_cmd, 0, sizeof(*seg_cmd)); /* zero every byte, incl. segname's unused tail */
    seg_cmd->cmd = LC_SEGMENT_64;
    seg_cmd->cmdsize = sizeof(*seg_cmd);
    memcpy(seg_cmd->segname, "__RESERVED", sizeof("__RESERVED")); /* 11 bytes incl NUL, fits in 16 */
    seg_cmd->vmaddr = vmaddr;
    seg_cmd->vmsize = vmsize;
    seg_cmd->fileoff = 0; /* pure VM reservation, no file content -- same shape as __PAGEZERO */
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
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <mach-o executable, built with sufficient -headerpad>\n", argv[0]);
        return 1;
    }

    FILE* f_in = fopen(argv[1], "rb");
    if (!f_in) { perror("fopen"); return 1; }

    struct mach_header_64 mh;
    if (fread(&mh, sizeof(mh), 1, f_in) != 1) {
        fprintf(stderr, "short read on mach_header_64\n");
        fclose(f_in);
        return 1;
    }
    if (mh.magic != MH_MAGIC_64 || mh.filetype != MH_EXECUTE) {
        fprintf(stderr, "not a thin 64-bit Mach-O executable\n");
        fclose(f_in);
        return 1;
    }

    /* Read the ORIGINAL commands into memory -- need to both scan them (for
     * __LINKEDIT's extent and the real slack size) and write them straight
     * through afterward, byte-for-byte, unmodified. */
    uint32_t orig_sizeofcmds = mh.sizeofcmds;
    uint8_t* cmds_buf = malloc(orig_sizeofcmds);
    if (!cmds_buf || fread(cmds_buf, 1, orig_sizeofcmds, f_in) != orig_sizeofcmds) {
        fprintf(stderr, "short read on load commands\n");
        fclose(f_in);
        free(cmds_buf);
        return 1;
    }

    struct segment_command_64* linkedit = NULL;
    long first_content_off = -1;    /* lowest real file offset any section/segment uses */

    for (uint32_t off = 0; off < orig_sizeofcmds;) {
        struct load_command* lc = (struct load_command*)(cmds_buf + off);
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64* seg = (struct segment_command_64*)lc;
            if (strncmp(seg->segname, "__LINKEDIT", sizeof(seg->segname)) == 0) {
                linkedit = seg;
            }
            if (seg->nsects == 0) {
                /* No sections to look inside (e.g. __LINKEDIT) -- the
                 * segment's own fileoff directly marks real content, IF it
                 * has any. A segment's fileoff otherwise (e.g. __TEXT's,
                 * which is 0 because __TEXT's own mapped range starts at
                 * the header) says nothing about where content within it
                 * begins -- that's what section offsets are for, below. */
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
        fclose(f_in);
        free(cmds_buf);
        return 1;
    }

    /* One page, from the actual host -- not a hardcoded guess. Getting this
     * wrong (e.g. a 4KB literal on a 16KB-page arm64 host) leaves the new
     * segment's vmaddr misaligned, which vm_map/mmap will refuse at map
     * time (NOTES.md 2026-09-14 -- this is exactly what caused a
     * reproducible SIGKILL on every launch before it was found). */
    long sys_page_size = getpagesize();
    if (sys_page_size <= 0) {
        fprintf(stderr, "getpagesize() returned nonsense (%ld)\n", sys_page_size);
        fclose(f_in);
        free(cmds_buf);
        return 1;
    }
    uint64_t page_size = (uint64_t)sys_page_size;
    uint64_t reserved_vm_size = page_size; /* one page per appended segment */

    /* Reserve above __LINKEDIT's own mapped end rather than inside its
     * range -- that address is free precisely because __LINKEDIT is the
     * highest-vmaddr segment the linker emits, so __LINKEDIT itself never
     * needs to move. */
    uint64_t linkedit_end = linkedit->vmaddr + linkedit->vmsize;
    if (linkedit_end % page_size != 0) {
        fprintf(stderr, "__LINKEDIT's mapped end 0x%llx isn't page-aligned (page size %llu) "
                "-- unexpected Mach-O shape\n",
                (unsigned long long)linkedit_end, (unsigned long long)page_size);
        fclose(f_in);
        free(cmds_buf);
        return 1;
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
        fclose(f_in);
        free(cmds_buf);
        return 1;
    }

    FILE* f_out = fopen(OUTPUT_FILENAME, "wb");
    if (!f_out) { perror("fopen"); fclose(f_in); free(cmds_buf); return 1; }

    mh.ncmds += SEGMENTS_TO_APPEND;
    mh.sizeofcmds += (uint32_t)new_cmds_size;

    struct segment_command_64 new_seg;
    fill_segment_command(&new_seg, new_vmaddr, reserved_vm_size,
                          VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE);

    /* header (updated counts) + every original command, byte-for-byte
     * unmodified (including __LINKEDIT's own) + the new command appended
     * last -- then everything else copies through untouched from f_in's
     * now-correctly-advanced cursor. Nothing pre-existing ever moves in
     * the FILE; only the (previously zero-filled headerpad) slack gets
     * used, and nothing about any existing command's fields changes. */
    if (write_all(f_out, &mh, sizeof(mh)) != 0 ||
        write_all(f_out, cmds_buf, orig_sizeofcmds) != 0 ||
        write_all(f_out, &new_seg, sizeof(new_seg)) != 0) {
        fclose(f_in);
        fclose(f_out);
        free(cmds_buf);
        return 1;
    }
    free(cmds_buf);

    /* f_in's cursor sits exactly at the start of the (until now zero-filled)
     * headerpad slack -- our new command REPLACES new_cmds_size bytes of
     * that slack rather than growing the file, so skip that much of it
     * before copying the rest. Getting this wrong is exactly what broke
     * the first version: it copied ALL the slack AND the new command,
     * making the output file_size = input+72, while __LINKEDIT's
     * (unchanged) fileoff+filesize still summed to the OLD length --
     * `codesign`'s strict validation requires fileoff+filesize == the
     * actual file length (Security/OSX/libsecurity_utilities/lib/macho++.cpp
     * MachO::validateStructure()), and 72 bytes off is still off. */
    if (fseek(f_in, (long)new_cmds_size, SEEK_CUR) != 0) {
        perror("fseek");
        fclose(f_in);
        fclose(f_out);
        return 1;
    }

    if (copy_remaining_file(f_in, f_out) != 0) {
        fclose(f_in);
        fclose(f_out);
        return 1;
    }

    fclose(f_in);
    fclose(f_out);
    printf("wrote %s -- remember to re-sign: codesign -s - -f %s\n", OUTPUT_FILENAME, OUTPUT_FILENAME);
    return 0;
}
