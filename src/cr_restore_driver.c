/* AI-assistance disclosure: developed with the assistance of Claude
 * (Anthropic) as a coding assistant, under the author's direction, review,
 * and testing. Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
 */
/* Minimal driver exercising cr_restore.c's do_restore(). Linked against
 * cr_restore.o + cr_common.o -- see src/Makefile. Needs the built binary
 * patched with extend_segment_vmsize.py and launched via spawn_noaslr
 * (both still in tests/) -- run directly, it will fail; see cr_restore.c's
 * file header. */
#include "cr_common.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <spawn.h>
#include <mach-o/loader.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <limits.h>
#include <assert.h>

#ifndef _POSIX_SPAWN_DISABLE_ASLR
#define _POSIX_SPAWN_DISABLE_ASLR 0x0100
#endif

#define EXE_ARG_INDEX 1
#define CKPT_ARG_INDEX 2
#define NUMBER_OF_ARGS 3

#define BUFFER_SIZE (64 * 1024)
#define PATCHED_PATH_SIZE PATH_MAX

extern char **environ;

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

static long find_first_content_off(uint8_t* cmds_buf, uint32_t orig_sizeofcmds) {
    long first_content_off = -1;

    for (uint32_t off = 0; off < orig_sizeofcmds;) {
        struct load_command* lc = (struct load_command*)(cmds_buf + off);
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64* seg = (struct segment_command_64*)lc;
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

    return first_content_off;
}

static void patched_binary_path(const char* orig_path, char* out, size_t outsz) {
    snprintf(out, outsz, "%s.patched", orig_path);
}

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

static bool lookup_identical_cache_region(region_desc_t* region) {
    mach_vm_address_t a = region->addr;
    mach_vm_size_t size = 0;
    natural_t depth = 32;
    vm_region_submap_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
    kern_return_t kr = mach_vm_region_recurse(mach_task_self(), &a, &size, &depth,
                                               (vm_region_recurse_info_t)&info, &count);
    if (kr != KERN_SUCCESS) return false;

    return a == region->addr && size == region->len && (uint32_t)info.protection == region->protection;
}

static size_t strip_dyld_cache_regions(struct segment_command_64* new_segs, region_desc_t* regions, uint32_t region_count) {
    size_t new_segs_count = 0;
    for (uint32_t i = 0; i < region_count; i++) {
        if (lookup_identical_cache_region(&regions[i])) {
            /* Skip this region, don't add a new segment for it. */
            continue;
        }
        /* Compact into new_segs[0..new_segs_count) -- indexing by the
         * write count, not by i, since skipped regions would otherwise
         * leave gaps of uninitialized entries inside the written range. */
        fill_segment_command(&new_segs[new_segs_count], regions[i].addr, regions[i].len,
                             regions[i].protection, regions[i].protection);
        new_segs_count++;
    }
    return new_segs_count;
}

static int write_patched_macho(
    region_desc_t* regions, uint32_t region_count, 
    struct mach_header_64* mh, uint8_t* cmds_buf, uint32_t orig_sizeofcmds,
    FILE* f_in,
    const char* path, char* patched) {

    assert(mh && regions && cmds_buf && path && patched && region_count > 0);
    
    patched_binary_path(path, patched, PATCHED_PATH_SIZE);

    FILE* f_out = fopen(patched, "wb");
    if (!f_out) { perror("fopen"); return -1; }

    size_t new_cmds_size = region_count * sizeof(struct segment_command_64);
    long first_content_off = find_first_content_off(cmds_buf, orig_sizeofcmds);
    long insertion_end = (long)sizeof(*mh) + (long)orig_sizeofcmds + (long)new_cmds_size;
    if (first_content_off >= 0 && insertion_end > first_content_off) {
        fprintf(stderr,
                "not enough headerpad slack: new command(s) would end at file offset %ld, "
                "but real content starts at %ld -- rebuild the target with a bigger "
                "-headerpad and try again\n",
                insertion_end, first_content_off);
        fclose(f_out);
        return -1;
    }

    struct segment_command_64 new_segs[MAX_REGIONS];
    size_t new_segs_count = strip_dyld_cache_regions(new_segs, regions, region_count);

    if (write_all(f_out, mh, sizeof(*mh)) != 0 ||
        write_all(f_out, cmds_buf, orig_sizeofcmds) != 0 ||
        write_all(f_out, new_segs, new_segs_count * sizeof(*new_segs)) != 0) {
        perror("write_all");
        fclose(f_out);
        return -1;
    }

    if (fseek(f_in, (long)new_cmds_size, SEEK_CUR) != 0) {
        perror("fseek");
        fclose(f_out);
        return -1;
    }
    if (copy_remaining_file(f_in, f_out) != 0) {
        perror("copy_remaining_file");
        fclose(f_out);
        return -1;
    }

    fclose(f_out);
    return 0;
}

static int read_ckpt_regions(const char* ckpt_file, region_desc_t* regions, uint32_t* region_count) {
    FILE* f = fopen(ckpt_file, "rb");
    if (!f) { perror("fopen"); return -1; }

    checkpoint_header_t hdr;
    if (fread(&hdr, sizeof(hdr), 1, f) != 1) {
        fprintf(stderr, "short read on checkpoint_header_t\n");
        fclose(f);
        return -1;
    }
    if (hdr.region_count > MAX_REGIONS) {
        fprintf(stderr, "checkpoint file has too many regions %u > %u\n",
                hdr.region_count, MAX_REGIONS);
        fclose(f);
        return -1;
    }

    if (fread(regions, sizeof(region_desc_t), hdr.region_count, f) != hdr.region_count) {
        fprintf(stderr, "short read on region descriptors\n");
        fclose(f);
        return -1;
    }

    *region_count = hdr.region_count;

    fclose(f);
    return 0;
}

static int reserve_regions(const char* path, char* patched, const char* ckpt_file) {
    FILE* f_in = fopen(path, "rb");
    if (!f_in) { perror("fopen"); return -1; }

    struct mach_header_64 mh;
    if (fread(&mh, sizeof(mh), 1, f_in) != 1) {
        fprintf(stderr, "short read on mach_header_64\n");
        fclose(f_in);
        return -1;
    }
    if (mh.magic != MH_MAGIC_64 || mh.filetype != MH_EXECUTE) {
        fprintf(stderr, "not a thin 64-bit Mach-O executable\n");
        fclose(f_in);
        return -1;
    }

    uint32_t orig_sizeofcmds = mh.sizeofcmds;
    uint8_t* cmds_buf = malloc(orig_sizeofcmds);
    if (!cmds_buf || fread(cmds_buf, 1, orig_sizeofcmds, f_in) != orig_sizeofcmds) {
        fprintf(stderr, "short read on load commands\n");
        fclose(f_in);
        return -1;
    }

    region_desc_t regions[MAX_REGIONS];
    uint32_t region_count;
    if (read_ckpt_regions(ckpt_file, regions, &region_count) != 0) {
        fclose(f_in);
        free(cmds_buf);
        return -1;
    }

    if (write_patched_macho(regions, region_count, &mh, cmds_buf, orig_sizeofcmds, f_in, path, patched) != 0) {
        fclose(f_in);
        free(cmds_buf);
        return -1;
    }

    fclose(f_in);
    free(cmds_buf);
    cmds_buf = NULL;
    return 0;
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);

    if (argc < NUMBER_OF_ARGS) {
        fprintf(stderr, "usage: %s <file> <checkpoint>\n", argv[0]);
        return 2;
    }

    char patched_path[PATCHED_PATH_SIZE];
    if (reserve_regions(argv[EXE_ARG_INDEX], patched_path, argv[CKPT_ARG_INDEX]) != 0) {
        fprintf(stderr, "reserve_regions failed\n");
        return 1;
    }

    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_setflags(&attr, _POSIX_SPAWN_DISABLE_ASLR);

    pid_t pid;
    int status;
    int rc = posix_spawn(&pid, patched_path, NULL, &attr, &argv[EXE_ARG_INDEX], environ);
    if (rc != 0) {
        fprintf(stderr, "posix_spawn failed: %s\n", strerror(rc));
        posix_spawnattr_destroy(&attr);
        return 1;
    }
    if (waitpid(pid, &status, 0) == -1) {
        perror("waitpid");
        posix_spawnattr_destroy(&attr);
        return 1;
    }
    posix_spawnattr_destroy(&attr);
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    } else {
        return 1;
    }

    return 0;
}
