#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

/* well above where ASLR/dyld/heap/stack normally land on this machine
 * (macOS 26.3.1, arm64) -- picked, not derived; if a future run ever
 * collides here, that's itself a finding worth logging. */
#define TARGET_ADDR ((void *)0x100000000000UL)
#define MAGIC       0xDEADBEEFCAFEBABEULL

int main(int argc, char **argv) {
    if (argc != 2 || (strcmp(argv[1], "write") != 0 && strcmp(argv[1], "read") != 0)) {
        fprintf(stderr, "usage: %s write|read\n", argv[0]);
        return 2;
    }

    long pagesize = sysconf(_SC_PAGESIZE);
    printf("pagesize: %ld bytes\n", pagesize);

    void *got = mmap(TARGET_ADDR, (size_t)pagesize, PROT_READ | PROT_WRITE,
                      MAP_FIXED | MAP_ANON | MAP_PRIVATE, -1, 0);
    if (got == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    printf("requested address: %p\n", TARGET_ADDR);
    printf("got address:       %p\n", got);
    if (got != TARGET_ADDR) {
        fprintf(stderr, "MAP_FIXED did not honor the requested address\n");
        return 1;
    }

    uint64_t *slot = (uint64_t *)got;

    if (strcmp(argv[1], "write") == 0) {
        *slot = MAGIC;
        printf("wrote 0x%016llx to %p\n", (unsigned long long)MAGIC, got);
        printf("read back within this same run: 0x%016llx (%s)\n",
               (unsigned long long)*slot,
               *slot == MAGIC ? "matches" : "MISMATCH");
    } else {
        printf("read from a fresh mapping in this run: 0x%016llx (%s)\n",
               (unsigned long long)*slot,
               *slot == 0 ? "zero, as expected for a fresh anonymous mapping"
                          : "NOT zero -- unexpected, investigate");
    }

    return 0;
}
