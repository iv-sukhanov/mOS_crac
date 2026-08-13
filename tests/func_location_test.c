#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <pthread.h>

int main() {
    long pagesize = sysconf(_SC_PAGESIZE);

    uint64_t mask = ~(pagesize - 1);

    void* mmaps_a = (void*)mmap;
    void* getpid_a = (void*)getpid;
    void* write_a = (void*)write;
    void* string_a = (void*)strdup;
    void* pthread_a = (void*)pthread_key_delete;

    printf("mmap address: %p, page-aligned: %p\n", mmaps_a, (void*)((uint64_t)mmaps_a & mask));
    printf("getpid address: %p, page-aligned: %p\n", getpid_a, (void*)((uint64_t)getpid_a & mask));
    printf("write address: %p, page-aligned: %p\n", write_a, (void*)((uint64_t)write_a & mask));
    printf("strdup address: %p, page-aligned: %p\n", string_a, (void*)((uint64_t)string_a & mask));
    printf("pthread_key_delete address: %p, page-aligned: %p\n", pthread_a, (void*)((uint64_t)pthread_a & mask));

    return 0;
}