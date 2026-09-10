#include <stdio.h>

int main() {
    void* fp = &main;
    printf("main function pointer: %p\n", fp);
    
    return 0;
}