// Freestanding "hello world" for arm64 macOS: zero LC_LOAD_DYLIB, no
// libSystem, no CRT. Raw BSD syscalls only (write, exit), invoked directly
// via `svc #0x80` with the syscall number in x16 -- Darwin's arm64 BSD
// syscall class (0x2000000) ORed with the classic BSD syscall number
// (write=4, exit=1). Entry point is `_start`, given to the linker via `-e`.
//
// This is step 1 of the freestanding-restore-driver line of research (see
// docs/006): confirm a zero-dylib Mach-O actually launches and runs on this
// machine before building anything more ambitious on top.

.global _start
.align 4

.text
_start:
    // write(1, msg, msg_len)
    mov     x0, #1
    adrp    x1, msg@PAGE
    add     x1, x1, msg@PAGEOFF
    mov     x2, #msg_len
    movz    x16, #0x0004            // SYS_write, low 16 bits
    movk    x16, #0x0200, lsl #16   // | BSD syscall class (0x2000000)
    svc     #0x80

    // exit(0)
    mov     x0, #0
    movz    x16, #0x0001            // SYS_exit, low 16 bits
    movk    x16, #0x0200, lsl #16   // | BSD syscall class (0x2000000)
    svc     #0x80

.data
msg:
    .ascii "Hello, freestanding world!\n"
msg_len = . - msg
