// Same freestanding "hello world" as freestanding_hello.s (zero LC_LOAD_DYLIB,
// no libSystem, no CRT, raw BSD syscalls only), except it spins forever
// after the write() instead of exit()ing immediately -- exit()ing before
// anything can attach made it impossible to vmmap the live process (found
// 2026-08-27, re-running the 2026-08-21 investigation). Kept as its own
// file rather than a flag on freestanding_hello.s: the two have genuinely
// different contracts (that one returns control to the shell promptly and
// is used as a quick launch/run smoke test; this one hangs on purpose and
// needs an external kill -9, see the `freestanding-spin` Makefile target).

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

    // spin forever instead of exit() -- lets vmmap attach to a live pid
spin:
    b       spin

.data
msg:
    .ascii "Hello, freestanding world!\n"
msg_len = . - msg
