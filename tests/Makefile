CC        ?= clang
CFLAGS    ?= -g -Wall -Wextra
BINDIR    ?= /tmp
CKPT_FILE ?= /tmp/ckpt.bin
RETRY_NUMBER ?= 1

# Generic rule: build any tests/<name>.c as $(BINDIR)/<name>. Works for every
# throwaway test in this directory, not just sim_checkpoint_test.
$(BINDIR)/%: %.c
	$(CC) $(CFLAGS) -o $@ $<

.PHONY: checkpoint restore run clean sweep-pc-page capture resume resume-noaslr run-noaslr freestanding-hello resume-noaslr-retry run-noaslr-retry full-capture bsdthread-munge-selfsign thread-capture thread-restore thread-run

checkpoint: $(BINDIR)/sim_checkpoint_test
	$(BINDIR)/sim_checkpoint_test checkpoint $(CKPT_FILE)

restore: $(BINDIR)/sim_checkpoint_test
	$(BINDIR)/sim_checkpoint_test restore $(CKPT_FILE)

capture: $(BINDIR)/sim_capture_test
	$(BINDIR)/sim_capture_test $(CKPT_FILE)

resume: $(BINDIR)/sim_noaslr_restore_test
	$(BINDIR)/sim_noaslr_restore_test $(CKPT_FILE)

# Same restore binary, but launched with ASLR disabled via spawn_noaslr --
# pins its own __TEXT/stack/heap-neighborhood to their lowest possible
# addresses instead of a random slide on top. See spawn_noaslr.c.
resume-noaslr: $(BINDIR)/sim_noaslr_restore_test $(BINDIR)/spawn_noaslr
	$(BINDIR)/spawn_noaslr $(BINDIR)/sim_noaslr_restore_test $(CKPT_FILE)

run-noaslr: capture resume-noaslr

# Same as resume-noaslr, but retries (each in a fresh process) up to
# MOS_CRAC_RETRIES times whenever the restore hits the unreclaimable
# MALLOC-guard-page collision -- see NOTES.md 2026-08-21 / spawn_noaslr.c.
MOS_CRAC_RETRIES ?= 10
resume-noaslr-retry: $(BINDIR)/sim_noaslr_restore_test $(BINDIR)/spawn_noaslr
	$(BINDIR)/spawn_noaslr -r $(MOS_CRAC_RETRIES) $(BINDIR)/sim_noaslr_restore_test $(CKPT_FILE)

run-noaslr-retry: capture resume-noaslr-retry

checkpoint-pc-page: $(BINDIR)/code_alloc_test
	$(BINDIR)/code_alloc_test checkpoint $(CKPT_FILE)

map-pc-page: $(BINDIR)/code_alloc_test
	$(BINDIR)/code_alloc_test restore $(CKPT_FILE)

run: checkpoint restore

run-pc-page: checkpoint-pc-page map-pc-page

sweep-pc-page: $(BINDIR)/code_alloc_test
	$(BINDIR)/code_alloc_test sweep

# Zero-LC_LOAD_DYLIB Mach-O hello world: raw `write`/`exit` BSD syscalls
# only, no libSystem, no CRT. ld64 refuses to emit a dylib-less dynamic
# executable directly, so this links with -lSystem to pass that check, then
# strips the LC_LOAD_DYLIB command back out and re-signs (see
# strip_lc_load_dylib.py). See docs/006 / NOTES.md 2026-08-21 for why this
# exists and what running it actually showed.
freestanding-hello: freestanding_hello.s strip_lc_load_dylib.py
	$(CC) -c -target arm64-apple-macos11 -o $(BINDIR)/freestanding_hello.o freestanding_hello.s
	ld -o $(BINDIR)/freestanding_hello $(BINDIR)/freestanding_hello.o -e _start -arch arm64 \
		-platform_version macos 11.0 11.0 \
		-syslibroot "$$(xcrun --sdk macosx --show-sdk-path)" -lSystem
	python3 strip_lc_load_dylib.py $(BINDIR)/freestanding_hello
	codesign -s - -f $(BINDIR)/freestanding_hello
	$(BINDIR)/freestanding_hello

# Whole-process capture, single-threaded target (docs/006 "Part 1"). Runs
# in the foreground and keeps going after the checkpoint is written -- Ctrl-C
# to stop it once you've seen the self-check pass.
full-capture: $(BINDIR)/full_capture_test
	$(BINDIR)/full_capture_test $(CKPT_FILE)

full-noaslr-restore: $(BINDIR)/full_restore_test $(BINDIR)/spawn_noaslr
	$(BINDIR)/spawn_noaslr -r $(RETRY_NUMBER) $(BINDIR)/full_restore_test $(CKPT_FILE)

full-run: full-capture full-noaslr-restore

# bsdthread_create_test.c's current round (docs/007, 2026-08-24/25) calls
# ptrauth_sign_unauthenticated/ptrauth_auth_data directly -- those intrinsics
# only exist when compiling for arm64e specifically (__has_feature(ptrauth_calls)),
# unlike every earlier round of this file, which only fed raw bytes to
# __bsdthread_create and needed no special arch flag.
bsdthread-munge-selfsign: bsdthread_create_test.c
	$(CC) $(CFLAGS) -arch arm64e -o $(BINDIR)/bsdthread_create_test bsdthread_create_test.c
	$(BINDIR)/bsdthread_create_test

# Single-worker-thread capture + mode-D restore (docs/007, 2026-08-25):
# recreate the captured thread via a self-signed __bsdthread_create()
# instead of hijacking main() (2026-08-21's known stuck-process bug).
# Capture stays plain arm64 (no arch flag, matching every other
# capture/restore file); restore needs -arch arm64e for real (non-NOP'd)
# PAC -- see thread_restore_test.c's file header for why.
thread-capture: $(BINDIR)/thread_capture_test
	$(BINDIR)/thread_capture_test $(CKPT_FILE)

thread-restore: thread_restore_test.c $(BINDIR)/spawn_noaslr
	$(CC) $(CFLAGS) -arch arm64e -o $(BINDIR)/thread_restore_test thread_restore_test.c
	$(BINDIR)/spawn_noaslr -r $(RETRY_NUMBER) $(BINDIR)/thread_restore_test $(CKPT_FILE)

thread-run: thread-capture thread-restore

clean:
	rm -f $(CKPT_FILE)
