CC        ?= clang
CFLAGS    ?= -g -Wall -Wextra
BINDIR    ?= /tmp
CKPT_FILE ?= /tmp/ckpt.bin

# Generic rule: build any tests/<name>.c as $(BINDIR)/<name>. Works for every
# throwaway test in this directory, not just sim_checkpoint_test.
$(BINDIR)/%: %.c
	$(CC) $(CFLAGS) -o $@ $<

.PHONY: checkpoint restore run clean sweep-pc-page capture resume resume-noaslr run-noaslr freestanding-hello

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

clean:
	rm -f $(CKPT_FILE)
