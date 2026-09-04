CC        ?= clang
CFLAGS    ?= -g -Wall -Wextra
BINDIR    ?= /tmp
CKPT_FILE ?= /tmp/ckpt.bin
RETRY_NUMBER ?= 1

# Generic rule: build any tests/<name>.c as $(BINDIR)/<name>. Works for every
# throwaway test in this directory, not just sim_checkpoint_test.
$(BINDIR)/%: %.c
	$(CC) $(CFLAGS) -o $@ $<

.PHONY: checkpoint restore run clean sweep-pc-page capture resume resume-noaslr run-noaslr freestanding-hello freestanding-spin resume-noaslr-retry run-noaslr-retry full-capture bsdthread-munge-selfsign thread-capture thread-restore thread-run cache-cow-probe reserve-probe full-run-reserved lr-sign-probe cr-capture cr-restore cr-run ucontext-reg-sign thread-state-resign

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

# Same idea as freestanding-hello, but the binary spins forever after its
# write() instead of exit()ing -- exiting immediately makes it impossible to
# vmmap the live process. Launches it backgrounded, vmmaps it (both the
# summary and the specific MALLOC/__TEXT/__DATA/__OBJC lines that answer
# "did libSystem load anyway"), then kills it. See NOTES.md 2026-08-21/
# 2026-08-27.
freestanding-spin: freestanding_spin.s strip_lc_load_dylib.py
	$(CC) -c -target arm64-apple-macos11 -o $(BINDIR)/freestanding_spin.o freestanding_spin.s
	ld -o $(BINDIR)/freestanding_spin $(BINDIR)/freestanding_spin.o -e _start -arch arm64 \
		-platform_version macos 11.0 11.0 \
		-syslibroot "$$(xcrun --sdk macosx --show-sdk-path)" -lSystem
	python3 strip_lc_load_dylib.py $(BINDIR)/freestanding_spin
	codesign -s - -f $(BINDIR)/freestanding_spin
	$(BINDIR)/freestanding_spin & \
	PID=$$!; \
	sleep 1; \
	echo "pid=$$PID"; \
	vmmap -summary $$PID; \
	echo "--- MALLOC / __TEXT / __DATA / __OBJC lines ---"; \
	vmmap -interleaved $$PID | grep -iE "malloc guard|malloc metadata|malloc zone|__TEXT|__DATA|__OBJC"; \
	kill -9 $$PID

# Whole-process capture, single-threaded target (docs/006 "Part 1"). Runs
# in the foreground and keeps going after the checkpoint is written -- Ctrl-C
# to stop it once you've seen the self-check pass.
full-capture: $(BINDIR)/full_capture_test
	$(BINDIR)/full_capture_test $(CKPT_FILE)

full-noaslr-restore: $(BINDIR)/full_restore_test $(BINDIR)/spawn_noaslr
	$(BINDIR)/spawn_noaslr $(BINDIR)/full_restore_test $(CKPT_FILE)

full-run: full-capture full-noaslr-restore

full-run-reserved: full-capture $(BINDIR)/full_restore_test $(BINDIR)/spawn_noaslr
	python3 extend_segment_vmsize.py $(BINDIR)/full_restore_test __DATA vmsize=0x50004000
	python3 extend_segment_vmsize.py $(BINDIR)/full_restore_test __LINKEDIT vmaddr=0x15000c000
	codesign -s - -f $(BINDIR)/full_restore_test
	$(BINDIR)/spawn_noaslr $(BINDIR)/full_restore_test $(CKPT_FILE)

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
	python3 extend_segment_vmsize.py $(BINDIR)/thread_restore_test __DATA vmsize=0x50004000
	python3 extend_segment_vmsize.py $(BINDIR)/thread_restore_test __LINKEDIT vmaddr=0x15000c000
	codesign -s - -f $(BINDIR)/thread_restore_test
	$(BINDIR)/spawn_noaslr -r $(RETRY_NUMBER) $(BINDIR)/thread_restore_test $(CKPT_FILE)

thread-run: thread-capture thread-restore

# cr_test.c's do_capture(), single-threaded self-capture (2026-09-03) --
# needs -arch arm64e itself now (unlike thread_capture_test.c), so this
# gets an _e suffix like the arm64e capture builds used ad hoc this
# session, distinguishing it from any future plain-arm64 cr_* build.
cr-capture: cr_capture_driver.c
	$(CC) $(CFLAGS) -arch arm64e -o $(BINDIR)/cr_capture_driver_e cr_capture_driver.c
	$(BINDIR)/cr_capture_driver_e $(CKPT_FILE)

# cr_test.c's do_restore() -- same segment-reservation/codesign/spawn_noaslr
# shape as thread-restore (same reason: whole-process guard-page collision,
# still unsolved -- NOTES.md 2026-09-03), signal-based resume mechanism
# instead of thread-restore's trampoline. Currently expected to fail at
# sigreturn's PAC check on the resumed pc -- see NOTES.md 2026-09-03.
cr-restore: cr_restore_driver.c $(BINDIR)/spawn_noaslr
	$(CC) $(CFLAGS) -arch arm64e -o $(BINDIR)/cr_restore_driver cr_restore_driver.c
	python3 extend_segment_vmsize.py $(BINDIR)/cr_restore_driver __DATA vmsize=0x50004000
	python3 extend_segment_vmsize.py $(BINDIR)/cr_restore_driver __LINKEDIT vmaddr=0x15000c000
	codesign -s - -f $(BINDIR)/cr_restore_driver
	$(BINDIR)/spawn_noaslr -r $(RETRY_NUMBER) $(BINDIR)/cr_restore_driver $(CKPT_FILE)

cr-run: cr-capture cr-restore

# Does MAP_FIXED (and the malloc-guard-page VM-call battery) behave
# differently against a shared-cache __DATA page before vs. after it's
# been copy-on-write-privatized by a real write? (2026-08-26 discussion)
cache-cow-probe: $(BINDIR)/cache_data_cow_test
	$(BINDIR)/cache_data_cow_test

# Is the LR signature ARM's PAC puts on the stack process-invariant (like
# the shared cache's IA-keyed function pointers, confirmed 2026-09-01) or
# process-dependent (like struct pthread's DB-keyed signature, docs/007)?
# Two same-boot runs under spawn_noaslr (pins sp, LR's own signing modifier)
# -- diff the two logs by hand; a differing lr against an identical sp is
# the answer. NOTES.md 2026-09-01 has the full plan.
lr-sign-probe: lr_sign_probe.c $(BINDIR)/spawn_noaslr
	$(CC) $(CFLAGS) -arch arm64e -o $(BINDIR)/lr_sign_probe lr_sign_probe.c
	$(BINDIR)/spawn_noaslr $(BINDIR)/lr_sign_probe > /tmp/lr_sign_run1.txt
	$(BINDIR)/spawn_noaslr $(BINDIR)/lr_sign_probe > /tmp/lr_sign_run2.txt
	@echo "--- run1 ---"; cat /tmp/lr_sign_run1.txt
	@echo "--- run2 ---"; cat /tmp/lr_sign_run2.txt
	@diff /tmp/lr_sign_run1.txt /tmp/lr_sign_run2.txt \
		&& echo "IDENTICAL -- LR signing looks process-invariant" \
		|| echo "DIFFERS -- LR signing is process-dependent"

# Grows __DATA_CONST's vmsize past its filesize (BSS-style reservation,
# same trick __PAGEZERO already uses) and moves __LINKEDIT's vmaddr out of
# the way to make room, on an ordinary dynamically-linked C binary -- see
# reserve_hello.c / extend_segment_vmsize.py. Confirms the reservation
# holds (the process reads from inside it) and that malloc lands its own
# regions well past it (vmmap from outside, zero collision). Recompiles
# reserve_hello.c fresh every run rather than depending on the generic
# $(BINDIR)/% rule -- patching updates the binary's mtime past the
# source's, so a stale-prerequisite build would silently re-patch an
# already-patched binary on a second run. See NOTES.md 2026-08-28.
reserve-probe: reserve_hello.c extend_segment_vmsize.py $(BINDIR)/spawn_noaslr
	$(CC) $(CFLAGS) -o $(BINDIR)/reserve_hello reserve_hello.c
	@VMSIZE_VAL=$(VMSIZE); \
	VMADDR_VAL=$$(printf "0x%x" $$(($$VMSIZE_VAL + 0x100008000))); \
	python3 extend_segment_vmsize.py $(BINDIR)/reserve_hello __DATA_CONST vmsize=$$VMSIZE_VAL; \
	python3 extend_segment_vmsize.py $(BINDIR)/reserve_hello __LINKEDIT vmaddr=$$VMADDR_VAL
	codesign -s - -f $(BINDIR)/reserve_hello 2>&1 | tail -1
	$(BINDIR)/spawn_noaslr $(BINDIR)/reserve_hello > /tmp/reserve_hello.out & \
	SHELL_PID=$$!; \
	sleep 1; \
	CHILD_PID=$$(pgrep -P $$SHELL_PID -f reserve_hello); \
	echo "child pid=$$CHILD_PID"; \
	vmmap -interleaved $$CHILD_PID 2>&1 | grep -E "^__TEXT|^__DATA|^__LINKEDIT|MALLOC guard|MALLOC metadata|MALLOC_TINY|MALLOC_SMALL" | head -20 | tee ../tmps/reserve_hello.vmmap; \
# 	kill -9 $$CHILD_PID $$SHELL_PID 2>/dev/null; \
	cat /tmp/reserve_hello.out

# Register-by-register PAC survey of a real kernel-delivered ucontext_t
# (2026-09-04) -- dumps x0-x28/fp/lr/sp/pc raw vs xpaci/xpacd-stripped plus
# the __opaque_flags decode, in one self-signal, single run (no cross-run
# diff needed, unlike lr-sign-probe -- this is a within-process structural
# question, not a process-dependence one). Needs -arch arm64e for the same
# reason lr-sign-probe does: the opaque pc/lr/sp/fp fields and the
# xpaci/xpacd instructions only mean anything real when ptrauth is live.
ucontext-reg-sign: ucontext_reg_sign_test.c
	$(CC) $(CFLAGS) -arch arm64e -o $(BINDIR)/ucontext_reg_sign_test ucontext_reg_sign_test.c
	$(BINDIR)/ucontext_reg_sign_test

# Strip+resign round trip against a real thread_get_state()/set_state()
# (2026-09-04, docs/010) -- single-process, locks down the recipe itself
# (key/discriminator/flags) before ever trying it cross-process. Needs
# -arch arm64e for the same reason every PAC-aware file in this repo does.
thread-state-resign: thread_state_resign_test.c
	$(CC) $(CFLAGS) -arch arm64e -o $(BINDIR)/thread_state_resign_test thread_state_resign_test.c
	$(BINDIR)/thread_state_resign_test

clean:
	rm -f $(CKPT_FILE)
