CC        ?= clang
CFLAGS    ?= -g -Wall -Wextra
BINDIR    ?= /tmp
CKPT_FILE ?= /tmp/ckpt.bin

# Generic rule: build any tests/<name>.c as $(BINDIR)/<name>. Works for every
# throwaway test in this directory, not just sim_checkpoint_test.
$(BINDIR)/%: %.c
	$(CC) $(CFLAGS) -o $@ $<

.PHONY: checkpoint restore run clean sweep-pc-page capture resume resume-noaslr run-noaslr

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

clean:
	rm -f $(CKPT_FILE)
