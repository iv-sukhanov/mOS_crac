# AI-assistance disclosure: developed with the assistance of Claude
# (Anthropic) as a coding assistant, under the author's direction, review,
# and testing. Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
#
# Builds the stable capture/restore pipeline as two real linked binaries,
# not the tests/ convention of #including a .c file directly.
# crac_daemon.c, spawn_noaslr.c and extend_segment_vmsize.py are still
# tests/ scratch tools, referenced here relatively for now.

CC        ?= clang
CFLAGS    ?= -g -Wall -Wextra -arch arm64e
BINDIR    ?= build
CKPT_FILE ?= build/ckpt.bin
RETRY_NUMBER ?= 1
TESTS_DIR ?= ../tests

.PHONY: cr-capture cr-restore cr-run clean

$(BINDIR):
	mkdir -p $(BINDIR)

$(BINDIR)/cr_common.o: cr_common.c cr_common.h | $(BINDIR)
	$(CC) $(CFLAGS) -c -o $@ cr_common.c

$(BINDIR)/cr_capture.o: cr_capture.c cr_common.h | $(BINDIR)
	$(CC) $(CFLAGS) -c -o $@ cr_capture.c

$(BINDIR)/cr_restore.o: cr_restore.c cr_common.h | $(BINDIR)
	$(CC) $(CFLAGS) -c -o $@ cr_restore.c

$(BINDIR)/cr_capture_driver: cr_capture_driver.c $(BINDIR)/cr_capture.o $(BINDIR)/cr_common.o
	$(CC) $(CFLAGS) -o $@ cr_capture_driver.c $(BINDIR)/cr_capture.o $(BINDIR)/cr_common.o

$(BINDIR)/cr_restore_driver: cr_restore_driver.c $(BINDIR)/cr_restore.o $(BINDIR)/cr_common.o
	$(CC) $(CFLAGS) -o $@ cr_restore_driver.c $(BINDIR)/cr_restore.o $(BINDIR)/cr_common.o

# crac_daemon must sit next to cr_capture_driver -- do_capture()'s
# find_or_launch_daemon() resolves it relative to its own running path.
$(BINDIR)/crac_daemon: $(TESTS_DIR)/crac_daemon.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $(TESTS_DIR)/crac_daemon.c

$(BINDIR)/spawn_noaslr: $(TESTS_DIR)/spawn_noaslr.c | $(BINDIR)
	$(CC) -g -Wall -Wextra -o $@ $(TESTS_DIR)/spawn_noaslr.c

cr-capture: $(BINDIR)/cr_capture_driver $(BINDIR)/crac_daemon
	$(BINDIR)/cr_capture_driver $(CKPT_FILE)

# Run directly (no ASLR-off, no reserved vmsize) this fails -- see
# cr_restore.c's file header.
cr-restore: $(BINDIR)/cr_restore_driver $(BINDIR)/spawn_noaslr
	python3 $(TESTS_DIR)/extend_segment_vmsize.py $(BINDIR)/cr_restore_driver __DATA vmsize=0x50004000
	python3 $(TESTS_DIR)/extend_segment_vmsize.py $(BINDIR)/cr_restore_driver __LINKEDIT vmaddr=0x15000c000
	codesign -s - -f $(BINDIR)/cr_restore_driver
	$(BINDIR)/spawn_noaslr -r $(RETRY_NUMBER) $(BINDIR)/cr_restore_driver $(CKPT_FILE)

cr-run: cr-capture cr-restore

clean:
	rm -rf $(BINDIR)
