# AI-assistance disclosure: developed with the assistance of Claude
# (Anthropic) as a coding assistant, under the author's direction, review,
# and testing. Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
#
# Builds the stable capture/restore pipeline as real linked binaries, not
# the tests/ convention of #including a .c file directly.
# crac_daemon.c is still a tests/ scratch tool, referenced here relatively
# for now. cr_restore_launcher.c has folded in what tests/spawn_noaslr.c
# and tests/extend_segment_vmsize.py used to do externally -- neither is
# needed here anymore.

CC        ?= clang
CFLAGS    ?= -g -Wall -Wextra -arch arm64e
BINDIR    ?= build
CKPT_FILE ?= build/ckpt.bin
TESTS_DIR ?= ../tests

HEADERPAD ?= 0x1000

.PHONY: cr-capture cr-restore cr-run compile-all clean

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
	$(CC) $(CFLAGS) -Wl,-headerpad,$(HEADERPAD) -o $@ cr_restore_driver.c $(BINDIR)/cr_restore.o $(BINDIR)/cr_common.o

$(BINDIR)/cr_restore_launcher: cr_restore_launcher.c $(BINDIR)/cr_common.o
	$(CC) $(CFLAGS) -o $@ cr_restore_launcher.c $(BINDIR)/cr_common.o

$(BINDIR)/crac_daemon: $(TESTS_DIR)/crac_daemon.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $(TESTS_DIR)/crac_daemon.c

cr-capture: $(BINDIR)/cr_capture_driver $(BINDIR)/crac_daemon
	$(BINDIR)/cr_capture_driver $(CKPT_FILE)

cr-restore: $(BINDIR)/cr_restore_driver $(BINDIR)/cr_restore_launcher
	$(BINDIR)/cr_restore_launcher $(BINDIR)/cr_restore_driver $(CKPT_FILE)

cr-run: cr-capture cr-restore

compile-all:
	$(MAKE) -k $(BINDIR)/cr_capture_driver $(BINDIR)/cr_restore_driver $(BINDIR)/cr_restore_launcher $(BINDIR)/crac_daemon

clean:
	rm -rf $(BINDIR)
