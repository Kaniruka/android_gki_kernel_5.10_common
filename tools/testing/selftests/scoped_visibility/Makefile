# SPDX-License-Identifier: GPL-2.0
CFLAGS += -Wall -Wextra -O2
TEST_GEN_PROGS := scoped_visibility_test
TEST_GEN_PROGS_EXTENDED := svctl
TEST_FILES := README
include ../lib.mk

$(OUTPUT)/scoped_visibility_test: scoped_visibility_test.c ../../../../include/uapi/linux/scoped_visibility.h
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $< $(LDLIBS) -o $@

$(OUTPUT)/svctl: svctl.c ../../../../include/uapi/linux/scoped_visibility.h
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $< $(LDLIBS) -o $@
