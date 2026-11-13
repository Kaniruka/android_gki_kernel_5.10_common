// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/kernel.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <syscall.h>
#include <unistd.h>

#include "../kselftest_harness.h"
#include "../clone3/clone3_selftests.h"

#ifndef __NR_close_range
#define __NR_close_range -1
#endif

#ifndef CLOSE_RANGE_UNSHARE
#define CLOSE_RANGE_UNSHARE	(1U << 1)
#endif

#ifndef CLOSE_RANGE_CLOEXEC
#define CLOSE_RANGE_CLOEXEC	(1U << 2)
#endif

static inline int sys_close_range(unsigned int fd, unsigned int max_fd,
				  unsigned int flags)
{
	return syscall(__NR_close_range, fd, max_fd, flags);
}

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

TEST(core_close_range)
{
	int i, ret;
	int open_fds[101];

	for (i = 0; i < ARRAY_SIZE(open_fds); i++) {
		int fd;

		fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
		ASSERT_GE(fd, 0) {
			if (errno == ENOENT)
				SKIP(return, "Skipping test since /dev/null does not exist");
		}

		open_fds[i] = fd;
	}

	EXPECT_EQ(-1, sys_close_range(open_fds[0], open_fds[100], -1)) {
		if (errno == ENOSYS)
			SKIP(return, "close_range() syscall not supported");
	}

	EXPECT_EQ(0, sys_close_range(open_fds[0], open_fds[50], 0));

	for (i = 0; i <= 50; i++)
		EXPECT_EQ(-1, fcntl(open_fds[i], F_GETFL));

	for (i = 51; i <= 100; i++)
		EXPECT_GT(fcntl(open_fds[i], F_GETFL), -1);

	/* create a couple of gaps */
	close(57);
	close(78);
	close(81);
	close(82);
	close(84);
	close(90);

	EXPECT_EQ(0, sys_close_range(open_fds[51], open_fds[92], 0));

	for (i = 51; i <= 92; i++)
		EXPECT_EQ(-1, fcntl(open_fds[i], F_GETFL));

	for (i = 93; i <= 100; i++)
		EXPECT_GT(fcntl(open_fds[i], F_GETFL), -1);

	/* test that the kernel caps and still closes all fds */
	EXPECT_EQ(0, sys_close_range(open_fds[93], open_fds[99], 0));

	for (i = 93; i <= 99; i++)
		EXPECT_EQ(-1, fcntl(open_fds[i], F_GETFL));

	EXPECT_GT(fcntl(open_fds[i], F_GETFL), -1);

	EXPECT_EQ(0, sys_close_range(open_fds[100], open_fds[100], 0));

	EXPECT_EQ(-1, fcntl(open_fds[100], F_GETFL));
}

TEST(close_range_unshare)
{
	int i, ret, status;
	pid_t pid;
	int open_fds[101];
	struct clone_args args = {
		.flags = CLONE_FILES,
		.exit_signal = SIGCHLD,
	};

	for (i = 0; i < ARRAY_SIZE(open_fds); i++) {
		int fd;

		fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
		ASSERT_GE(fd, 0) {
			if (errno == ENOENT)
				SKIP(return, "Skipping test since /dev/null does not exist");
		}

		open_fds[i] = fd;
	}

	pid = sys_clone3(&args, sizeof(args));
	ASSERT_GE(pid, 0);

	if (pid == 0) {
		ret = sys_close_range(open_fds[0], open_fds[50],
				      CLOSE_RANGE_UNSHARE);
		if (ret)
			exit(EXIT_FAILURE);

		for (i = 0; i <= 50; i++)
			if (fcntl(open_fds[i], F_GETFL) != -1)
				exit(EXIT_FAILURE);

		for (i = 51; i <= 100; i++)
			if (fcntl(open_fds[i], F_GETFL) == -1)
				exit(EXIT_FAILURE);

		/* create a couple of gaps */
		close(57);
		close(78);
		close(81);
		close(82);
		close(84);
		close(90);

		ret = sys_close_range(open_fds[51], open_fds[92],
				      CLOSE_RANGE_UNSHARE);
		if (ret)
			exit(EXIT_FAILURE);

		for (i = 51; i <= 92; i++)
			if (fcntl(open_fds[i], F_GETFL) != -1)
				exit(EXIT_FAILURE);

		for (i = 93; i <= 100; i++)
			if (fcntl(open_fds[i], F_GETFL) == -1)
				exit(EXIT_FAILURE);

		/* test that the kernel caps and still closes all fds */
		ret = sys_close_range(open_fds[93], open_fds[99],
				      CLOSE_RANGE_UNSHARE);
		if (ret)
			exit(EXIT_FAILURE);

		for (i = 93; i <= 99; i++)
			if (fcntl(open_fds[i], F_GETFL) != -1)
				exit(EXIT_FAILURE);

		if (fcntl(open_fds[100], F_GETFL) == -1)
			exit(EXIT_FAILURE);

		ret = sys_close_range(open_fds[100], open_fds[100],
				      CLOSE_RANGE_UNSHARE);
		if (ret)
			exit(EXIT_FAILURE);

		if (fcntl(open_fds[100], F_GETFL) != -1)
			exit(EXIT_FAILURE);

		exit(EXIT_SUCCESS);
	}

	EXPECT_EQ(waitpid(pid, &status, 0), pid);
	EXPECT_EQ(true, WIFEXITED(status));
	EXPECT_EQ(0, WEXITSTATUS(status));
}

TEST(close_range_unshare_capped)
{
	int i, ret, status;
	pid_t pid;
	int open_fds[101];
	struct clone_args args = {
		.flags = CLONE_FILES,
		.exit_signal = SIGCHLD,
	};

	for (i = 0; i < ARRAY_SIZE(open_fds); i++) {
		int fd;

		fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
		ASSERT_GE(fd, 0) {
			if (errno == ENOENT)
				SKIP(return, "Skipping test since /dev/null does not exist");
		}

		open_fds[i] = fd;
	}

	pid = sys_clone3(&args, sizeof(args));
	ASSERT_GE(pid, 0);

	if (pid == 0) {
		ret = sys_close_range(open_fds[0], UINT_MAX,
				      CLOSE_RANGE_UNSHARE);
		if (ret)
			exit(EXIT_FAILURE);

		for (i = 0; i <= 100; i++)
			if (fcntl(open_fds[i], F_GETFL) != -1)
				exit(EXIT_FAILURE);

		exit(EXIT_SUCCESS);
	}

	EXPECT_EQ(waitpid(pid, &status, 0), pid);
	EXPECT_EQ(true, WIFEXITED(status));
	EXPECT_EQ(0, WEXITSTATUS(status));
}

TEST(close_range_bitmap_corruption)
{
	pid_t pid;
	int status;
	struct __clone_args args = {
		.flags = CLONE_FILES,
		.exit_signal = SIGCHLD,
	};

	/* get the first 128 descriptors open */
	for (int i = 2; i < 128; i++)
		EXPECT_GE(dup2(0, i), 0);

	/* get descriptor table shared */
	pid = sys_clone3(&args, sizeof(args));
	ASSERT_GE(pid, 0);

	if (pid == 0) {
		/* unshare and truncate descriptor table down to 64 */
		if (sys_close_range(64, ~0U, CLOSE_RANGE_UNSHARE))
			exit(EXIT_FAILURE);

		ASSERT_EQ(fcntl(64, F_GETFD), -1);
		/* ... and verify that the range 64..127 is not
		   stuck "fully used" according to secondary bitmap */
		EXPECT_EQ(dup(0), 64)
			exit(EXIT_FAILURE);
		exit(EXIT_SUCCESS);
	}

	EXPECT_EQ(waitpid(pid, &status, 0), pid);
	EXPECT_EQ(true, WIFEXITED(status));
	EXPECT_EQ(0, WEXITSTATUS(status));
}

/*
 * CLOSE_RANGE_CLOEXEC must set the close-on-exec bit instead of closing the
 * descriptors. Descriptors outside the requested range are left alone, and the
 * flag must be honoured with a low RLIMIT_NOFILE in place.
 */
TEST(close_range_cloexec)
{
	int i, ret;
	int open_fds[101];
	struct rlimit rlimit;

	for (i = 0; i < ARRAY_SIZE(open_fds); i++) {
		int fd;

		fd = open("/dev/null", O_RDONLY);
		ASSERT_GE(fd, 0) {
			if (errno == ENOENT)
				SKIP(return, "Skipping test since /dev/null does not exist");
		}

		open_fds[i] = fd;
	}

	ret = sys_close_range(1000, 1000, CLOSE_RANGE_CLOEXEC);
	if (ret < 0) {
		if (errno == ENOSYS)
			SKIP(return, "close_range() syscall not supported");
		/*
		 * No XFAIL in this harness: a kernel without
		 * CLOSE_RANGE_CLOEXEC support must fail here instead of being
		 * skipped.
		 */
		ASSERT_EQ(0, ret);
	}

	/* Ensure the FD_CLOEXEC bit is set also with a resource limit in place.  */
	ASSERT_EQ(0, getrlimit(RLIMIT_NOFILE, &rlimit));
	rlimit.rlim_cur = 25;
	ASSERT_EQ(0, setrlimit(RLIMIT_NOFILE, &rlimit));

	/* Set close-on-exec for two ranges: [0-50] and [75-100].  */
	ret = sys_close_range(open_fds[0], open_fds[50], CLOSE_RANGE_CLOEXEC);
	ASSERT_EQ(0, ret);
	ret = sys_close_range(open_fds[75], open_fds[100], CLOSE_RANGE_CLOEXEC);
	ASSERT_EQ(0, ret);

	for (i = 0; i <= 50; i++) {
		int flags = fcntl(open_fds[i], F_GETFD);

		EXPECT_GT(flags, -1);
		EXPECT_EQ(flags & FD_CLOEXEC, FD_CLOEXEC);
	}

	for (i = 51; i <= 74; i++) {
		int flags = fcntl(open_fds[i], F_GETFD);

		EXPECT_GT(flags, -1);
		EXPECT_EQ(flags & FD_CLOEXEC, 0);
	}

	for (i = 75; i <= 100; i++) {
		int flags = fcntl(open_fds[i], F_GETFD);

		EXPECT_GT(flags, -1);
		EXPECT_EQ(flags & FD_CLOEXEC, FD_CLOEXEC);
	}

	/* Test a common pattern, also used by Android posix_spawn paths.  */
	ret = sys_close_range(3, UINT_MAX, CLOSE_RANGE_CLOEXEC);
	ASSERT_EQ(0, ret);
	for (i = 0; i <= 100; i++) {
		int flags = fcntl(open_fds[i], F_GETFD);

		EXPECT_GT(flags, -1);
		EXPECT_EQ(flags & FD_CLOEXEC, FD_CLOEXEC);
	}
}

/*
 * CLOSE_RANGE_CLOEXEC with CLOSE_RANGE_UNSHARE must preserve every descriptor
 * the caller still needs in the private table, and must not modify the table
 * that other CLONE_FILES users keep sharing.
 */
TEST(close_range_unshare_cloexec_isolation)
{
	int i, ret, status;
	pid_t pid;
	int open_fds[101];
	struct __clone_args args = {
		.flags = CLONE_FILES,
		.exit_signal = SIGCHLD,
	};

	for (i = 0; i < ARRAY_SIZE(open_fds); i++) {
		int fd;

		fd = open("/dev/null", O_RDONLY);
		ASSERT_GE(fd, 0) {
			if (errno == ENOENT)
				SKIP(return, "Skipping test since /dev/null does not exist");
		}

		open_fds[i] = fd;
	}

	pid = sys_clone3(&args, sizeof(args));
	ASSERT_GE(pid, 0);

	if (pid == 0) {
		/*
		 * Ask for cloexec over everything while unsharing: the private
		 * copy keeps all of it, so nothing may be closed.
		 */
		ret = sys_close_range(open_fds[0], UINT_MAX,
				      CLOSE_RANGE_CLOEXEC | CLOSE_RANGE_UNSHARE);
		if (ret)
			exit(EXIT_FAILURE);

		for (i = 0; i < ARRAY_SIZE(open_fds); i++) {
			int flags = fcntl(open_fds[i], F_GETFD);

			if (flags < 0)
				exit(EXIT_FAILURE);
			if (!(flags & FD_CLOEXEC))
				exit(EXIT_FAILURE);
		}

		exit(EXIT_SUCCESS);
	}

	EXPECT_EQ(waitpid(pid, &status, 0), pid);
	EXPECT_EQ(true, WIFEXITED(status));
	EXPECT_EQ(0, WEXITSTATUS(status));

	/* The child unshared, so this table must be completely unaffected. */
	for (i = 0; i < ARRAY_SIZE(open_fds); i++) {
		int flags = fcntl(open_fds[i], F_GETFD);

		EXPECT_GT(flags, -1);
		EXPECT_EQ(flags & FD_CLOEXEC, 0);
	}
}

/*
 * Unsharing can shrink the descriptor table far below the requested maximum.
 * The close-on-exec bitmap bound must then be recomputed from the table that
 * is actually in use, otherwise bits are set past the end of the bitmap.
 * A missing clamp writes one word past close_on_exec, which lands in
 * open_fds_init for a table of exactly NR_OPEN_DEFAULT entries; the descriptor
 * allocation check below is what makes that corruption observable.
 */
TEST(close_range_unshare_cloexec_shrunk_table)
{
	int i, ret, status, fd;
	pid_t pid;
	struct __clone_args args = {
		.flags = CLONE_FILES,
		.exit_signal = SIGCHLD,
	};

	/* Grow the table beyond the default 64 entries. */
	for (i = 2; i < 128; i++)
		ASSERT_GE(dup2(0, i), 0);

	/*
	 * Leave only descriptors 0-5 open: an unshare that copies every
	 * descriptor the caller still needs now fits a smaller table.
	 */
	for (i = 6; i < 128; i++)
		close(i);

	pid = sys_clone3(&args, sizeof(args));
	ASSERT_GE(pid, 0);

	if (pid == 0) {
		ret = sys_close_range(3, ~0U,
				      CLOSE_RANGE_CLOEXEC | CLOSE_RANGE_UNSHARE);
		if (ret)
			exit(EXIT_FAILURE);

		for (i = 3; i <= 5; i++) {
			int flags = fcntl(i, F_GETFD);

			if (flags < 0)
				exit(EXIT_FAILURE);
			if (!(flags & FD_CLOEXEC))
				exit(EXIT_FAILURE);
		}

		if (fcntl(0, F_GETFD) < 0)
			exit(EXIT_FAILURE);

		/*
		 * Descriptor 6 is the lowest free one. If the bitmap bound was not
		 * clamped, the excess word overwrote open_fds_init and marks the
		 * remaining descriptors as allocated, so this allocation cannot
		 * return 6.
		 */
		fd = open("/dev/null", O_RDONLY);
		if (fd != 6)
			exit(EXIT_FAILURE);

		exit(EXIT_SUCCESS);
	}

	EXPECT_EQ(waitpid(pid, &status, 0), pid);
	EXPECT_EQ(true, WIFEXITED(status));
	EXPECT_EQ(0, WEXITSTATUS(status));

	/* Clean up the descriptors this test grew the table with. */
	for (i = 2; i < 128; i++)
		close(i);
}

TEST_HARNESS_MAIN
