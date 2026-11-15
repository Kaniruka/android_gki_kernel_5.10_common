// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include "../../../../include/uapi/linux/scoped_visibility.h"
#include <linux/capability.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <fcntl.h>
#include <grp.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE 1U
#endif

#define CONTROL "/sys/kernel/security/scoped_visibility/control"
#define UID_A 20001
#define UID_B 20002
#define UID_PROVIDER 30001
#define MAP_A 10
#define MAP_B 20
#define V2_LIVE_LEASE_MS 60000
#define V2_LEASE_TEST_MS SV_MIN_LEASE_MS
#define V2_REPLACE_ROUNDS 24

_Static_assert(sizeof(struct sv_snapshot) == 4632, "v1 snapshot ABI changed");
_Static_assert(sizeof(struct sv_info) == 536, "v1 info ABI changed");
_Static_assert(sizeof(struct sv_root_v2) == 144, "v2 root ABI mismatch");
_Static_assert(sizeof(struct sv_package_v2) == 264, "v2 package ABI mismatch");
_Static_assert(sizeof(struct sv_snapshot_v2) == 56, "v2 snapshot ABI mismatch");
_Static_assert(sizeof(struct sv_info_v2) == 544, "v2 info ABI mismatch");
_Static_assert(_IOC_SIZE(SV_IOC_REPLACE_V2) == 56, "v2 replace ioctl size mismatch");
_Static_assert(_IOC_SIZE(SV_IOC_GET_INFO_V2) == 544, "v2 info ioctl size mismatch");

static int ctl = -1;
static int root_a_fd = -1, root_b_fd = -1;
static int list_a_fd = -1;
static int foreign_dir_fd = -1, deep_file_fd = -1;
static int mounted;
static int tests, failures;
static unsigned long long generation;
static int owned_policy;
static char *fixture;
static char root_a[320], root_b[320], staging[320];
static char alpha[384], beta_a[384], beta_b[384], alpha_b[384];
static char foo[384], foo_bar[384], foo_barx[384];
static char alpha_file[448], beta_a_file[448], beta_b_file[448];
static char alpha_b_file[448];

static void check(int ok, const char *what)
{
	printf("%s - %s\n", ok ? "ok" : "not ok", what);
	tests++;
	if (!ok)
		failures++;
}

static int no_effective_caps(void)
{
	struct __user_cap_header_struct h = {
		.version = _LINUX_CAPABILITY_VERSION_3,
		.pid = 0,
	};
	struct __user_cap_data_struct d[2];

	return !syscall(SYS_capget, &h, d) && !d[0].effective && !d[1].effective;
}

static int drop_to(uid_t uid)
{
	return !setgroups(0, NULL) && !setresgid(uid, uid, uid) &&
		!setresuid(uid, uid, uid) && (uid == 0 || no_effective_caps());
}

typedef int (*uid_probe_fn)(void *arg);

static int as_uid(uid_t uid, uid_probe_fn fn, void *arg)
{
	pid_t pid = fork();
	int status;

	if (!pid) {
		alarm(20);
		if (!drop_to(uid))
			_exit(2);
		_exit(fn(arg) ? 0 : 1);
	}
	if (pid < 0 || waitpid(pid, &status, 0) != pid)
		return 0;
	return WIFEXITED(status) && !WEXITSTATUS(status);
}

static int touch_file(const char *path)
{
	int fd = open(path, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0666);

	if (fd < 0)
		return -1;
	return close(fd);
}

static int mkdir_mode(const char *path)
{
	if (mkdir(path, 0777))
		return -1;
	return chmod(path, 0777);
}

static void path_join(char *dst, size_t size, const char *base, const char *name)
{
	snprintf(dst, size, "%s/%s", base, name);
}

static int make_package(const char *path, const char *file)
{
	return mkdir_mode(path) || touch_file(file) ? -1 : 0;
}

static int setup_fixture(void)
{
	if (!mkdtemp(fixture))
		return -1;
	if (mount("tmpfs", fixture, "tmpfs", MS_NOSUID | MS_NODEV,
		  "mode=0777,size=4m"))
		return -1;
	mounted = 1;
	if (chmod(fixture, 0777))
		return -1;
	path_join(root_a, sizeof(root_a), fixture, "user-a");
	path_join(root_b, sizeof(root_b), fixture, "user-b");
	path_join(staging, sizeof(staging), fixture, "staging");
	if (mkdir_mode(root_a) || mkdir_mode(root_b) || mkdir_mode(staging))
		return -1;
	path_join(alpha, sizeof(alpha), root_a, "com.example.alpha");
	path_join(beta_a, sizeof(beta_a), root_a, "com.example.beta");
	path_join(beta_b, sizeof(beta_b), root_b, "com.example.beta");
	path_join(alpha_b, sizeof(alpha_b), root_b, "com.example.alpha");
	path_join(foo, sizeof(foo), root_a, "com.foo");
	path_join(foo_bar, sizeof(foo_bar), root_a, "com.foo.bar");
	path_join(foo_barx, sizeof(foo_barx), root_a, "com.foo.barx");
	path_join(alpha_file, sizeof(alpha_file), alpha, "known");
	path_join(beta_a_file, sizeof(beta_a_file), beta_a, "secret");
	path_join(beta_b_file, sizeof(beta_b_file), beta_b, "known");
	path_join(alpha_b_file, sizeof(alpha_b_file), alpha_b, "secret");
	if (make_package(alpha, alpha_file) ||
	    make_package(beta_a, beta_a_file) ||
	    make_package(beta_b, beta_b_file) ||
	    make_package(alpha_b, alpha_b_file) ||
	    mkdir_mode(foo) || mkdir_mode(foo_bar) || mkdir_mode(foo_barx))
		return -1;
	root_a_fd = open(root_a, O_PATH | O_DIRECTORY | O_CLOEXEC);
	root_b_fd = open(root_b, O_PATH | O_DIRECTORY | O_CLOEXEC);
	list_a_fd = open(root_a, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	foreign_dir_fd = open(beta_a, O_PATH | O_DIRECTORY | O_CLOEXEC);
	deep_file_fd = open(beta_a_file, O_PATH | O_CLOEXEC);
	return root_a_fd >= 0 && root_b_fd >= 0 && list_a_fd >= 0 &&
		foreign_dir_fd >= 0 && deep_file_fd >= 0 ? 0 : -1;
}

static void fill_v1(struct sv_snapshot *s, unsigned long long expected,
		    int fd, int with_users)
{
	memset(s, 0, sizeof(*s));
	s->version = SV_VERSION;
	s->expected_generation = expected;
	if (fd < 0)
		return;
	s->nr_entries = 1;
	s->entries[0].fd = fd;
	if (with_users) {
		s->entries[0].nr_ranges = 3;
		s->entries[0].ranges[0].min = 0;
		s->entries[0].ranges[0].max = 0;
		s->entries[0].ranges[1].min = UID_A;
		s->entries[0].ranges[1].max = UID_A;
		s->entries[0].ranges[2].min = UID_PROVIDER;
		s->entries[0].ranges[2].max = UID_PROVIDER;
	}
}

static int publish_v1(unsigned long long expected, int fd, int with_users)
{
	struct sv_snapshot s;

	fill_v1(&s, expected, fd, with_users);
	if (ioctl(ctl, SV_IOC_REPLACE, &s))
		return -1;
	generation = expected + 1;
	owned_policy = 1;
	return 0;
}

static void fill_root(struct sv_root_v2 *root, int fd, unsigned int map_id)
{
	memset(root, 0, sizeof(*root));
	root->fd = fd;
	root->map_id = map_id;
	root->nr_ranges = 2;
	root->ranges[0].min = 0;
	root->ranges[0].max = 0;
	root->ranges[1].min = UID_PROVIDER;
	root->ranges[1].max = UID_PROVIDER;
}

static void fill_package(struct sv_package_v2 *pkg, unsigned int map_id,
			 unsigned int uid, const char *name)
{
	memset(pkg, 0, sizeof(*pkg));
	pkg->map_id = map_id;
	pkg->uid = uid;
	snprintf(pkg->name, sizeof(pkg->name), "%s", name);
}

static void fill_v2(struct sv_snapshot_v2 *s, unsigned long long expected,
		    struct sv_root_v2 *roots, unsigned int nr_roots,
		    struct sv_package_v2 *packages, unsigned int nr_packages,
		    unsigned int lease_ms)
{
	memset(s, 0, sizeof(*s));
	s->version = SV_VERSION_V2;
	s->expected_generation = expected;
	s->nr_roots = nr_roots;
	s->nr_packages = nr_packages;
	s->roots_ptr = (__u64)(uintptr_t)roots;
	s->packages_ptr = (__u64)(uintptr_t)packages;
	s->lease_ms = lease_ms;
}

static int publish_v2(unsigned long long expected, struct sv_root_v2 *roots,
		      unsigned int nr_roots,
		      struct sv_package_v2 *packages,
		      unsigned int nr_packages, unsigned int lease_ms)
{
	struct sv_snapshot_v2 s;

	fill_v2(&s, expected, roots, nr_roots, packages, nr_packages, lease_ms);
	if (ioctl(ctl, SV_IOC_REPLACE_V2, &s))
		return -1;
	generation = expected + 1;
	owned_policy = 1;
	return 0;
}

static int reject_v2(struct sv_snapshot_v2 *s, int expected_errno)
{
	errno = 0;
	return ioctl(ctl, SV_IOC_REPLACE_V2, s) == -1 && errno == expected_errno;
}

static int expect_statx(const char *path, int expected_errno)
{
	struct statx sx;
	int ret;

	memset(&sx, 0, sizeof(sx));
	errno = 0;
	ret = statx(AT_FDCWD, path, AT_SYMLINK_NOFOLLOW,
		    STATX_BASIC_STATS, &sx);
	if (!expected_errno)
		return ret == 0;
	return ret == -1 && errno == expected_errno;
}

static int expect_openat(int dirfd, const char *name, int flags,
			 int expected_errno)
{
	int fd;

	errno = 0;
	fd = openat(dirfd, name, flags | O_CLOEXEC);
	if (!expected_errno) {
		if (fd < 0)
			return 0;
		close(fd);
		return 1;
	}
	if (fd >= 0) {
		close(fd);
		return 0;
	}
	return errno == expected_errno;
}

struct v2_concurrent_state {
	unsigned int publication_seq;
	unsigned int lookups;
	unsigned int overlapping_lookups;
};

static void v2_lookup_reader(int ready_fd, int stop_fd, int done_fd,
			     struct v2_concurrent_state *state)
{
	struct pollfd stop = { .fd = stop_fd, .events = POLLIN };
	unsigned long long count = 0;
	char token = 'R';

	alarm(15);
	if (!drop_to(UID_A))
		_exit(2);
	for (;;) {
		unsigned int before = __atomic_load_n(&state->publication_seq,
						     __ATOMIC_SEQ_CST);
		unsigned int after;

		if (!expect_statx(alpha_file, 0) || !expect_statx(beta_a, ENOENT))
			_exit(3);
		after = __atomic_load_n(&state->publication_seq, __ATOMIC_SEQ_CST);
		__atomic_add_fetch(&state->lookups, 1, __ATOMIC_SEQ_CST);
		if ((before & 1) || (after & 1) || before != after)
			__atomic_add_fetch(&state->overlapping_lookups, 1,
					   __ATOMIC_SEQ_CST);
		count++;
		if (count == 1 && write(ready_fd, &token, sizeof(token)) !=
		    sizeof(token))
			_exit(4);
		sched_yield();
		stop.revents = 0;
		if (poll(&stop, 1, 0) < 0)
			_exit(5);
		if (stop.revents & (POLLIN | POLLHUP | POLLERR))
			break;
	}
	if (write(done_fd, &count, sizeof(count)) != sizeof(count))
		_exit(6);
	_exit(0);
}

static int replace_v2_during_lookup(struct sv_root_v2 *roots,
				    struct sv_package_v2 *packages)
{
	int ready[2] = { -1, -1 }, stop[2] = { -1, -1 };
	int done[2] = { -1, -1 }, ok = 1, status = 0;
	struct sv_info_v2 info;
	struct v2_concurrent_state *state;
	unsigned long long lookups = 0;
	unsigned int overlapping = 0;
	unsigned int replacements = 0;
	struct pollfd pfd;
	pid_t pid = -1;
	char token;
	int ret;

	state = mmap(NULL, sizeof(*state), PROT_READ | PROT_WRITE,
		     MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (state == MAP_FAILED)
		return 0;
	memset(state, 0, sizeof(*state));
	if (pipe(ready) || pipe(stop) || pipe(done)) {
		ok = 0;
		goto out;
	}
	pid = fork();
	if (!pid) {
		close(ready[0]);
		close(stop[1]);
		close(done[0]);
		v2_lookup_reader(ready[1], stop[0], done[1], state);
	}
	if (pid < 0) {
		ok = 0;
		goto out;
	}
	close(ready[1]);
	ready[1] = -1;
	close(stop[0]);
	stop[0] = -1;
	close(done[1]);
	done[1] = -1;
	pfd.fd = ready[0];
	pfd.events = POLLIN;
	pfd.revents = 0;
	do {
		ret = poll(&pfd, 1, 10000);
	} while (ret < 0 && errno == EINTR);
	if (ret != 1 || !(pfd.revents & POLLIN) ||
	    read(ready[0], &token, sizeof(token)) != sizeof(token)) {
		ok = 0;
		goto stop_reader;
	}
	while (replacements < V2_REPLACE_ROUNDS) {
		__atomic_add_fetch(&state->publication_seq, 1, __ATOMIC_SEQ_CST);
		ret = publish_v2(generation, roots, 2, packages, 6,
				 V2_LIVE_LEASE_MS);
		__atomic_add_fetch(&state->publication_seq, 1, __ATOMIC_SEQ_CST);
		if (ret) {
			perror("concurrent v2 replacement");
			ok = 0;
			break;
		}
		replacements++;
		sched_yield();
	}
	close(stop[1]);
	stop[1] = -1;
	if (ok) {
		pfd.fd = done[0];
		pfd.events = POLLIN;
		pfd.revents = 0;
		do {
			ret = poll(&pfd, 1, 10000);
		} while (ret < 0 && errno == EINTR);
		if (ret != 1 || !(pfd.revents & POLLIN) ||
		    read(done[0], &lookups, sizeof(lookups)) != sizeof(lookups))
			ok = 0;
	}
stop_reader:
	if (!ok)
		kill(pid, SIGKILL);
	do {
		ret = waitpid(pid, &status, 0);
	} while (ret < 0 && errno == EINTR);
	if (ret != pid || !WIFEXITED(status) ||
	    WEXITSTATUS(status))
		ok = 0;
	if (ok && (ioctl(ctl, SV_IOC_GET_INFO_V2, &info) ||
		   info.version != SV_VERSION_V2 ||
		   info.flags != SV_INFO_F_CHILD_AWARE ||
		   info.generation != generation || info.nr_entries != 2 ||
		   info.nr_packages != 6))
		ok = 0;
out:
	lookups = __atomic_load_n(&state->lookups, __ATOMIC_SEQ_CST);
	overlapping = __atomic_load_n(&state->overlapping_lookups,
				      __ATOMIC_SEQ_CST);
	if (ready[0] >= 0)
		close(ready[0]);
	if (ready[1] >= 0)
		close(ready[1]);
	if (stop[0] >= 0)
		close(stop[0]);
	if (stop[1] >= 0)
		close(stop[1]);
	if (done[0] >= 0)
		close(done[0]);
	if (done[1] >= 0)
		close(done[1]);
	munmap(state, sizeof(*state));
	printf("# v2 concurrent lookups: %llu; overlapping: %u; replacements: %u\n",
	       lookups, overlapping, replacements);
	return ok && replacements == V2_REPLACE_ROUNDS && lookups > 0 &&
		overlapping > 0;
}

static int stat_root_a(void *arg)
{
	struct stat st;
	int fd;
	int ok;
	(void)arg;

	ok = !stat(root_a, &st) && S_ISDIR(st.st_mode);
	ok &= expect_statx(root_a, 0);
	fd = open(root_a, O_PATH | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0)
		return 0;
	ok &= faccessat(AT_FDCWD, root_a, X_OK, 0) == 0;
	ok &= expect_openat(fd, "com.example.alpha", O_PATH | O_DIRECTORY, 0);
	close(fd);
	return ok;
}

static int v1_owner_probe(void *arg)
{
	(void)arg;
	return expect_statx(alpha_file, 0) &&
		expect_openat(root_a_fd, "com.example.alpha", O_PATH | O_DIRECTORY, 0);
}

static int v1_denied_probe(void *arg)
{
	(void)arg;
	return expect_statx(root_a, ENOENT);
}

static int owned_a_operations(void *arg)
{
	int pkgfd, fd, ok = 1;
	struct stat st;
	char buf[448];
	(void)arg;

	if (!expect_statx(alpha_file, 0))
		return 0;
	pkgfd = openat(root_a_fd, "com.example.alpha",
		       O_PATH | O_DIRECTORY | O_CLOEXEC);
	if (pkgfd < 0)
		return 0;
	fd = openat(pkgfd, "known", O_PATH | O_CLOEXEC);
	ok &= fd >= 0;
	if (fd >= 0) {
		ok &= !fstat(fd, &st) && S_ISREG(st.st_mode);
		close(fd);
	}
	fd = openat(pkgfd, "created", O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC,
		    0666);
	ok &= fd >= 0;
	if (fd >= 0)
		close(fd);
	ok &= !mkdirat(pkgfd, "dir", 0777);
	ok &= syscall(SYS_renameat2, pkgfd, "created", pkgfd, "renamed",
		     RENAME_NOREPLACE) == 0;
	ok &= !unlinkat(pkgfd, "renamed", 0);
	ok &= !unlinkat(pkgfd, "dir", AT_REMOVEDIR);
	close(pkgfd);
	/* Cleanup only names this probe created if an earlier assertion failed. */
	snprintf(buf, sizeof(buf), "%s/com.example.alpha/created", root_a);
	unlink(buf);
	snprintf(buf, sizeof(buf), "%s/com.example.alpha/renamed", root_a);
	unlink(buf);
	snprintf(buf, sizeof(buf), "%s/com.example.alpha/dir", root_a);
	rmdir(buf);
	return ok;
}

static int create_allowed_package_root(void *arg)
{
	int ok;
	(void)arg;

	errno = 0;
	ok = !mkdirat(root_a_fd, "com.example.create", 0777);
	if (ok)
		ok &= !unlinkat(root_a_fd, "com.example.create", AT_REMOVEDIR);
	return ok;
}

static int hidden_existing_equals_absent_a(void *arg)
{
	int a, b, ea, eb, fd, ok = 1;
	char absent[384], absent_file[448];
	(void)arg;

	/* Existing other-package and nonexistent package names must be opaque. */
	path_join(absent, sizeof(absent), root_a, "com.example.absent");
	errno = 0;
	a = statx(AT_FDCWD, beta_a, AT_SYMLINK_NOFOLLOW,
		  STATX_BASIC_STATS, &(struct statx){ 0 });
	ea = errno;
	errno = 0;
	b = statx(AT_FDCWD, absent, AT_SYMLINK_NOFOLLOW,
		  STATX_BASIC_STATS, &(struct statx){ 0 });
	eb = errno;
	ok &= a == -1 && ea == ENOENT && b == -1 && eb == ENOENT;
	{
		struct stat st;

		errno = 0;
		a = stat(beta_a, &st);
		ea = errno;
		errno = 0;
		b = stat(absent, &st);
		eb = errno;
		ok &= a == -1 && ea == ENOENT && b == -1 && eb == ENOENT;
	}
	ok &= expect_openat(root_a_fd, "com.example.beta",
			    O_PATH | O_DIRECTORY, ENOENT);
	ok &= expect_openat(root_a_fd, "com.example.absent",
			    O_PATH | O_DIRECTORY, ENOENT);
	/* A real unlisted package beats a prefix match to com.foo / com.foo.bar. */
	ok &= expect_openat(root_a_fd, "com.foo.barx",
			    O_PATH | O_DIRECTORY, ENOENT);
	/* mkdir, rename and unlink on the protected parent share the same denial. */
	errno = 0;
	a = mkdirat(root_a_fd, "com.example.beta", 0700);
	ea = errno;
	errno = 0;
	b = mkdirat(root_a_fd, "com.example.absent", 0700);
	eb = errno;
	ok &= a == -1 && ea == ENOENT && b == -1 && eb == ENOENT;
	if (!b)
		unlinkat(root_a_fd, "com.example.absent", AT_REMOVEDIR);
	fd = openat(AT_FDCWD, staging, O_PATH | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0)
		return 0;
	/* Create owned sources in this tmpfs; never use a caller-supplied path. */
	{
		int src = openat(fd, "rename-source", O_CREAT | O_EXCL | O_WRONLY |
				 O_CLOEXEC, 0666);
		if (src < 0) {
			close(fd);
			return 0;
		}
		close(src);
	}
	errno = 0;
	a = syscall(SYS_renameat2, fd, "rename-source", root_a_fd,
		    "com.example.beta", RENAME_NOREPLACE);
	ea = errno;
	errno = 0;
	b = syscall(SYS_renameat2, fd, "rename-source", root_a_fd,
		    "com.example.absent", RENAME_NOREPLACE);
	eb = errno;
	ok &= a == -1 && ea == ENOENT && b == -1 && eb == ENOENT;
	/* If a regression created the absent target, remove only this exact file. */
	path_join(absent_file, sizeof(absent_file), root_a, "com.example.absent");
	unlink(absent_file);
	{
		int ret = unlinkat(root_a_fd, "com.example.beta", AT_REMOVEDIR);
		int err = errno;
		/* Without the policy this nonempty directory would report ENOTEMPTY. */
		ok &= ret == -1 && err == ENOENT;
		ret = unlinkat(root_a_fd, "com.example.absent", AT_REMOVEDIR);
		err = errno;
		ok &= ret == -1 && err == ENOENT;
	}
	unlinkat(fd, "rename-source", 0);
	close(fd);
	return ok;
}

static int hidden_cross_map_b(void *arg)
{
	int ret_a, ret_b, ea, eb;
	char absent[384];
	(void)arg;

	path_join(absent, sizeof(absent), root_b, "com.example.absent");
	errno = 0;
	ret_a = statx(AT_FDCWD, alpha_b, AT_SYMLINK_NOFOLLOW,
		      STATX_BASIC_STATS, &(struct statx){ 0 });
	ea = errno;
	errno = 0;
	ret_b = statx(AT_FDCWD, absent, AT_SYMLINK_NOFOLLOW,
		      STATX_BASIC_STATS, &(struct statx){ 0 });
	eb = errno;
	return ret_a == -1 && ea == ENOENT && ret_b == -1 && eb == ENOENT &&
		expect_openat(root_b_fd, "com.example.alpha",
			      O_PATH | O_DIRECTORY, ENOENT) &&
		expect_openat(root_b_fd, "com.example.absent",
			      O_PATH | O_DIRECTORY, ENOENT);
}

static int own_b_operations(void *arg)
{
	(void)arg;
	return expect_statx(beta_b_file, 0) &&
		expect_openat(root_b_fd, "com.example.beta", O_PATH | O_DIRECTORY, 0);
}

static int hidden_cross_map_a(void *arg)
{
	char absent[384];
	(void)arg;
	path_join(absent, sizeof(absent), root_b, "com.example.absent");
	return expect_statx(beta_b, ENOENT) && expect_statx(absent, ENOENT) &&
		expect_openat(root_b_fd, "com.example.beta", O_PATH | O_DIRECTORY,
			      ENOENT) &&
		expect_openat(root_b_fd, "com.example.absent", O_PATH | O_DIRECTORY,
			      ENOENT);
}

static int exact_prefix_names(void *arg)
{
	(void)arg;
	return expect_statx(foo, 0) && expect_statx(foo_bar, 0) &&
		expect_statx(foo_barx, ENOENT) &&
		expect_openat(root_a_fd, "com.foo", O_PATH | O_DIRECTORY, 0) &&
		expect_openat(root_a_fd, "com.foo.bar", O_PATH | O_DIRECTORY, 0) &&
		expect_openat(root_a_fd, "com.foo.barx", O_PATH | O_DIRECTORY,
			      ENOENT);
}

static int list_as_package_denied(void *arg)
{
	char buf[4096];
	long ret;
	(void)arg;

	errno = 0;
	ret = syscall(SYS_getdents64, list_a_fd, buf, sizeof(buf));
	return ret == -1 && errno == ENOENT;
}

static int list_as_provider_allowed(void *arg)
{
	char buf[4096];
	long ret;
	(void)arg;

	if (lseek(list_a_fd, 0, SEEK_SET) < 0)
		return 0;
	ret = syscall(SYS_getdents64, list_a_fd, buf, sizeof(buf));
	return ret > 0;
}

static int root_and_provider_access(void *arg)
{
	struct stat st;
	(void)arg;
	return !stat(root_a, &st) &&
		expect_openat(root_a_fd, "com.example.beta",
			      O_PATH | O_DIRECTORY, 0) &&
		!stat(beta_a_file, &st) && !stat(root_b, &st) &&
		expect_openat(root_b_fd, "com.example.alpha",
			      O_PATH | O_DIRECTORY, 0) && !stat(beta_b_file, &st);
}

static int held_fd_boundary(void *arg)
{
	struct stat st;
	int direct, deep;
	(void)arg;

	errno = 0;
	direct = fstat(foreign_dir_fd, &st);
	if (direct != -1 || errno != ENOENT)
		return 0;
	/* A deeper FD opened before activation remains a capability by design. */
	deep = fstat(deep_file_fd, &st);
	return deep == 0 && S_ISREG(st.st_mode) &&
		expect_statx(beta_a_file, ENOENT);
}

static int lease_expired_probe(void *arg)
{
	int ret, err;
	(void)arg;
	if (!expect_statx(alpha, ENOENT) ||
	    !expect_openat(root_a_fd, "com.example.alpha",
			   O_PATH | O_DIRECTORY, ENOENT) ||
	    !expect_openat(root_a_fd, "com.example.late",
			   O_PATH | O_DIRECTORY, ENOENT))
		return 0;
	errno = 0;
	ret = mkdirat(root_a_fd, "com.example.late", 0777);
	err = errno;
	if (!ret)
		unlinkat(root_a_fd, "com.example.late", AT_REMOVEDIR);
	return ret == -1 && err == ENOENT;
}

static int admin_empty_policy_probe(void *arg)
{
	struct sv_info_v2 i;
	struct sv_info old;
	struct sv_snapshot_v2 s;
	(void)arg;

	memset(&i, 0, sizeof(i));
	if (ioctl(ctl, SV_IOC_GET_INFO_V2, &i) ||
	    i.version != SV_VERSION_V2 || i.flags != SV_INFO_F_CHILD_AWARE ||
	    i.generation != generation || i.nr_entries != 2 || i.nr_packages != 6 ||
	    i.lease_remaining_ms != 0 || ioctl(ctl, SV_IOC_GET_INFO, &old) ||
	    old.version != SV_VERSION || old.flags || old.generation != generation)
		return 0;
	fill_v2(&s, generation, NULL, 0, NULL, 0, SV_MIN_LEASE_MS);
	if (ioctl(ctl, SV_IOC_REPLACE_V2, &s))
		return 0;
	generation++;
	owned_policy = 1;
	return 1;
}

static int after_admin_clear(void *arg)
{
	(void)arg;
	return expect_statx(alpha_file, 0) &&
		expect_openat(root_a_fd, "com.example.beta",
			      O_PATH | O_DIRECTORY, 0);
}

static int clear_policy(void)
{
	struct sv_snapshot s;

	if (!owned_policy)
		return 0;
	/* Exercise the legacy clear path after v2 as a compatibility guarantee. */
	fill_v1(&s, generation, -1, 0);
	if (ioctl(ctl, SV_IOC_REPLACE, &s))
		return -1;
	generation++;
	owned_policy = 0;
	return 0;
}

static void cleanup_fixture(void)
{
	if (deep_file_fd >= 0)
		close(deep_file_fd);
	if (foreign_dir_fd >= 0)
		close(foreign_dir_fd);
	if (list_a_fd >= 0)
		close(list_a_fd);
	if (root_a_fd >= 0)
		close(root_a_fd);
	if (root_b_fd >= 0)
		close(root_b_fd);
	if (!mounted)
		goto remove_mountpoint;
	/* Only remove fixed names created by this unique tmpfs fixture. */
	unlink(alpha_file);
	unlink(beta_a_file);
	unlink(beta_b_file);
	unlink(alpha_b_file);
	{
		char path[448];

		path_join(path, sizeof(path), staging, "rename-source");
		unlink(path);
		path_join(path, sizeof(path), root_a, "com.example.absent");
		unlink(path);
		rmdir(path);
		path_join(path, sizeof(path), root_a, "com.example.create");
		rmdir(path);
		path_join(path, sizeof(path), root_a, "com.example.late");
		rmdir(path);
		path_join(path, sizeof(path), root_a, "com.example.alpha/created");
		unlink(path);
		path_join(path, sizeof(path), root_a, "com.example.alpha/renamed");
		unlink(path);
		path_join(path, sizeof(path), root_a, "com.example.alpha/dir");
		rmdir(path);
	}
	rmdir(foo_barx);
	rmdir(foo_bar);
	rmdir(foo);
	rmdir(alpha);
	rmdir(beta_a);
	rmdir(beta_b);
	rmdir(alpha_b);
	rmdir(root_a);
	rmdir(root_b);
	rmdir(staging);
	if (umount2(fixture, 0)) {
		fprintf(stderr, "fixture mount retained at %s: %s\n",
			fixture, strerror(errno));
		return;
	}
	mounted = 0;
remove_mountpoint:
	if (*fixture && rmdir(fixture) && errno != ENOENT)
		fprintf(stderr, "fixture retained at %s: %s\n",
			fixture, strerror(errno));
}

int main(int argc, char **argv)
{
	/* mkdtemp() updates this template in place. */
	char fixture_path[] = "/tmp/scoped-visibility-v2-XXXXXX";
	struct sv_info old_info;
	struct sv_info_v2 info_v2;
	struct sv_snapshot_v2 bad_v2;
	struct sv_root_v2 roots[2];
	struct sv_package_v2 packages[6];
	struct sv_package_v2 duplicate_packages[7];
	int require = 0, ok;

	if (argc == 2 && !strcmp(argv[1], "--require-control")) {
		require = 1;
	} else if (argc != 1) {
		fprintf(stderr, "usage: %s [--require-control]\n", argv[0]);
		return 1;
	}
	fixture = fixture_path;
	setvbuf(stdout, NULL, _IONBF, 0);
	puts("TAP version 13");
	ctl = open(CONTROL, O_RDWR | O_CLOEXEC);
	if (ctl < 0) {
		if (errno == ENOENT && !require) {
			puts("1..0 # SKIP scoped visibility control absent");
			return 4;
		}
		perror(CONTROL);
		puts("not ok 1 - required control unavailable\n1..1");
		return 1;
	}
	if (geteuid() || ioctl(ctl, SV_IOC_GET_INFO, &old_info) ||
	    old_info.nr_entries) {
		puts("1..0 # SKIP requires root and empty registry (existing policy preserved)");
		close(ctl);
		return 4;
	}
	generation = old_info.generation;
	if (ioctl(ctl, SV_IOC_GET_INFO_V2, &info_v2) ||
	    info_v2.version != SV_VERSION_V2 || info_v2.generation != generation ||
	    info_v2.nr_entries || info_v2.nr_packages ||
	    info_v2.lease_remaining_ms)
		goto setup_fail;
	check((sizeof(void *) == 4 || sizeof(void *) == 8) &&
	      sizeof(uintptr_t) == sizeof(void *),
	      "native/compat process uses a supported fixed-width pointer ABI");
	check(_IOC_SIZE(SV_IOC_REPLACE) == sizeof(struct sv_snapshot) &&
	      _IOC_SIZE(SV_IOC_GET_INFO) == sizeof(struct sv_info),
	      "legacy v1 ioctl numbers and structure sizes remain stable");
	if (setup_fixture())
		goto setup_fail;
	check(1, "dedicated tmpfs fixture and held-descriptor boundary prepared");

	/* Prove the v1 writer and read ABI still work before switching to v2. */
	if (publish_v1(generation, root_a_fd, 1))
		goto setup_fail;
	check(as_uid(UID_A, v1_owner_probe, NULL),
	      "v1 full-UID range keeps its legacy subtree access");
	check(as_uid(UID_B, v1_denied_probe, NULL),
	      "v1 still denies a UID outside its range");
	if (ioctl(ctl, SV_IOC_GET_INFO, &old_info) ||
	    old_info.version != SV_VERSION || old_info.flags ||
	    old_info.generation != generation || old_info.nr_entries != 1)
		goto setup_fail;
	check(1, "v1 GET_INFO remains version 1 with its original layout");
	if (publish_v1(generation, -1, 0))
		goto setup_fail;

	fill_root(&roots[0], root_a_fd, MAP_A);
	fill_root(&roots[1], root_b_fd, MAP_B);
	/* Deliberately unsorted, with prefix names, to exercise exact name lookup. */
	fill_package(&packages[0], MAP_B, UID_B, "com.example.beta");
	fill_package(&packages[1], MAP_A, UID_A, "com.foo.bar");
	fill_package(&packages[2], MAP_A, UID_A, "com.example.late");
	fill_package(&packages[3], MAP_A, UID_A, "com.example.create");
	fill_package(&packages[4], MAP_A, UID_A, "com.foo");
	fill_package(&packages[5], MAP_A, UID_A, "com.example.alpha");
	if (publish_v2(generation, roots, 2, packages, 6,
		       V2_LIVE_LEASE_MS))
		goto setup_fail;
	check(ioctl(ctl, SV_IOC_GET_INFO_V2, &info_v2) == 0 &&
	      info_v2.version == SV_VERSION_V2 &&
	      info_v2.flags == SV_INFO_F_CHILD_AWARE &&
	      info_v2.generation == generation && info_v2.nr_entries == 2 &&
	      info_v2.nr_packages == 6 && info_v2.lease_remaining_ms > 0 &&
	      info_v2.lease_remaining_ms <= V2_LIVE_LEASE_MS,
	      "v2 publishes two mapped roots and a complete package snapshot");
	check(as_uid(UID_A, stat_root_a, NULL),
	      "ordinary package UID can stat, O_PATH-open, and search the root");
	check(as_uid(UID_A, owned_a_operations, NULL),
	      "own direct-child chain supports statx, O_PATH, openat, create, rename, unlink");
	check(as_uid(UID_A, exact_prefix_names, NULL),
	      "sorted package table resolves exact and prefix-related names separately");
	check(as_uid(UID_A, create_allowed_package_root, NULL),
	      "trusted package name can create and remove its previously absent root");
	check(as_uid(UID_A, hidden_existing_equals_absent_a, NULL),
	      "existing foreign and absent packages match across stat/openat/O_PATH/mkdir/rename/unlink");
	check(as_uid(UID_A, hidden_cross_map_a, NULL),
	      "map ID and full UID prevent cross-user package access");
	check(as_uid(UID_B, own_b_operations, NULL),
	      "second mapped user can access its own full-UID package");
	check(as_uid(UID_B, hidden_cross_map_b, NULL),
	      "second mapped user cannot resolve another user's package");
	check(as_uid(UID_A, held_fd_boundary, NULL),
	      "direct-child FD is rechecked while an older deep FD remains a capability");
	check(as_uid(UID_A, list_as_package_denied, NULL),
	      "protected root listing is denied even through a pre-opened directory FD");
	check(as_uid(UID_PROVIDER, list_as_provider_allowed, NULL),
	      "provider full UID retains administrator root listing");
	check(as_uid(UID_PROVIDER, root_and_provider_access, NULL),
	      "provider range retains access to every package on its mapped root");
	check(as_uid(0, root_and_provider_access, NULL),
	      "root UID remains an administrator across both registered roots");
	if (ioctl(ctl, SV_IOC_GET_INFO, &old_info) ||
	    old_info.version != SV_VERSION || old_info.flags ||
	    old_info.generation != generation || old_info.nr_entries != 2)
		goto setup_fail;
	check(1, "legacy v1 GET_INFO can inspect a live v2 generation");
	fill_v2(&bad_v2, generation, NULL, 0, NULL, SV_MAX_PACKAGES + 1,
		SV_MIN_LEASE_MS);
	ok = reject_v2(&bad_v2, EINVAL);
	check(ok, "v2 package count is bounded before user arrays are read");
	fill_v2(&bad_v2, generation, NULL, SV_MAX_ENTRIES + 1, NULL, 0,
		SV_MIN_LEASE_MS);
	ok = reject_v2(&bad_v2, EINVAL);
	check(ok, "v2 root count is bounded before user arrays are read");
	fill_v2(&bad_v2, generation, roots, 2, packages, 1,
		V2_LIVE_LEASE_MS);
	bad_v2.packages_ptr = 1;
	check(reject_v2(&bad_v2, EFAULT),
	      "v2 rejects an unreadable package array before publication");
	fill_v2(&bad_v2, generation, roots, 2, packages, 1,
		V2_LIVE_LEASE_MS);
	packages[0].map_id = 99;
	check(reject_v2(&bad_v2, EINVAL),
	      "v2 rejects package entries for an unknown mapped root");
	packages[0].map_id = MAP_B;
	memcpy(duplicate_packages, packages, sizeof(packages));
	fill_package(&duplicate_packages[6], MAP_A, UID_B,
		     "com.example.alpha");
	fill_v2(&bad_v2, generation, roots, 2, duplicate_packages, 7,
		V2_LIVE_LEASE_MS);
	check(reject_v2(&bad_v2, EINVAL),
	      "v2 rejects duplicate map/name entries even with different UIDs");
	fill_v2(&bad_v2, generation, roots, 2, packages, 6,
		SV_MIN_LEASE_MS - 1);
	check(reject_v2(&bad_v2, EINVAL),
	      "v2 rejects leases below the bounded interval");
	check(ioctl(ctl, SV_IOC_GET_INFO_V2, &info_v2) == 0 &&
	      info_v2.generation == generation && info_v2.nr_entries == 2 &&
	      info_v2.nr_packages == 6,
	      "rejected v2 inputs preserve the currently published snapshot");
	check(replace_v2_during_lookup(roots, packages),
	      "UID_A lookups stay consistent during 24 v2 package-array replacements");
	if (publish_v2(generation, roots, 2, packages, 6, V2_LEASE_TEST_MS))
		goto setup_fail;
	check(ioctl(ctl, SV_IOC_GET_INFO_V2, &info_v2) == 0 &&
	      info_v2.lease_remaining_ms > 0 &&
	      info_v2.lease_remaining_ms <= V2_LEASE_TEST_MS &&
	      as_uid(UID_A, v1_owner_probe, NULL),
	      "short renewed lease allows a listed package before expiry");

	/* Keep the short expiry wait separate from slower native/compat test cases. */
	{
		struct timespec delay = { .tv_sec = V2_LEASE_TEST_MS / 1000 + 1 };

		while (nanosleep(&delay, &delay) && errno == EINTR)
			;
	}
	check(as_uid(UID_A, lease_expired_probe, NULL),
	      "expired lease hides known packages and refuses package-root creation");
	check(as_uid(UID_PROVIDER, root_and_provider_access, NULL),
	      "expired lease preserves provider/admin access");
	check(as_uid(0, root_and_provider_access, NULL),
	      "expired lease preserves root UID administrator access");
	check(as_uid(UID_PROVIDER, list_as_provider_allowed, NULL),
	      "provider listing remains available after package lease expiry");
	check(as_uid(UID_A, list_as_package_denied, NULL),
	      "non-provider root listing stays denied after package lease expiry");
	check(admin_empty_policy_probe(NULL),
	      "administrator can inspect and replace an expired policy");
	check(as_uid(UID_A, after_admin_clear, NULL),
	      "administrator empty snapshot restores ordinary pathname behavior");
	if (clear_policy()) {
		perror("clear owned scoped visibility policy; fixture retained");
		close(ctl);
		return 1;
	}
	cleanup_fixture();
	close(ctl);
	printf("1..%d\n", tests);
	return failures ? 1 : 0;

setup_fail:
	perror("v2 fixture or registry operation");
	check(0, "fixture/registry operation");
	if (owned_policy && clear_policy()) {
		perror("clear owned scoped visibility policy; fixture retained");
		close(ctl);
		return 1;
	}
	cleanup_fixture();
	close(ctl);
	printf("1..%d\n", tests);
	return 1;
}
