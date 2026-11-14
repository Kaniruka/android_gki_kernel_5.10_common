// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include "../../../../include/uapi/linux/scoped_visibility.h"
#include <linux/capability.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/sysmacros.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <grp.h>
#include <sched.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <signal.h>
#include <time.h>

#define CONTROL "/sys/kernel/security/scoped_visibility/control"
_Static_assert(sizeof(struct sv_snapshot) == 4632, "snapshot ABI layout");
_Static_assert(sizeof(struct sv_info) == 536, "info ABI layout");
static int ctl = -1, failures, tests;
static char root[256], guarded[300], alias[300], file[340], missing[340];
static int bound;
static int no_caps(void);
static int fd_metadata(uid_t uid, int fd, int error)
{
	pid_t pid = fork();
	int status;

	if (!pid) {
		struct stat st;
		int ret;

		if (setgroups(0, NULL) || setresgid(uid, uid, uid) ||
		    setresuid(uid, uid, uid) || !no_caps())
			_exit(2);
		ret = fstat(fd, &st);
		_exit(error ? !(ret == -1 && errno == error) : ret != 0);
	}
	if (pid < 0 || waitpid(pid, &status, 0) != pid)
		return 0;
	return WIFEXITED(status) && !WEXITSTATUS(status);
}

static void check(int ok, const char *what)
{
	printf("%s - %s\n", ok ? "ok" : "not ok", what);
	tests++;
	if (!ok)
		failures++;
}

static int info(struct sv_info *i)
{
	memset(i, 0, sizeof(*i));
	i->version = SV_VERSION;
	return ioctl(ctl, SV_IOC_GET_INFO, i);
}

static int replace(struct sv_snapshot *s)
{
	return ioctl(ctl, SV_IOC_REPLACE, s);
}

static void snapshot(struct sv_snapshot *s, unsigned long long gen, int fd)
{
	memset(s, 0, sizeof(*s));
	s->version = SV_VERSION;
	s->expected_generation = gen;
	if (fd >= 0) {
		s->nr_entries = 1;
		s->entries[0].fd = fd;
		s->entries[0].nr_ranges = 2;
		s->entries[0].ranges[0].min = 0;
		s->entries[0].ranges[0].max = 0;
		s->entries[0].ranges[1].min = 1001;
		s->entries[0].ranges[1].max = 1001;
	}
}

static int no_caps(void)
{
	struct __user_cap_header_struct h = { _LINUX_CAPABILITY_VERSION_3, 0 };
	struct __user_cap_data_struct d[2];

	return !syscall(SYS_capget, &h, d) && !d[0].effective && !d[1].effective;
}

static int expected(int ret, int err)
{
	return err ? ret == -1 && errno == err : ret == 0;
}

static long long monotonic_ms(void)
{
	struct timespec t;

	if (clock_gettime(CLOCK_MONOTONIC, &t))
		return -1;
	return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static int await_pipe(int fd, long long deadline)
{
	struct pollfd p = { .fd = fd, .events = POLLIN };
	long long remaining = deadline - monotonic_ms();

	return remaining > 0 && poll(&p, 1, remaining) == 1 && (p.revents & POLLIN);
}

/* Both old and new snapshots deny this UID; publication must not open a gap. */
static int replace_during_lookup(int fd, unsigned long long *generation)
{
	int ready[2], stop[2], done[2], status, ok = 1, n = 0;
	long long deadline = monotonic_ms() + 10000;
	unsigned long long count = 0;
	char token;
	pid_t pid;
	struct sv_snapshot update;

	if (pipe(ready))
		return 0;
	if (pipe(stop)) {
		close(ready[0]);
		close(ready[1]);
		return 0;
	}
	if (pipe(done)) {
		close(ready[0]);
		close(ready[1]);
		close(stop[0]);
		close(stop[1]);
		return 0;
	}
	pid = fork();
	if (!pid) {
		struct stat st;
		struct pollfd p = { .fd = stop[0], .events = POLLIN };

		close(ready[0]);
		close(stop[1]);
		close(done[0]);
		alarm(10);
		if (setgroups(0, NULL) || setresgid(1002, 1002, 1002) ||
		    setresuid(1002, 1002, 1002) || !no_caps())
			_exit(2);
		for (;;) {
			if (stat(file, &st) != -1 || errno != ENOENT)
				_exit(3);
			count++;
			if (count == 1 && write(ready[1], "R", 1) != 1)
				_exit(4);
			n = poll(&p, 1, 0);
			if (n < 0)
				_exit(5);
			if (n)
				break; /* Parent closes its pipe only after publishing. */
		}
		if (write(done[1], &count, sizeof(count)) != sizeof(count))
			_exit(6);
		_exit(0);
	}
	close(ready[1]);
	close(stop[0]);
	close(done[1]);
	if (pid < 0)
		ok = 0;
	else if (!await_pipe(ready[0], deadline) || read(ready[0], &token, 1) != 1)
		ok = 0;
	for (n = 0; ok && n < 24; n++) {
		if (monotonic_ms() >= deadline) {
			ok = 0;
			break;
		}
		snapshot(&update, *generation, fd);
		if (replace(&update)) {
			ok = 0;
			break;
		}
		/* Never adopt an external writer's generation during rollback. */
		(*generation)++;
	}
	close(stop[1]);
	if (pid > 0) {
		if (!ok || !await_pipe(done[0], deadline) ||
		    read(done[0], &count, sizeof(count)) != sizeof(count)) {
			ok = 0;
			kill(pid, SIGKILL);
		}
		if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) ||
		    WEXITSTATUS(status))
			ok = 0;
	}
	close(ready[0]);
	close(done[0]);
	printf("# concurrent denied lookup count: %llu; replacements: %d\n", count, n);
	return ok && count > 0;
}

/* Every pathname probe runs after irreversible credential drop. */
static int client(uid_t uid, int denied, int admin_probe)
{
	pid_t pid = fork();
	int status;

	if (!pid) {
		struct stat st;
		struct statx sx;
		struct sv_info i;
		char a[340], b[340], source[340];
		int fd, ok = 1, e = denied ? ENOENT : 0;
		DIR *dir;

		if (setgroups(0, NULL) || setresgid(uid, uid, uid) ||
		    setresuid(uid, uid, uid) || !no_caps())
			_exit(2);
		if (admin_probe) {
			struct sv_snapshot s;

			snapshot(&s, 0, -1);
			ok = info(&i) == -1 && errno == EPERM;
			ok &= replace(&s) == -1 && errno == EPERM;
			ok &= read(ctl, &i, sizeof(i)) == -1 && errno == EPERM;
			_exit(ok ? 0 : 1);
		}
		ok &= expected(stat(file, &st), e);
		ok &= expected(stat(missing, &st), ENOENT);
		ok &= expected(statx(AT_FDCWD, file, 0, STATX_BASIC_STATS, &sx), e);
		ok &= expected(statx(AT_FDCWD, missing, 0, STATX_BASIC_STATS, &sx), ENOENT);
		fd = open(file, O_PATH);
		ok &= denied ? fd == -1 && errno == ENOENT : fd >= 0;
		if (fd >= 0)
			close(fd);
		fd = open(missing, O_PATH);
		ok &= fd == -1 && errno == ENOENT;
		snprintf(a, sizeof(a), "%s/existing", guarded);
		snprintf(b, sizeof(b), "%s/new", guarded);
		ok &= expected(mkdir(a, 0700), denied ? ENOENT : EEXIST);
		ok &= expected(mkdir(b, 0700), e);
		if (!denied)
			ok &= !rmdir(b);
		snprintf(source, sizeof(source), "%s/source-%u", root, uid);
		fd = open(source, O_CREAT | O_WRONLY | O_EXCL, 0600);
		if (fd < 0)
			_exit(3);
		close(fd);
		ok &= expected(syscall(SYS_renameat2, AT_FDCWD, source,
			AT_FDCWD, file, RENAME_NOREPLACE), denied ? ENOENT : EEXIST);
		ok &= expected(syscall(SYS_renameat2, AT_FDCWD, source,
			AT_FDCWD, missing, RENAME_NOREPLACE), e);
		if (!denied)
			ok &= !unlink(missing);
		else
			ok &= !unlink(source);
		ok &= expected(stat(guarded, &st), e);
		dir = opendir(guarded);
		ok &= denied ? !dir && errno == ENOENT : !!dir;
		if (dir)
			closedir(dir);
		if (bound) {
			snprintf(a, sizeof(a), "%s/known", alias);
			ok &= expected(stat(a, &st), e);
		}
		_exit(ok ? 0 : 1);
	}
	if (pid < 0 || waitpid(pid, &status, 0) != pid)
		return 0;
	return WIFEXITED(status) && !WEXITSTATUS(status);
}

/* Trusted setup grants only a descendant object in a private namespace. */
static int owned_view(const char *source)
{
	char view[300], own[340], first[380], second[380];
	pid_t pid;
	int status, ret = 0;

	snprintf(view, sizeof(view), "%s/view", root);
	if (mkdir(view, 0755))
		return 0;
	pid = fork();
	if (!pid) {
		struct stat st;
		int fd, ok = 1;

		if (unshare(CLONE_NEWNS) ||
		    mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL) ||
		    mount("tmpfs", view, "tmpfs", MS_NOSUID | MS_NODEV,
			  "mode=0751"))
			_exit(2);
		snprintf(own, sizeof(own), "%s/own", view);
		if (mkdir(own, 0755) || mount(source, own, NULL, MS_BIND, NULL))
			_exit(3);
		if (setgroups(0, NULL) || setresgid(1001, 1001, 1001) ||
		    setresuid(1001, 1001, 1001) || !no_caps())
			_exit(4);
		ok &= stat(file, &st) == -1 && errno == ENOENT;
		ok &= stat(own, &st) == 0;
		fd = open(own, O_RDONLY | O_DIRECTORY);
		ok &= fd >= 0;
		if (fd >= 0)
			close(fd);
		snprintf(first, sizeof(first), "%s/first", own);
		snprintf(second, sizeof(second), "%s/second", own);
		ok &= mkdir(first, 0700) == 0;
		ok &= rename(first, second) == 0;
		ok &= rmdir(second) == 0;
		_exit(ok ? 0 : 1);
	}
	if (pid > 0 && waitpid(pid, &status, 0) == pid)
		ret = WIFEXITED(status) && !WEXITSTATUS(status);
	if (rmdir(view))
		ret = 0;
	return ret;
}

int main(int argc, char **argv)
{
	struct sv_info before, after;
	struct sv_snapshot s, bad;
	struct stat st;
	char existing[340] = { 0 };
	int fd = -1, descendant_fd = -1, f, registered = 0, require = 0;
	int readonly, roret;
	unsigned long long own_generation = 0;

	if (argc == 2 && !strcmp(argv[1], "--require-control")) {
		require = 1;
	} else if (argc != 1) {
		fprintf(stderr, "usage: %s [--require-control]\n", argv[0]);
		return 1;
	}
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
	if (geteuid() || info(&before) || before.nr_entries) {
		puts("1..0 # SKIP requires root and empty registry (existing policy preserved)");
		close(ctl);
		return 4;
	}
	snprintf(root, sizeof(root), "/tmp/scoped-visibility-XXXXXX");
	if (!mkdtemp(root) || chmod(root, 0777))
		goto setup_fail;
	snprintf(guarded, sizeof(guarded), "%s/protected", root);
	snprintf(alias, sizeof(alias), "%s/alias", root);
	snprintf(file, sizeof(file), "%s/known", guarded);
	snprintf(missing, sizeof(missing), "%s/absent", guarded);
	snprintf(existing, sizeof(existing), "%s/existing", guarded);
	if (mkdir(guarded, 0777) || chmod(guarded, 0777) ||
	    mkdir(existing, 0777) || mkdir(alias, 0777))
		goto setup_fail;
	f = open(file, O_CREAT | O_EXCL | O_WRONLY, 0666);
	if (f < 0)
		goto setup_fail;
	close(f);
	fd = open(guarded, O_PATH | O_DIRECTORY);
	if (fd < 0)
		goto setup_fail;
	descendant_fd = open(existing, O_PATH | O_DIRECTORY);
	if (descendant_fd < 0)
		goto setup_fail;
	if (!mount(guarded, alias, NULL, MS_BIND, NULL))
		bound = 1;
	else
		printf("# bind alias unavailable: %s\n", strerror(errno));
	check(client(1002, 0, 0), "unprivileged observer before policy");
	snapshot(&s, before.generation, fd);
	if (replace(&s))
		goto setup_fail;
	registered = 1;
	own_generation = before.generation + 1;
	check(!info(&after) && after.version == SV_VERSION && !after.flags && !after.reserved &&
	      after.nr_entries == 1 && after.generation == before.generation + 1 &&
	      !fstat(fd, &st) && after.objects[0].ino == (unsigned long long)st.st_ino &&
	      after.objects[0].dev_major == major(st.st_dev) &&
	      after.objects[0].dev_minor == minor(st.st_dev),
	      "atomic registration exposes generation and pinned inode");
	check(client(1002, 1, 0),
	      "zero-capability observer: positive/negative probes and metadata hidden");
	if (bound) {
		check(client(1002, 1, 0), "same-inode bind alias denied");
	} else {
		puts("ok - same-inode bind alias # SKIP mount capability unavailable");
		tests++;
	}
	check(client(1001, 0, 0), "zero-capability allowed owner retains operations");
	check(client(1002, 1, 1), "inherited administrator fd rechecks caller credentials");
	check(fd_metadata(1002, fd, ENOENT), "registered directory FD metadata is checked");
	check(fd_metadata(1002, descendant_fd, 0),
	      "known boundary: preactivation descendant FD remains a capability");
	readonly = open(CONTROL, O_RDONLY | O_CLOEXEC);
	if (readonly < 0) {
		check(0, "open read-only administrator descriptor");
	} else {
		bad = s;
		bad.expected_generation = own_generation;
		roret = ioctl(readonly, SV_IOC_REPLACE, &bad);
		check(roret == -1 && errno == EBADF,
		      "read-only control descriptor cannot replace policy");
		if (!roret)
			own_generation++;
		close(readonly);
	}
	if (!replace_during_lookup(fd, &own_generation)) {
		check(0, "bounded concurrent snapshot replacement preserves denial");
		goto cleanup;
	}
	check(1, "bounded concurrent snapshot replacement preserves denial");
	if (info(&after) || after.generation != own_generation)
		goto setup_fail;
	/* Keep s deliberately stale for the following optimistic-write test. */
	bad = s;
	errno = 0;
	check(replace(&bad) == -1 && errno == EAGAIN, "stale snapshot rejected");
	bad.expected_generation = after.generation;
	bad.flags = 1;
	check(replace(&bad) == -1 && errno == EINVAL, "invalid snapshot rejected");
	bad = s;
	bad.expected_generation = after.generation;
	bad.nr_entries = 2;
	bad.entries[1] = bad.entries[0];
	check(replace(&bad) == -1 && errno == EINVAL, "duplicate inode rejected");
	bad = s;
	bad.expected_generation = after.generation;
	bad.entries[0].ranges[1].max = (__u32)-1;
	check(replace(&bad) == -1 && errno == EINVAL, "invalid UID rejected");
	bad = s;
	bad.expected_generation = after.generation;
	bad.entries[0].ranges[1].min = 0;
	check(replace(&bad) == -1 && errno == EINVAL, "overlapping UID ranges rejected");
	bad = s;
	bad.expected_generation = after.generation;
	bad.entries[0].fd = -1;
	check(replace(&bad) == -1 && errno == EBADF, "invalid directory FD rejected");
	check(read(ctl, &before, 1) == -1 && errno == EMSGSIZE,
	      "short status read cannot mix policy generations");
	check(read(ctl, &before, sizeof(before)) == sizeof(before) &&
	      before.generation == after.generation && before.nr_entries == 1 &&
	      read(ctl, &before, sizeof(before)) == 0,
	      "complete binary status read returns one coherent snapshot");
	check(!info(&before) && before.generation == after.generation && before.nr_entries == 1 &&
	      client(1002, 1, 0), "rejected updates preserve old policy");
	if (chown(existing, 1001, 1001) || chmod(existing, 0700))
		goto setup_fail;
	snapshot(&s, own_generation, fd);
	s.entries[0].nr_ranges = 1;
	memset(&s.entries[0].ranges[1], 0,
	       sizeof(s.entries[0].ranges) - sizeof(s.entries[0].ranges[0]));
	if (replace(&s))
		goto setup_fail;
	own_generation++;
	check(client(1001, 1, 0), "admin-only raw container rejects ordinary owner traversal");
	check(owned_view(existing),
	      "private tmpfs parent and owned child bind preserve legal access");
	snapshot(&s, own_generation, -1);
	if (replace(&s))
		goto setup_fail;
	registered = 0;
	check(client(1002, 0, 0), "empty snapshot restores pathname behavior");
	goto cleanup;
setup_fail:
	perror("fixture or registry operation");
	check(0, "fixture/registry operation");
cleanup:
	/* Clear pins before unmount/unlink. Never recursively remove anything. */
	if (registered) {
		snapshot(&s, own_generation, -1);
		if (replace(&s)) {
			perror("clear registry; fixture retained");
			return 1;
		}
	}
	if (fd >= 0)
		close(fd);
	if (descendant_fd >= 0)
		close(descendant_fd);
	if (bound && umount(alias)) {
		perror("umount; fixture retained");
		return 1;
	}
	if (*file)
		unlink(file);
	if (*existing)
		rmdir(existing);
	if (*alias)
		rmdir(alias);
	if (*guarded)
		rmdir(guarded);
	if (*root && rmdir(root) && errno != ENOENT) {
		fprintf(stderr, "fixture retained at %s: %s\n", root, strerror(errno));
		check(0, "remove owned fixture (no recursive cleanup)");
	}
	close(ctl);
	printf("1..%d\n", tests);
	return failures ? 1 : 0;
}
