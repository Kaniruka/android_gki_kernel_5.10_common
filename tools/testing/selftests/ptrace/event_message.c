// SPDX-License-Identifier: GPL-2.0-only
/* Verify event messages belong to the current ptrace stop. */
#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

#include "../kselftest_harness.h"

FIXTURE(event_message) {
	pid_t pid;
};

FIXTURE_SETUP(event_message)
{
	self->pid = -1;
}

FIXTURE_TEARDOWN(event_message)
{
	if (self->pid > 0) {
		kill(self->pid, SIGKILL);
		waitpid(self->pid, NULL, 0);
	}
}

TEST_F(event_message, exec_then_signal)
{
	unsigned long message;
	int status;

	self->pid = fork();
	ASSERT_GE(self->pid, 0);
	if (!self->pid) {
		if (ptrace(PTRACE_TRACEME, 0, NULL, NULL))
			_exit(1);
		raise(SIGSTOP);
		execl("/proc/self/exe", "event_message", "--tracee", NULL);
		_exit(1);
	}
	ASSERT_EQ(waitpid(self->pid, &status, 0), self->pid);
	ASSERT_TRUE(WIFSTOPPED(status));
	ASSERT_EQ(WSTOPSIG(status), SIGSTOP);
	ASSERT_EQ(ptrace(PTRACE_SETOPTIONS, self->pid, NULL,
			PTRACE_O_TRACEEXEC), 0);
	ASSERT_EQ(ptrace(PTRACE_CONT, self->pid, NULL, NULL), 0);
	ASSERT_EQ(waitpid(self->pid, &status, 0), self->pid);
	ASSERT_EQ(status >> 8, SIGTRAP | (PTRACE_EVENT_EXEC << 8));
	ASSERT_EQ(ptrace(PTRACE_GETEVENTMSG, self->pid, NULL, &message), 0);
	ASSERT_EQ(message, (unsigned long)self->pid);
	/* Reading a legitimate event must not consume or clear its payload. */
	ASSERT_EQ(ptrace(PTRACE_GETEVENTMSG, self->pid, NULL, &message), 0);
	ASSERT_EQ(message, (unsigned long)self->pid);
	ASSERT_EQ(kill(self->pid, SIGUSR1), 0);
	ASSERT_EQ(ptrace(PTRACE_CONT, self->pid, NULL, NULL), 0);
	ASSERT_EQ(waitpid(self->pid, &status, 0), self->pid);
	ASSERT_EQ(status >> 8, SIGUSR1);
	message = ~0UL;
	ASSERT_EQ(ptrace(PTRACE_GETEVENTMSG, self->pid, NULL, &message), 0);
	ASSERT_EQ(message, 0UL);
	ASSERT_EQ(ptrace(PTRACE_CONT, self->pid, NULL, NULL), 0);
	ASSERT_EQ(waitpid(self->pid, &status, 0), self->pid);
	ASSERT_TRUE(WIFEXITED(status));
	ASSERT_EQ(WEXITSTATUS(status), 0);
	self->pid = -1;
}

int main(int argc, char **argv)
{
	if (argc == 2 && !strcmp(argv[1], "--tracee"))
		return 0;
	return test_harness_run(argc, argv);
}
