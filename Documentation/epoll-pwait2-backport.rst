epoll_pwait2 backport
====================

This tree backports the Linux 5.11 epoll_pwait2 syscall for userspace that
requires a nanosecond timeout. The implementation and syscall registration
derive from these upstream commits, under the original kernel file licenses:

* 7cdf7c20e97141eadb05121cc521c8eff47e7d93, Willem de Bruijn,
  "epoll: convert internal api to timespec64".
* 58169a52ebc9a733aeb5bea857bc5daa71a301bb, Willem de Bruijn,
  "epoll: add syscall epoll_pwait2".
* b0a0c2615f6f199a656ed8549d7dce625d77aa77, Willem de Bruijn,
  "epoll: wire up syscall epoll_pwait2".
* 450f68e2425e63228d91f346547714076fc5f3e8, Heiko Carstens,
  "epoll: fix compat syscall wire up of epoll_pwait2".

Each commit is available at https://git.kernel.org/torvalds/c/ followed by
its full commit ID. Original author and sign-off metadata are retained in the
source patches accompanying the local backport evidence.

The 5.10 adaptation retains this tree's existing epoll ready-list, locking,
wakeup and signal handling fixes. It changes only the timeout representation
and adds the native and compat syscall entry points. Syscall table additions
cover the same architectures as upstream, including its compat correction.
The generic and arm64 compat syscall counts remain 449, since this tree
already includes process_mrelease at number 448; epoll_pwait2 fills number
441 (551 on alpha).

epoll_wait and epoll_pwait retain millisecond arguments, zero for nonblocking
operation and negative values for an infinite wait. epoll_pwait2 consumes a
time64 __kernel_timespec, validates it through poll_select_set_timeout, and
passes an absolute nanosecond deadline to the existing hrtimer wait path.
A NULL timeout means an infinite wait. Signal masks use the existing native
or compat save/restore paths; invalid user pointers and invalid timespecs
return the upstream errors rather than a synthetic successful wait.

Validation must cover zero, sub-millisecond, infinite and invalid timeouts,
event delivery, signal interruption and restoration, and native/compat
syscall dispatch. Source checks alone do not establish device boot success.
