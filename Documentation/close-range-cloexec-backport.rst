close_range CLOSE_RANGE_CLOEXEC backport
========================================

This tree backports the Linux 5.11 ``close_range(2)`` ``CLOSE_RANGE_CLOEXEC``
semantics required by Android userspace that marks descriptors close-on-exec
without closing them. The implementation, UAPI flag and regression coverage
derive from these upstream commits, under the original kernel file licenses:

* 582f1fb6b721facf04848d2ca57f34468da1813e, Giuseppe Scrivano,
  "fs, close_range: add flag CLOSE_RANGE_CLOEXEC".
* fec8a6a691033f2538cd46848f17f337f0739923, Christian Brauner,
  "close_range: unshare all fds for CLOSE_RANGE_UNSHARE |
  CLOSE_RANGE_CLOEXEC".
* 9b5b872215fe6d1ca6a1ef411f130bd58e269012, Christian Brauner,
  "file: fix close_range() for unshare+cloexec".
* 23afeaeff3d985b07abf2c76fd12b8c548da8367, Giuseppe Scrivano,
  "selftests: core: add tests for CLOSE_RANGE_CLOEXEC".

Each commit is available at https://git.kernel.org/torvalds/c/ followed by
its full commit ID. Original author and sign-off metadata are retained in the
source patches accompanying the local backport evidence.

The first two commits are a pair and the third is mandatory. CLOSE_RANGE_CLOEXEC
alone is not correct: an unshare that copies only the descriptors below the
lowest requested one drops descriptors the caller still intends to use, and the
close-on-exec bitmap bound must be recomputed from the descriptor table that is
actually installed rather than from the pre-unshare maximum.

Behaviour after the backport:

* ``close_range(first, last, CLOSE_RANGE_CLOEXEC)`` sets FD_CLOEXEC on
  descriptors in the inclusive range and closes nothing. Descriptors outside the
  range keep their previous flags.
* ``close_range(first, last, 0)`` keeps closing descriptors.
* ``CLOSE_RANGE_UNSHARE`` keeps its existing private-table semantics.
* ``CLOSE_RANGE_CLOEXEC | CLOSE_RANGE_UNSHARE`` installs a private table that
  retains every descriptor the caller still needs, and leaves the table that
  other ``CLONE_FILES`` users share unmodified. The bitmap is capped to the
  last valid index of the private table while ``file_lock`` is held.
* Unknown flag bits and a reversed range still return ``-EINVAL``.

The 5.10 adaptation is limited to ``fs/file.c`` and the UAPI header. It keeps
this tree's existing descriptor helpers and locking, extracts the unchanged
close loop into ``__range_close()``, and adds ``last_fd()`` plus
``__range_cloexec()`` with the upstream clamping fix. ``bitmap_set()`` needs an
explicit ``<linux/bitmap.h>`` include in 5.10. No syscall table, architecture,
KMI, ABI or module symbol change is involved: arm64 already routes
``__NR_close_range`` to 436 with a 4-byte flags argument.

The selftest port targets this tree's ``kselftest_harness.h``, which provides
``SKIP`` but no ``XFAIL`` macro. An unavailable ``close_range`` syscall
(``ENOSYS``) is therefore skipped as an unsupported host, while a missing
``CLOSE_RANGE_CLOEXEC`` implementation (``EINVAL``) is a hard failure rather than
an expected failure or a skip. The ported test also covers the common
``close_range(3, UINT_MAX, CLOSE_RANGE_CLOEXEC)`` shape. Two additional
regression tests cover shared-table isolation and a shrunk table: the suite
grows the descriptor table, leaves a low descriptor set open, then unshares and
truncates while requesting close-on-exec up to ``~0U``, which only stays within
bounds when both follow-up fixes are present. That test then allocates one more
descriptor and requires the lowest free number: a missing clamp writes one word
past ``close_on_exec``, which for a table of exactly ``NR_OPEN_DEFAULT`` entries
lands in ``open_fds_init``, so the next allocation skips the free descriptor
range. Checking descriptor flags alone would not expose that corruption because
every existing descriptor still reports its original state. The tests use the harness
``struct __clone_args`` so that ``sys_clone3()`` type checking is satisfied.

Three checkpatch hints are deliberately not applied, because following them
would diverge from the upstream text or from the userspace contract: the
``CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC`` condition keeps the upstream
parentheses so the imported line stays comparable with its source commit; the
flag definitions keep the upstream ``(1U << n)`` form, which the userspace
selftest copy needs and which the ``BIT()`` macro cannot replace outside the
kernel; and the ``ENOSYS`` branch stays because the selftest maps a missing
``__NR_close_range`` to -1, so ``syscall(-1)`` legitimately reports ``ENOSYS``
and the test skips instead of failing on a host without the syscall.

Validation boundaries: compiling and running the core selftest on an x86-64
host exercises the test logic and that host's kernel only. It does not prove
that this 5.10 backport behaves correctly on any target kernel, and a source
build of a single object is not a full kernel build. Behaviour on a device,
including hotspot operation, requires a separately built image and device-side
verification; a successful host run is not evidence of device boot or of
userspace success.
