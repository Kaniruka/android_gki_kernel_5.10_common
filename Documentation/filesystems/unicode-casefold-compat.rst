Unicode ignorable characters and existing directory hashes
========================================================

This kernel preserves Default_Ignorable_Code_Point characters during NFD
and casefold normalization.  For example, ``a<U+200B>b`` differs from ``ab``.
ASCII case equivalence and canonical Unicode decomposition still apply.
This closes the ignorable-character alias used across Android FUSE and
backing casefold lookup boundaries.  It is independent of KernelSU/SUSFS
and is included in both root profiles.  This does not claim to fix every
FUSE package-visibility or cached-dentry disclosure issue.

Provenance
----------

Unicode generator and shipped data: upstream commit
5c26d2f1d3f5e4be3e196526bead29ecb139cf91, stable 5.10 backport
39fffca572844d733b137a0ff9eacd67b9b0c8e3.  The byte iterator is unchanged;
normalization lengths and output use the same updated tables.

ext4 compatibility lookup is adapted from upstream commit
9e28059d56649a7212d5b3f8751ec021154ba3dd.  F2FS already contains the linear
lookup introduced by 91b587ba79e1b68bb718d12b0758dbcdab4e9cb7.

Compatibility policy
--------------------

Old casefold names can have stored hashes computed after dropping these
characters.  A hash lookup miss therefore falls back to scanning names
using current equality.  This covers old exact spellings without rewriting
directory entries, including encrypted names when their key is available.
The opaque fscrypt no-key name matching path remains unchanged.

Compatibility scanning is mandatory for casefold directories.  The old
encoding flag saying no compatibility scan is needed cannot certify that
hashes were generated with these new tables and is not used to bypass the
scan.  F2FS still accepts ``lookup_mode=perf``, ``compat`` and ``auto`` so
existing fstab entries continue to mount; all select effective ``compat``.
The ``perf`` alias emits a warning once, and mount options and sysfs report
the effective mode.  Non-casefold directories do not use the fallback.
Negative casefold lookups and old-hash lookups can cost a directory scan.

Historical aliases are deliberately no longer equivalent.  Once a new
kernel creates both ``ab`` and ``a<U+200B>b``, an old kernel can consider
them equal.  Rolling back to old normalization semantics is not guaranteed
safe.  Do not downgrade a writable filesystem containing such names
without checking and resolving legacy-equivalent collisions.  This change
does not silently migrate on-disk hashes or implement downgrade conversion.

Validation
----------

Enable CONFIG_UNICODE_NORMALIZATION_SELFTEST to run the kernel Unicode
vectors, including preserved ignorable characters and their lengths.
``tools/testing/selftests/filesystems/unicode_casefold_compat.py`` provides
a manual, argument-taking two-kernel test on a disposable mounted ext4/F2FS
filesystem; it is not an automatic no-argument test.  Run its
``prepare DIRECTORY`` phase under the old kernel, unmount, then run
``check DIRECTORY`` under this kernel.  It checks small and larger
directories, exact-name reads, enumeration, alias rejection, rename,
unlink and distinct new names.  The first check deletes an old-hash entry
before any rename can rebuild its hash.  Remount and repeat check to
exercise persistence; repeats do not prove old-hash deletion again.
Inspect layouts with filesystem tools to establish actual
inline and indexed directory coverage; entry counts alone do not prove it.
Run each F2FS lookup_mode spelling and check that effective
mode is compat.  Repeat with a keyed encrypted parent directory; verify
opaque names separately after removing its key.  The script does not
format, mount or boot a kernel.

Host source-API checks and successful compilation do not prove filesystem
runtime compatibility.  The old-image/new-kernel cases, encrypted no-key
cases and device behavior require the corresponding runtime environment.
