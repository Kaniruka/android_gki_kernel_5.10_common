Experimental scoped directory visibility registry
==================================================

This source-only interface feasibility prototype is disabled by default with
CONFIG_SECURITY_SCOPED_VISIBILITY. It depends on SECURITYFS and is independent
of root integration profiles. It is not a complete FUSE or Android privacy fix.
No runtime, boot, lifecycle or performance guarantee follows from compilation.

Interface
---------

The root-owned mode 0600 securityfs node ``scoped_visibility/control`` provides
SV_IOC_GET_INFO and SV_IOC_REPLACE from ``linux/scoped_visibility.h``. Every
read and ioctl checks current initial-user-namespace CAP_SYS_ADMIN, including
on inherited descriptors. A user namespace's root cannot manage the registry.
Normal DAC and SELinux policy also apply. Read returns one complete binary
sv_info record; a smaller nonzero buffer is rejected with EMSGSIZE, and subsequent
reads return EOF. GET_INFO returns a fresh coherent record in one ioctl.

All structures have fixed-width fields and identical native/compat layouts.
The ioctl type 0xF7, commands 0 and 1, is a local experimental range in this
tree, not an upstream allocation or a frozen ABI.
Version is 1; flags and all reserved or unused entries/ranges must be zero.
REPLACE also requires a control descriptor opened for writing.
REPLACE supplies expected_generation and up to 32 entries. Each entry supplies
an authoritative directory FD (including O_PATH) and 1..16 initial-namespace
UID intervals. Intervals are inclusive, sorted and nonoverlapping; invalid
UIDs and duplicate directory inode objects are rejected. Empty registry is
permitted. The kernel parses neither package names nor Android UID arithmetic.
Path acquisition, classification and identity policy belong to the trusted
initializer. A concurrent FD-table change has ordinary FD syscall semantics.

Initial generation is 0. Each successful replacement, including clear,
increments it once. Stale expected_generation returns EAGAIN, generation
exhaustion returns EOVERFLOW. Invalid input, FD failure and allocation failure
leave the previous snapshot intact. GET_INFO returns generation, count and
dev-major/dev-minor/inode diagnostic identities in input order. These numbers
are not authorization tokens; enforcement compares pinned inode pointers.

Enforcement and lifetime
-----------------------

Directory MAY_EXEC or MAY_READ permission checks and vfs_getattr consult the
registry using the caller's current fsuid on every decision. A matching object
with no allowed interval returns ENOENT. There is no implicit privileged-UID
or capability bypass for these decisions. Allowed and unregistered objects
continue through all normal DAC, filesystem and SELinux checks. Parent search
checks run before positive and negative child lookup outcomes, including RCU
walk. Metadata checks also cover a held FD to the registered directory itself.
Existing open directory readdir uses the VFS file_permission path and is not
revoked by this prototype; enrollment must precede unauthorized FD acquisition.

Policies are bounded, immutable and read under RCU without blocking locks,
allocation or filesystem calls. Writers prepare and validate complete new
snapshots, retaining a path reference and a separate igrab inode reference per
entry. Both references matter: an unlinked dentry can become negative while the
inode identity must remain alive. A writer mutex serializes publication and
generation comparison. After synchronize_rcu, references are released in
process context, never in an RCU callback. Failed preparation releases every
acquired reference. Retained mount references can prevent normal unmount until
policy clear/replacement; lazy detached mounts may also remain pinned.

Explicit counterexamples and external requirements
-------------------------------------------------

For a native-view experiment, raw private containers can be limited to
explicitly authorized provider/administrator UIDs, with no ordinary app
permission to traverse them. Legal own/shared-UID access then requires a
private tmpfs parent and authorized descendant bind objects. Merely placing
an own bind below a restricted raw parent is insufficient: parent search is
checked first. This policy makes a same-inode broad container export fail
closed, but it may break own access until the proper native view is restored.
The kernel does not infer these UID sets or enroll the objects automatically.

* Recreated or replaced directory roots have different inode identity and are
  not automatically enrolled. Same-inode bind aliases share a rule, but a bind
  of a deeper descendant bypasses the registered parent entirely.
* A preactivation descendant FD, transferred FD or other route starting below
  the protected parent is a capability. Descendant metadata and existing open
  files are not revoked. Current permission checks do not prove complete
  revocation for cached permissions or all filesystem internal operations.
* Allowing a user domain on a container cannot hide other packages of the same
  user when the complete lower data tree is exported. Correct native own/shared
  UID views remain mandatory; a later broad export breaks this dependency.
* The kernel does not establish trusted initializer readiness, block app
  launch, handle UID reuse, or enroll user-unlock/volume/remount replacements.
  The initializer must supply authoritative objects and intervals, enforce
  activation before untrusted code, and coordinate process lifecycle updates.
* No package-manager visibility semantics, media-policy rewrite, rootless
  initializer, persistent policy or automatic subtree classification is
  provided. Do not enroll Android ancestors or public media to disguise an
  incomplete private-directory view.

Source review and builds establish interface feasibility only. Meaningful
device acceptance requires a separately authorized patched-kernel boot plus
ordinary-app, cache, namespace, lifecycle, native-view and concurrency tests.
