Experimental scoped directory visibility registry
==================================================

This experimental registry is disabled by default with
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
The ioctl type 0xF7, commands 0 through 3, is a local experimental range in
this tree, not an upstream allocation or a frozen ABI.
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

Version-1 enforcement and lifetime
----------------------------------

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

Version-1 counterexamples and external requirements
--------------------------------------------------

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

Source review and builds alone establish interface feasibility only. Meaningful
device acceptance requires a separately authorized patched-kernel boot plus
ordinary-app, cache, namespace, lifecycle, native-view and concurrency tests.

Child-aware version 2
---------------------

``SV_IOC_REPLACE_V2`` (command 2) publishes a complete version-2 policy under
exactly the same initial-user-namespace CAP_SYS_ADMIN, write-descriptor and
generation rules. Version 1, including its ioctl numbers and semantics, remains
available. Both replacement commands replace the whole policy, rather than
merging rules. Old GET_INFO/read records remain version-1 diagnostic records;
they do not identify the policy mode. New ``SV_IOC_GET_INFO_V2`` (command 3)
always returns version 2, and ``SV_INFO_F_CHILD_AWARE`` reports whether the
active policy is child-aware. It reports package count as well as root count.
``lease_remaining_ms`` reports rounded-up remaining running time (zero after
expiry or with no active v2 policy). Counts remain diagnostic even after the
lease expires. An empty v2 snapshot still has a policy deadline: a positive
remaining value alone proves neither root protection nor package grants;
interpret it together with flags and both counts. It does not return names or
authorized UIDs.

The fixed-width ``sv_snapshot_v2`` header is 56 bytes. Its aligned 64-bit
``roots_ptr`` and ``packages_ptr`` address arrays of at most 32 ``sv_root_v2``
records (144 bytes each) and 4096 ``sv_package_v2`` records (264 bytes each).
Native arm64 and arm32 compat callers use identical layouts. Each root pins a
directory FD and supplies 1..16 sorted nonoverlapping full-UID ranges plus a
``map_id``. Ranges authorize container enumeration and all child names; no UID
or capability is implicitly privileged. Root inode objects must be unique.
Each package record contains map_id, one full initial-namespace UID and a
NUL-terminated name component of at most 255 bytes. Name trailing storage must
be zero; empty names, slash, dot and dot-dot, invalid UIDs, unknown map_ids and
duplicate (map_id, name) pairs are rejected with EINVAL. Distinct names may
map to the same UID (shared UID). No inode ownership or Android UID arithmetic
is consulted. The trusted controller must resolve package identity correctly.

Several lower/FUSE data/obb roots for one Android user can reference the same
map_id and share one package table. The kernel treats map_id as opaque; roots
for different Android users must receive separate maps, even if their appIds
coincide. A name authorizes exactly its associated full UID. Names are matched
in full, without prefixes, case folding or inode-owner fallback. Packages are
sorted at publication; lookup uses bounded binary search. An empty package
table with retained roots is valid and denies all non-range child access.
Unused pointers (zero record count), flags and reserved fields must be zero.
All user arrays are copied, validated and pinned before publication. Errors
leave the previous policy intact.

For version 2 only, ordinary callers can stat, O_PATH-open and search the
registered root. Opening it for reading and enumerating it return ENOENT;
``iterate_dir`` rechecks enumeration on a root FD acquired before publication.
Allowing observation of the container enables ordinary component-by-component
openat and mkdirs; it grants no child access. Positive and negative child
lookup, atomic open, create, delete and both rename endpoints check the child
name and caller fsuid before the filesystem operation. Direct-child metadata
through an already-held FD is also rechecked. Successful checks continue
through ordinary DAC, SELinux and filesystem permission checks. Dot/dot-dot do
not supply a package authorization: returning to the root still requires the
next normal component to pass its name rule. Enrolling a root does not change
normal permissions on its ancestor directories.

``lease_ms`` must be 1000..300000. Publication sets a deadline using
``ktime_get_ns`` (CLOCK_MONOTONIC, excluding suspend time). Once expired, all
non-range child names return ENOENT, including previously authorized names;
root search/metadata and enumeration policy remain unchanged. Range-authorized
administrators/providers continue to work. The controller should revalidate
PackageManager and republish before expiry (for example 60-second leases,
20-second refreshes). Leases bound stale authorization after a controller
stops in running time; they do not provide immediate uninstall/UID-reuse
revocation or bound suspend time. Publication is asynchronous to package
lifecycle, so a refresh interval remains a possible stale-identity window.

Version-2 boundaries
~~~~~~~~~~~~~~~~~~~~

This is a VFS container-entry policy, independent of a particular ROM's native
own-directory bind setup. It does not change FUSE daemon or SELinux policy.
Every relevant view must still expose an enrolled root inode. Recreated roots,
separately materialized filesystem views and unregistered aliases need new
trusted enrollment. Existing FDs starting deeper than the first child remain
capabilities, and arbitrary deeper binds are not protected by a recursive
ancestry classifier. Direct-child metadata checks do not establish complete
revocation of already-open files, cached filesystem-internal permissions or
FD-relative operations starting below the container. No RCU ancestor walk or
subtree-wide inode tagging is implemented. Tests must describe these limits;
they are not evidence of universal revocation or production performance.

Recorded core verification
~~~~~~~~~~~~~~~~~~~~~~~~~~

The 2026-11-15 arm64 QEMU runs passed the public-interface v1 (22 cases) and
v2 (37 cases) tests in native and arm32 compat processes, for both a rootless
generic Image and the mayfly BakaSU/SUSFS device-configuration Image. This
includes real VFS positive/negative lookups, creation/rename, root-FD listing,
held-FD boundaries, lease expiry/diagnostics and 24 concurrent same-semantics
v2 replacements per process with overlapping lookups. The final external
module helper also completed status/clear/status against each actual guest.
See ``tools/testing/selftests/scoped_visibility/README`` for the test scope.
These tmpfs guest results do not establish device FUSE/F2FS behavior, Android
ordinary-app integration, full revocation/lifecycle handling or performance.
