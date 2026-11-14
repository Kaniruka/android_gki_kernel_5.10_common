# Baseband Guard for Android common 5.10

Derived from [vc-teahouse/Baseband-guard](https://github.com/vc-teahouse/Baseband-guard),
revision **028ff7fd509e2104596da7cc1ef8e6ce2a0c9082**, by 秋刀鱼 / TG@qdykernel.
The upstream GPL v2 license is retained in `LICENSE`. This is a reviewed 5.10
adaptation of its policy and hooks, not an invocation of upstream `setup.sh`.

Build with `CONFIG_SECURITY_SELINUX=y`, `CONFIG_BBG=y`, and append
`baseband_guard` to the existing `CONFIG_LSM` list. Keep SELinux in that list.
The basic protection defaults on in Kconfig; `CONFIG_BBG_BLOCK_BOOT` and
`CONFIG_BBG_BLOCK_RECOVERY` default off. Kconfig alone does not activate an LSM
omitted from the list. A boot-time `lsm=` override must include both modules.
There is no runtime switch or SELinux policy modification.

## Effective policy

| Caller / operation | Result from this LSM |
| --- | --- |
| Non-block inode, block read, ioctl outside the list below | Allow |
| Caller outside the su/magisk/ksu domains, with no sticky restriction | Allow |
| Restricted caller, allowlisted block partition or zram whole device | Allow |
| Restricted caller, other block device, write / setattr / listed ioctl | `-EPERM` |

An allow means that the remaining DAC and LSM checks still apply; it never
overrides a SELinux denial. Restriction depends on actual SELinux credential
SID or previous-exec SID matching `u:r:su:s0`, `u:r:magisk:s0`, or `u:r:ksu:s0`.
Executable names, paths, UID, argv and comm do not grant trust. Once exec sees a
restricted current or proposed credential, a private LSM credential flag remains
restricted across fork, exec and credential preparation/transfer. Credential
blob allocation/free is owned by the 5.10 LSM core; failed allocation returns
`-ENOMEM` before hooks run. Domain conversion errors other than absent-domain
`-EINVAL` restrict rather than granting access. No SID cache survives policy
reloads. Before SELinux policy initialization, upstream's trusted boot behavior
is retained; disabling/removing SELinux is outside this protection model.

Allowed partition labels are `dtbo`, `userdata`, `cache`, `metadata`, `misc`,
`vbmeta`, `vbmeta_system`, `vbmeta_vendor`, and (by default) `boot`, `init_boot`,
`vendor_boot`, `vendor_kernel_boot`, `recovery`. Exact labels and active-slot
`_a`/`_b` forms are accepted. If no valid `androidboot.slot_suffix` command-line
token exists, both suffixes are accepted, as upstream does. Bootconfig is not
parsed. Whole disks and unlabeled devices are denied for restricted callers,
except whole devices whose kernel disk name starts with `zram` (upstream policy).
`modem`, `modemst1/2`, `fsg`, `persist`, `super` are not on the allowlist.

Destructive ioctl checks cover `BLKDISCARD`, `BLKSECDISCARD`, `BLKZEROOUT`,
`BLKPG`, `BLKRRPART`, and **`BLKROSET`** in native and compat hooks. The last
uses the actual 5.10 constant, fixing upstream's ineffective `BLKSETRO` guard.
Other device-specific ioctls, mmap/DAX writes, kernel-internal writes, mounted
filesystem writes, and alternate hardware interfaces are not comprehensive
targets of these hooks. A privileged caller able to change SELinux domains
without an intervening marked exec, change policy, or alter the kernel is not
contained by this feature. This is not a general anti-root security boundary.

## Changes from upstream and lifetime review

* The unsynchronized, unbounded, never-invalidated `allowed_devs` hash is
  removed. Every restricted operation resolves the current device. There is no
  cache allocation, data race, or stale authorization after dev_t reuse.
* `get_gendisk()` / `put_disk_and_module()` and `disk_get_part()` /
  `disk_put_part()` balance both disk/module and partition references. Partition
  metadata is immutable after publication and freed with the partition. No
  block-device open is performed recursively from permission hooks. A missing
  disk/partition/metadata denies access. Lookups may sleep in these VFS hooks.
* A separate `DEFINE_LSM` blob replaces SELinux structure injection. Its
  `unsigned long` flag preserves alignment for a following LSM blob. Normal
  prepare/transfer hooks copy the flag; no separate allocation is necessary.
* `bprm_check_security`, after exec credentials are computed, replaces upstream
  `bprm_creds_for_exec`, whose observation of new SELinux SID depends on LSM
  hook order. The current domain is also checked at protected operations, so a
  direct root-domain operation without exec is restricted. This tightens the
  upstream pre-exec window without adding any trusted domains.
* Upstream lazily cached global SIDs are replaced by per-check resolution.
  This avoids concurrent initialization and stale SID assumptions but adds
  context conversion work. Cache removal adds referenced block lookups to
  restricted operations. No performance measurements have been made.
* Kbuild generates private flask headers through the normal host generator;
  there are no parse-time shell builds, network fetches, or SELinux edits.

## Validation and limits

`sh security/baseband_guard/tests/run.sh` compiles the **production** `policy.h`
with four boot/recovery configurations. It checks exact names, active/inactive
slots, malformed command-line tokens, bounded/nonterminated labels, denied
critical labels, destructive versus query ioctls, SID/osid matching and
allocation/error fail-closed decisions. These are host policy tests, not a
simulated kernel or proof of the VFS/credential hook paths.

The adapted arm64 object was built with Android Clang r416183b in an independent
output directory. `W=1` preparation fails in the pre-existing arm64 vDSO for
missing prototypes; the normal target build succeeds. The credential allocator,
exec call ordering, hook registration, and partition release paths were checked
against this source tree. Kernel runtime fork/exec inheritance, native/compat
ioctls, concurrent device removal/repartitioning, allocation fault injection,
SELinux coexistence, device boot and performance have **not** been exercised on
the modified target kernel. Full dual-profile build is a separate integration
check.

Review references: workspace kernel-dev-skill
`references/lectures/smp.md` (shared state and locking),
`references/labs/device_model.md` (reference-counted device lifetime).
