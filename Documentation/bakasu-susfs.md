# BakaSU + SUSFS on Android 12 GKI 5.10

For modern Android userspace requiring nanosecond Looper waits, this tree also
includes the [epoll_pwait2 compatibility backport](epoll-pwait2-backport.rst).
Android 12 process-launch paths that mark descriptors close-on-exec without
closing them use the
[close_range CLOSE_RANGE_CLOEXEC backport](close-range-cloexec-backport.rst).
Module CRC compatibility alone does not establish userspace syscall compatibility.

This integration targets generic arm64 GKI, Android 12 KMI generation 9. It does
not replace a device's vendor modules, DTB, ramdisk or AVB keys. A successful
build is not proof that a particular device boots or that its vendor module ABI
matches. Device images and validation records are maintained separately.

## Sources and integration

| Component | Fixed source |
| --- | --- |
| Kernel baseline | [`ad7de5b742db00d6bc1587a80e81f10c877b31d9`](https://github.com/Kaniruka/android_gki_kernel_5.10_common/commit/ad7de5b742db00d6bc1587a80e81f10c877b31d9), Linux 5.10.240 |
| BakaSU | [`eca1c3bf99d99408aa6b857a38adb86b71cb8791`](https://github.com/Kaniruka/BakaSU/commit/eca1c3bf99d99408aa6b857a38adb86b71cb8791), `KernelSU` Git submodule |
| SUSFS | [`5436438b5cc77f146e04f71070da153dabe17a9d`](https://gitlab.com/simonpunk/susfs4ksu/-/commit/5436438b5cc77f146e04f71070da153dabe17a9d), `gki-android12-5.10`, v2.4.0 |
| AOSP Clang | `clang-r416183b`, [`6e3223f76384455acde43affde3df0ea9df66c0d`](https://android.googlesource.com/platform/prebuilts/clang/host/linux-x86/+/6e3223f76384455acde43affde3df0ea9df66c0d/) |

The baseline contained no integrated KernelSU/SukiSU/APatch or SUSFS in the
inspected build entries and kernel hook paths. BakaSU is added through
`drivers/kernelsu`, a symlink to the pinned submodule's `kernel` directory.
Keep the submodule's complete history: its Kbuild computes a version code from
the commit count. Do not replace it with an extracted source archive or update
it to an arbitrary moving branch during a build.

The SUSFS kernel-side `50_add_susfs_in_gki-android12-5.10.patch` and its
`fs/susfs.c`, `include/linux/susfs.h`, `include/linux/susfs_def.h` are integrated
in the kernel tree. The upstream `10_enable_susfs_for_ksu.patch` targets original
KernelSU and is **not** applied to BakaSU, which already has its own SUSFS
interfaces and Kconfig. Upstream copyright and licensing notices are retained.
The local Kconfig entry limits this integration to arm64 and defaults KSU off;
the dedicated build script enables it only for a selected root profile. Other architectures and
ordinary configurations do not inherit BakaSU's upstream default-on setting.
Existing optional MLGO and hot/cold-split flags are compiler/linker-probed;
Clang r416183b does not accept the inherited MLGO advisor flag.
The baseline had also removed `sched_group_capacity.next_update`, changing
the frozen scheduler type layout. The field is restored from the
[official Android 12 / 5.10.240 source](https://android.googlesource.com/kernel/common/+/refs/tags/android12-5.10-2025-09_r1/kernel/sched/sched.h)
and the repository's `android/abi_gki_aarch64.xml` contract. Existing capacity
update logic is retained; the layout restoration fixes scheduler export CRCs
without overriding CRC values or bypassing MODVERSIONS.

The 5.10 kernel patch applies cleanly to this baseline. The only additional
hook adaptation is in `fs/read_write.c`: BakaSU declares
`int ksu_handle_sys_read(unsigned int, char __user **, size_t *)`, so the
declaration and call pass `fd`, `&buf` and `&count` instead of using the upstream
SUSFS patch's one-argument `void` declaration.
The pinned [user fork](https://github.com/Kaniruka/BakaSU) is based on upstream
`548d1dda060ca198823d8808804d01f5209ef4a9`. Its SELinux changes retain a
reference-counted original-policy snapshot and preserve parser error/lifetime
handling. The kernel bridges context/access queries and setprocattr to this
snapshot while keeping live SID transitions and native fallbacks intact.
Run `python3 tools/testing/selftests/selinux/ksu_bridge_test.py` and
`python3 tools/testing/selftests/selinux/ksu_parser_test.py` for focused host
regressions; these do not replace a full CFI build or device validation.
Adding the fork commit also increments BakaSU's history-derived version code.
Trailing whitespace in the imported `fs/susfs.c` was normalized.
SUSFS 2.4's optional priority UID filter is unavailable at this BakaSU pin:
its Kconfig and dispatcher do not implement that option, so it is not enabled.
Accordingly, `fs/susfs.c` compiles the two SELinux-domain credential helpers
(`susfs_switch_to_ksu_domain`, `susfs_restore_creds`) under that same option
guard as their only call sites, avoiding unused helper definitions when disabled.

SUSFS's upstream repository carries GPL-3.0 in its root license, copied verbatim
to [susfs-LICENSE](susfs-LICENSE); the imported files have no separate SPDX
exception. BakaSU identifies its kernel directory as GPL-2.0-only. These source
declarations are preserved, not relicensed by this integration; compatibility
of their combined redistribution has not been established here.

The build defaults to `ROOT_VARIANT=none`. Profiles explicitly select their
root and hook configuration after applying the seed, then verify the resolved
configuration after `olddefconfig`:

| `ROOT_VARIANT` | Built-in KSU | Hook | SUSFS |
| --- | --- | --- | --- |
| `none` (default) | Disabled | All disabled | Disabled |
| `bakasu-susfs` | Enabled | SUSFS inline | Enabled |

Tracepoint and manual hooks are disabled in both profiles. Invalid or empty profile values fail
before output changes. CFI, MODVERSIONS and thin LTO remain required in every
profile. Linked symbols are checked for the selected profile: rootless builds
reject root/SUSFS symbols.
Other SUSFS features follow the pinned BakaSU Kconfig defaults and require
appropriate userspace configuration; compilation does not activate a device's
policy.

## Local build

Use an x86-64 Linux host. On Ubuntu 22.04:

```sh
sudo apt-get update
sudo apt-get install -y build-essential bc bison flex libssl-dev libelf-dev \
  libncurses5 libtinfo5 python3 python-is-python3 lz4 dwarves rsync cpio xz-utils curl git
git clone --depth=1 https://github.com/Kaniruka/android_gki_kernel_5.10_common
cd android_gki_kernel_5.10_common
git submodule update --init --recursive
ci/fetch-toolchain.sh
JOBS=8 ci/build-gki.sh # rootless
ROOT_VARIANT=bakasu-susfs OUT_DIR=out/bakasu-susfs DIST_DIR=dist/bakasu-susfs JOBS=8 ci/build-gki.sh
```

Initialize the pinned submodule for **every** profile, including `none`:
the kernel Kconfig includes its definitions even when root is disabled.
Use separate output and distribution paths when comparing profiles.

The compiler is downloaded from a fixed AOSP Git revision, not a floating
release URL. Its revision and archive digest are recorded in the compiler cache.
Do not put credentials in this repository or workflow; no custom GitHub secrets
are required for the public dependencies. Local `.env` files are ignored.

`ci/build-gki.sh configure` performs configuration without compiling the image.
`TOOLCHAIN_DIR`, `OUT_DIR`, `DIST_DIR` and `JOBS` can override the default paths
and parallelism. Use a new `DIST_DIR` for each build; an existing destination
is rejected to avoid mixing artifacts. `OUT_DIR` may be reused for incremental
compilation. `TOOLCHAIN_DIR` must point to the **root** of Clang r416183b, not
its `bin` directory. Substituting a newer compiler can change CFI and ABI
behavior and is not covered by this build configuration.

`BASE_CONFIG` optionally names an absolute path to a known-good kernel
configuration. When it is set, the script verifies that it is a readable file,
copies it to `OUT_DIR/.config` instead of running `gki_defconfig`, and then
applies the same forced options and `olddefconfig` pass. When it is unset, the
previous `gki_defconfig` behavior is unchanged. The seed affects only that
invocation, changes nothing in CI's generic builds, and does not extend the ABI
coverage described below; its path and digest are recorded in `build-info.txt`.

```sh
ROOT_VARIANT=bakasu-susfs BASE_CONFIG=/absolute/path/known-good.config ci/build-gki.sh
```

This standalone make-based build does not run Android's full `build/build.sh`
ABI XML comparison, KMI symbol-list enforcement or symbol trimming. Preserving
CFI and MODVERSIONS is not a substitute for those checks; the artifacts are
custom GKI-source builds, not an assertion of official GKI certification.

## GitHub Actions and artifacts

The **Generic GKI profiles** workflow builds both profiles on pushes and
pull requests to `android12-5.10-2025-09`. Manual dispatch selects `all` (default)
or one profile. Each matrix job has separate outputs, logs
and artifact names, while reusing the fixed compiler cache. Workflow concurrency
cancels older runs on the same ref. It uses read-only repository
permissions and pinned action commits. It builds the checked-out source and
pinned BakaSU submodule; it does not download and run a moving root setup script.

The kernel artifact contains `Image`, `Image.gz`, `Image.lz4`, `vmlinux`,
`System.map`, `Module.symvers`, `kernel.config`, a modules archive, build source
identities and `SHA256SUMS`. `build-info.txt` records `root_variant`,
`enabled_features` and the pinned dependency source identities separately;
a source identity does not imply that the dependency was compiled in. Build logs are uploaded separately, including on
failure. Artifacts expire after 14 days. The workflow does not publish releases,
build manager APKs, create device-specific boot images or flash devices.

For device packaging, use the correct stock boot image and preserve its ramdisk
and header parameters. Replacing a kernel invalidates existing signatures;
never label a repacked image as signed by the device's original AVB key. Check
vendor module symbol CRCs, required features and bootloader requirements before
installation. Keep a known-good boot image and let the device owner perform
flashing and runtime verification.

## Updating and validation

Update BakaSU and SUSFS together deliberately. Recheck hook signatures as well
as names: upstream grep-based checks do not prove C prototype compatibility.
Record new revisions and adaptation changes, regenerate the configuration,
compile with CFI enabled, and inspect linked root/SUSFS symbols. Compare vendor
module CRCs separately when validating a device; public builds carry no device
compatibility guarantee. For user-facing management and SUSFS userspace tools,
follow the matching [BakaSU build documentation](https://bakasu.org/guide/build)
and [SUSFS upstream instructions](https://gitlab.com/simonpunk/susfs4ksu).
