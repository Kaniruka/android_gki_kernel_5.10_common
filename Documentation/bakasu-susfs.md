# BakaSU + SUSFS on Android 12 GKI 5.10

This integration targets generic arm64 GKI, Android 12 KMI generation 9. It does
not replace a device's vendor modules, DTB, ramdisk or AVB keys. A successful
build is not proof that a particular device boots or that its vendor module ABI
matches. Device images and validation records are maintained separately.

## Sources and integration

| Component | Fixed source |
| --- | --- |
| Kernel baseline | [`ad7de5b742db00d6bc1587a80e81f10c877b31d9`](https://github.com/Kaniruka/android_gki_kernel_5.10_common/commit/ad7de5b742db00d6bc1587a80e81f10c877b31d9), Linux 5.10.240 |
| BakaSU | [`548d1dda060ca198823d8808804d01f5209ef4a9`](https://github.com/Baka-SU/BakaSU/commit/548d1dda060ca198823d8808804d01f5209ef4a9), `KernelSU` Git submodule |
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
the dedicated build script explicitly enables it. Other architectures and
ordinary configurations do not inherit BakaSU's upstream default-on setting.
Existing optional MLGO and hot/cold-split flags are compiler/linker-probed;
Clang r416183b does not accept the inherited MLGO advisor flag.

The 5.10 kernel patch applies cleanly to this baseline. The only additional
hook adaptation is in `fs/read_write.c`: BakaSU declares
`int ksu_handle_sys_read(unsigned int, char __user **, size_t *)`, so the
declaration and call pass `fd`, `&buf` and `&count` instead of using the upstream
SUSFS patch's one-argument `void` declaration. BakaSU itself is unchanged.
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

The build selects built-in `CONFIG_KSU=y` and `CONFIG_KSU_SUSFS=y`. SUSFS inline
hooks and BakaSU's tracepoint hook are mutually exclusive; the build explicitly
disables the tracepoint and manual-hook choices. CFI and MODVERSIONS stay
enabled. Thin LTO is used to reduce build memory requirements. Other SUSFS
features follow the pinned BakaSU Kconfig defaults and require appropriate
userspace configuration; compilation does not activate a device's policy.

## Local build

Use an x86-64 Linux host. On Ubuntu 22.04:

```sh
sudo apt-get update
sudo apt-get install -y build-essential bc bison flex libssl-dev libelf-dev \
  libncurses5 libtinfo5 python3 python-is-python3 lz4 dwarves rsync curl git
git clone --depth=1 https://github.com/Kaniruka/android_gki_kernel_5.10_common
cd android_gki_kernel_5.10_common
git submodule update --init --recursive
ci/fetch-toolchain.sh
JOBS=8 ci/build-gki.sh
```

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

This standalone make-based build does not run Android's full `build/build.sh`
ABI XML comparison, KMI symbol-list enforcement or symbol trimming. Preserving
CFI and MODVERSIONS is not a substitute for those checks; the artifacts are
custom GKI-source builds, not an assertion of official GKI certification.

## GitHub Actions and artifacts

The **BakaSU + SUSFS GKI** workflow builds on pushes and pull requests to
`android12-5.10-2025-09`, and can be started manually. It uses read-only repository
permissions and pinned action commits. It builds the checked-out source and
pinned BakaSU submodule; it does not download and run a moving root setup script.

The kernel artifact contains `Image`, `Image.gz`, `Image.lz4`, `vmlinux`,
`System.map`, `Module.symvers`, `kernel.config`, a modules archive, build source
identities and `SHA256SUMS`. Build logs are uploaded separately, including on
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
