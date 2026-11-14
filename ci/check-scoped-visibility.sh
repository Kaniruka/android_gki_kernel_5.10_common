#!/usr/bin/env bash
# Compile the default-off prototype in an isolated configuration, not shipping output.
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"
export TOOLCHAIN_DIR=${TOOLCHAIN_DIR:-$ROOT/.cache/clang-r416183b}
export OUT_DIR=${SCOPED_CHECK_OUT_DIR:-$ROOT/out/scoped-check-${ROOT_VARIANT:-none}}
export PATH="$TOOLCHAIN_DIR/bin:$PATH"
ci/build-gki.sh configure
scripts/config --file "$OUT_DIR/.config" --enable SECURITY_SCOPED_VISIBILITY
make O="$OUT_DIR" ARCH=arm64 LLVM=1 LLVM_IAS=1 olddefconfig
grep -qx 'CONFIG_SECURITY_SCOPED_VISIBILITY=y' "$OUT_DIR/.config"
make O="$OUT_DIR" ARCH=arm64 LLVM=1 LLVM_IAS=1 \
  CROSS_COMPILE=aarch64-linux-gnu- CROSS_COMPILE_COMPAT=arm-linux-gnueabi- \
  -j"${JOBS:-8}" security/scoped_visibility.o fs/namei.o fs/stat.o
