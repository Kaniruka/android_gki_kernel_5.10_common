#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"
MODE=${1:-build}
case "$MODE" in configure|build) ;; *) echo "Usage: $0 [configure|build]" >&2; exit 2 ;; esac
ROOT_VARIANT=${ROOT_VARIANT-none}
case "$ROOT_VARIANT" in
  none|bakasu-susfs) ;;
  *) echo 'ROOT_VARIANT must be none or bakasu-susfs' >&2; exit 2 ;;
esac
TOOLCHAIN_DIR=${TOOLCHAIN_DIR:-$ROOT/.cache/clang-r416183b}
OUT_DIR=$(realpath -m "${OUT_DIR:-$ROOT/out/gki}")
DIST_DIR=$(realpath -m "${DIST_DIR:-$ROOT/dist}")
[[ "$OUT_DIR" != "$ROOT" && "$DIST_DIR" != "$ROOT" ]] || { echo 'Output directories must differ from source' >&2; exit 2; }
if [[ "$MODE" == build && -e "$DIST_DIR" ]]; then
  echo 'DIST_DIR already exists; select a new directory for this build' >&2
  exit 2
fi
BASE_CONFIG=${BASE_CONFIG:-}
if [[ -n "$BASE_CONFIG" ]]; then
  BASE_CONFIG=$(realpath -m -- "$BASE_CONFIG")
  if [[ "$BASE_CONFIG" == "$OUT_DIR/.config" || "$BASE_CONFIG" -ef "$OUT_DIR/.config" ]]; then
    echo 'BASE_CONFIG must not be the output configuration file' >&2
    exit 2
  fi
  [[ -f "$BASE_CONFIG" && -r "$BASE_CONFIG" ]] || { echo "BASE_CONFIG is not a readable file: $BASE_CONFIG" >&2; exit 2; }
fi
export PATH="$TOOLCHAIN_DIR/bin:$PATH"
command -v python >/dev/null || { echo 'Missing python command; install python-is-python3' >&2; exit 1; }
clang --version | grep -q 'r416183b' || { echo 'Expected Android Clang r416183b' >&2; exit 1; }
[[ $(git -C KernelSU rev-parse HEAD) == 548d1dda060ca198823d8808804d01f5209ef4a9 ]] || { echo 'Unexpected BakaSU revision; initialize pinned submodule' >&2; exit 1; }
[[ $(git -C KernelSU rev-parse --is-shallow-repository) == false ]] || { echo 'BakaSU needs full commit history for its version code' >&2; exit 1; }
export ARCH=arm64 LLVM=1 LLVM_IAS=1
export CROSS_COMPILE=aarch64-linux-gnu- CROSS_COMPILE_COMPAT=arm-linux-gnueabi-
export KBUILD_BUILD_USER=gki KBUILD_BUILD_HOST=builder KBUILD_BUILD_VERSION=1
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git show -s --format=%ct HEAD)}
export KBUILD_BUILD_TIMESTAMP
KBUILD_BUILD_TIMESTAMP=$(date -u -d "@$SOURCE_DATE_EPOCH")
mkdir -p "$OUT_DIR"
CONFIG_SEED=gki_defconfig
CONFIG_SEED_SHA256=
if [[ -n "$BASE_CONFIG" ]]; then
  CONFIG_SEED=$BASE_CONFIG
  CONFIG_SEED_SHA256=$(sha256sum -- "$BASE_CONFIG" | cut -d' ' -f1)
  cp -f -- "$BASE_CONFIG" "$OUT_DIR/.config"
else
  make O="$OUT_DIR" gki_defconfig
fi
scripts/config --file "$OUT_DIR/.config" \
  --set-str LOCALVERSION '-android12-9' --disable LOCALVERSION_AUTO \
  --disable LTO_CLANG_FULL --enable LTO_CLANG_THIN
# Clear every root/hook choice before selecting this build's profile.
scripts/config --file "$OUT_DIR/.config" --disable KSU --disable KSU_SUSFS \
  --disable KSU_TRACEPOINT_HOOK --disable KSU_MANUAL_HOOK
case "$ROOT_VARIANT" in
  bakasu-susfs)
    scripts/config --file "$OUT_DIR/.config" --enable KSU --enable KSU_SUSFS ;;
esac
make O="$OUT_DIR" olddefconfig
for option in CFI_CLANG MODVERSIONS LTO_CLANG_THIN; do
  grep -qx "CONFIG_${option}=y" "$OUT_DIR/.config" || { echo "Required option lost: $option" >&2; exit 1; }
done
# olddefconfig may resolve choices/dependencies differently from the seed.
for option in KSU KSU_SUSFS KSU_TRACEPOINT_HOOK KSU_MANUAL_HOOK; do
  expected=n
  case "$ROOT_VARIANT:$option" in
    bakasu-susfs:KSU|bakasu-susfs:KSU_SUSFS) expected=y ;;
  esac
  actual=$(scripts/config --file "$OUT_DIR/.config" --state "$option")
  [[ "$actual" == "$expected" || ( "$expected" == n && "$actual" == undef ) ]] || {
    echo "Unexpected option: $option=$actual (expected $expected)" >&2; exit 1;
  }
done
if [[ "$ROOT_VARIANT" != bakasu-susfs ]] &&
   grep -Eq '^CONFIG_KSU_SUSFS[^=]*=(y|m)$' "$OUT_DIR/.config"; then
  echo 'Unexpected enabled SUSFS option' >&2; exit 1
fi
if grep -qx 'CONFIG_IKHEADERS=y' "$OUT_DIR/.config"; then
  for tool in cpio xz; do
    command -v "$tool" >/dev/null || { echo "IKHEADERS requires $tool" >&2; exit 1; }
  done
fi
if [[ "$MODE" == configure ]]; then exit 0; fi
make O="$OUT_DIR" -j"${JOBS:-$(nproc)}" Image Image.gz Image.lz4 modules
case "$ROOT_VARIANT" in
  none)
    if grep -Eq ' [^ ]*(ksu_|kernelsu_|susfs_)[^ ]*$' "$OUT_DIR/System.map"; then
      echo 'Unexpected linked root/SUSFS symbol in rootless build' >&2; exit 1
    fi ;;
  bakasu-susfs)
    grep -q ' kernelsu_init$' "$OUT_DIR/System.map" || {
      echo 'Missing linked symbol: kernelsu_init' >&2; exit 1;
    }
    for symbol in ksu_handle_sys_read ksu_handle_execveat susfs_init; do
      grep -q " ${symbol}$" "$OUT_DIR/System.map" || {
        echo "Missing linked symbol: $symbol" >&2; exit 1;
      }
    done ;;
esac
mkdir -p "$DIST_DIR"
cp "$OUT_DIR"/arch/arm64/boot/Image{,.gz,.lz4} "$DIST_DIR/"
cp "$OUT_DIR"/{Module.symvers,System.map,vmlinux} "$DIST_DIR/"
cp "$OUT_DIR/.config" "$DIST_DIR/kernel.config"
tar -C "$OUT_DIR" -czf "$DIST_DIR/modules.tar.gz" \
  -T "$OUT_DIR/modules.order" modules.order modules.builtin modules.builtin.modinfo
{
  printf 'source=%s\n' "$(git rev-parse HEAD)"
  printf 'root_variant=%s\n' "$ROOT_VARIANT"
  case "$ROOT_VARIANT" in
    none) printf 'enabled_features=none\n' ;;
    bakasu-susfs) printf 'enabled_features=bakasu,susfs_inline_hook\n' ;;
  esac
  printf 'bakasu_source=%s\n' "$(git -C KernelSU rev-parse HEAD)"
  printf 'susfs_source=%s\n' '5436438b5cc77f146e04f71070da153dabe17a9d'
  printf 'config_seed=%s\n' "$CONFIG_SEED"
  if [[ -n "$CONFIG_SEED_SHA256" ]]; then
    printf 'config_seed_sha256=%s\n' "$CONFIG_SEED_SHA256"
  fi
  printf 'source_date_epoch=%s\n' "$SOURCE_DATE_EPOCH"
  printf 'kernel_release=%s\n' "$(cat "$OUT_DIR/include/config/kernel.release")"
  clang --version
  printf '\nSource status (empty means clean):\n'
  git status --porcelain
  printf '\nBakaSU status:\n'
  git -C KernelSU status --porcelain
} > "$DIST_DIR/build-info.txt"
git diff --binary HEAD > "$DIST_DIR/source.patch"
git -C KernelSU diff --binary HEAD > "$DIST_DIR/bakasu.patch"
# SHA256SUMS is explicitly excluded from the input list.
# shellcheck disable=SC2094
(cd "$DIST_DIR" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
