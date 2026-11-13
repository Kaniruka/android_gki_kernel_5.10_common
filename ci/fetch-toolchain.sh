#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=ci/toolchain.env
source "$ROOT/ci/toolchain.env"
DEST=${1:-$ROOT/.cache/$CLANG_VERSION}
ARCHIVE="$ROOT/.cache/$CLANG_VERSION-$CLANG_REVISION.tar.gz"
URL="https://android.googlesource.com/platform/prebuilts/clang/host/linux-x86/+archive/$CLANG_REVISION/$CLANG_VERSION.tar.gz"
if [[ -f "$DEST/.revision" && $(cat "$DEST/.revision") == "$CLANG_REVISION" && -x "$DEST/bin/clang" ]]; then
  "$DEST/bin/clang" --version
  exit 0
fi
[[ ! -e "$DEST" ]] || { echo "Compiler destination exists without matching provenance: $DEST" >&2; exit 1; }
mkdir -p "$ROOT/.cache" "$(dirname "$DEST")"
curl --fail --location --retry 3 --output "$ARCHIVE.part" "$URL"
mv "$ARCHIVE.part" "$ARCHIVE"
STAGING=$(mktemp -d "${DEST}.tmp.XXXXXX")
trap 'rm -rf -- "$STAGING"' EXIT
tar -xzf "$ARCHIVE" -C "$STAGING"
"$STAGING/bin/clang" --version | grep -q r416183b
printf '%s\n' "$CLANG_REVISION" > "$STAGING/.revision"
sha256sum "$ARCHIVE" | cut -d ' ' -f1 > "$STAGING/.archive-sha256"
mv "$STAGING" "$DEST"
trap - EXIT
printf 'Compiler installed: %s\n' "$DEST"
