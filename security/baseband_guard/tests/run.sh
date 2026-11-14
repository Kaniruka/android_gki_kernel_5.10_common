#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
cd "$(dirname "$0")"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
for boot in 0 1; do
	for recovery in 0 1; do
		set --
		if [ "$boot" = 1 ]; then set -- "$@" -DCONFIG_BBG_BLOCK_BOOT; fi
		if [ "$recovery" = 1 ]; then set -- "$@" -DCONFIG_BBG_BLOCK_RECOVERY; fi
		"${CC:-cc}" -std=gnu11 -Wall -Wextra -Werror "$@" policy_test.c -o "$tmp/policy"
		"$tmp/policy"
	done
done
