// SPDX-License-Identifier: GPL-2.0-only
/* Compile the production policy, not a userspace reimplementation. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <linux/blkpg.h>
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#include "../policy.h"

int main(void)
{
	const char unterminated[] = {'b', 'o', 'o', 't'};
	const char *slot;
	const char * const denied[] = {
		"modem", "modem_a", "modem_b", "modemst1", "modemst2", "fsg",
		"persist", "userdata_evil", "userdata_a_extra", "userdata_c",
		"bootloader", "", "USERDATA", "sda", "super",
	};
	size_t i;

	assert(!bbg_active_slot(""));
	assert(!bbg_active_slot("xandroidboot.slot_suffix=_a"));
	assert(!bbg_active_slot("androidboot.slot_suffix=_a_bad"));
	assert(!bbg_active_slot("androidboot.slot_suffix="));
	assert(!bbg_active_slot("androidboot.slot_suffix=_c"));
	assert(!strcmp(bbg_active_slot("androidboot.slot_suffix=_a"), "_a"));
	assert(!strcmp(bbg_active_slot("foo=1 androidboot.slot_suffix=_b bar=2"), "_b"));
	slot = bbg_active_slot("androidboot.slot_suffix=_c androidboot.slot_suffix=_b");
	assert(slot);
	assert(!strcmp(slot, "_b"));
	assert(bbg_partition_allowed("userdata", 32, NULL));
	assert(bbg_partition_allowed("userdata_a", 32, NULL));
	assert(bbg_partition_allowed("userdata_b", 32, NULL));
	assert(bbg_partition_allowed("userdata_a", 32, "_a"));
	assert(!bbg_partition_allowed("userdata_b", 32, "_a"));
	assert(!bbg_partition_allowed("userdata_a", 32, "_b"));
	assert(bbg_partition_allowed("userdata_b", 32, "_b"));
	assert(!bbg_partition_allowed(unterminated, sizeof(unterminated), NULL));
	for (i = 0; i < ARRAY_SIZE(denied); i++)
		assert(!bbg_partition_allowed(denied[i], 64, NULL));
#ifdef CONFIG_BBG_BLOCK_BOOT
	assert(!bbg_partition_allowed("boot", 32, NULL));
	assert(!bbg_partition_allowed("init_boot_a", 32, "_a"));
	assert(!bbg_partition_allowed("vendor_boot_b", 32, NULL));
#else
	assert(bbg_partition_allowed("boot", 32, NULL));
	assert(bbg_partition_allowed("init_boot_a", 32, "_a"));
	assert(bbg_partition_allowed("vendor_boot_b", 32, NULL));
#endif
#ifdef CONFIG_BBG_BLOCK_RECOVERY
	assert(!bbg_partition_allowed("recovery", 32, NULL));
	assert(!bbg_partition_allowed("recovery_b", 32, "_b"));
#else
	assert(bbg_partition_allowed("recovery", 32, NULL));
	assert(bbg_partition_allowed("recovery_b", 32, "_b"));
#endif
	assert(bbg_destructive_ioctl(BLKDISCARD));
	assert(bbg_destructive_ioctl(BLKSECDISCARD));
	assert(bbg_destructive_ioctl(BLKZEROOUT));
	assert(bbg_destructive_ioctl(BLKPG));
	assert(bbg_destructive_ioctl(BLKRRPART));
	assert(bbg_destructive_ioctl(BLKROSET));
	assert(!bbg_destructive_ioctl(BLKGETSIZE64));
	assert(!bbg_destructive_ioctl(BLKROGET));
	assert(!bbg_destructive_ioctl(0));
	assert(bbg_domain_restricted(0, 42, 42, 1));
	assert(bbg_domain_restricted(0, 42, 1, 42));
	assert(!bbg_domain_restricted(0, 42, 1, 2));
	assert(!bbg_domain_restricted(-EINVAL, 42, 42, 42));
	assert(bbg_domain_restricted(-ENOMEM, 0, 1, 2));
	assert(bbg_domain_restricted(-EIO, 0, 1, 2));
	puts("Baseband Guard production policy: PASS");
	return 0;
}
