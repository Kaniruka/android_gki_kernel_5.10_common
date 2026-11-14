/* SPDX-License-Identifier: GPL-2.0-only */
/* Policy derived from vc-teahouse/Baseband-guard, by 秋刀鱼 / TG@qdykernel. */
#ifndef _BASEBAND_GUARD_POLICY_H
#define _BASEBAND_GUARD_POLICY_H

/* EINVAL means a domain is absent; other conversion failures fail closed. */
static inline bool bbg_domain_restricted(int error, unsigned int domain,
					 unsigned int sid, unsigned int osid)
{
	if (error == -EINVAL)
		return false;
	return error || sid == domain || osid == domain;
}

/* Callers supply string, bool, size_t and BLK* definitions (also host tested). */
static inline const char *bbg_active_slot(const char *cmdline)
{
	static const char key[] = "androidboot.slot_suffix=";
	const char *p = cmdline;

	while ((p = strstr(p, key))) {
		if (p == cmdline || p[-1] == ' ') {
			p += sizeof(key) - 1;
			if (p[0] == '_' && (p[1] == 'a' || p[1] == 'b') &&
			    (!p[2] || p[2] == ' '))
				return p[1] == 'a' ? "_a" : "_b";
			continue;
		}
		p += sizeof(key) - 1;
	}
	return NULL;
}

static inline bool bbg_partition_allowed(const char *name, size_t max_len,
					 const char *slot)
{
	static const char * const names[] = {
#ifndef CONFIG_BBG_BLOCK_BOOT
		"boot", "init_boot", "vendor_boot", "vendor_kernel_boot",
#endif
		"dtbo", "userdata", "cache", "metadata", "misc",
		"vbmeta", "vbmeta_system", "vbmeta_vendor",
#ifndef CONFIG_BBG_BLOCK_RECOVERY
		"recovery",
#endif
	};
	size_t len, i, base;

	len = strnlen(name, max_len);
	if (!len || len == max_len)
		return false;
	for (i = 0; i < ARRAY_SIZE(names); i++) {
		base = strlen(names[i]);
		if (len == base && !memcmp(name, names[i], base))
			return true;
		if (len != base + 2 || memcmp(name, names[i], base) ||
		    name[base] != '_')
			continue;
		if (slot ? !memcmp(name + base, slot, 2) :
		    (name[base + 1] == 'a' || name[base + 1] == 'b'))
			return true;
	}
	return false;
}

static inline bool bbg_destructive_ioctl(unsigned int cmd)
{
	switch (cmd) {
	case BLKDISCARD:
	case BLKSECDISCARD:
	case BLKZEROOUT:
	case BLKPG:
	case BLKRRPART:
	case BLKROSET:
		return true;
	default:
		return false;
	}
}

#endif
