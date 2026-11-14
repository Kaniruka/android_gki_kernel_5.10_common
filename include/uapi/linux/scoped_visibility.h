/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_SCOPED_VISIBILITY_H
#define _UAPI_LINUX_SCOPED_VISIBILITY_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define SV_VERSION 1
#define SV_MAX_ENTRIES 32
#define SV_MAX_RANGES 16

struct sv_uid_range {
	__u32 min;
	__u32 max;
};

struct sv_entry {
	__s32 fd;
	__u32 reserved;
	__u32 nr_ranges;
	__u32 reserved2;
	struct sv_uid_range ranges[SV_MAX_RANGES];
};

struct sv_snapshot {
	__u32 version;
	__u32 flags;
	__u64 expected_generation;
	__u32 nr_entries;
	__u32 reserved;
	struct sv_entry entries[SV_MAX_ENTRIES];
};

/* Diagnostic identities only: enforcement compares pinned inode objects. */
struct sv_object_info {
	__u64 ino;
	__u32 dev_major;
	__u32 dev_minor;
};

struct sv_info {
	__u32 version;
	__u32 flags;
	__u64 generation;
	__u32 nr_entries;
	__u32 reserved;
	struct sv_object_info objects[SV_MAX_ENTRIES];
};

/* Local experimental range, not an upstream allocation or stable ABI. */
#define SV_IOC_MAGIC 0xF7
#define SV_IOC_GET_INFO _IOR(SV_IOC_MAGIC, 0x00, struct sv_info)
#define SV_IOC_REPLACE _IOW(SV_IOC_MAGIC, 0x01, struct sv_snapshot)

#endif
