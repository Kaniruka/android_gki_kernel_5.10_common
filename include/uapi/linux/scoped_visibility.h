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

/* Child-aware policy: all pointer targets are copied before publication. */
#define SV_VERSION_V2 2
#define SV_MAX_PACKAGES 4096
#define SV_PACKAGE_NAME_SIZE 256
#define SV_MIN_LEASE_MS 1000
#define SV_MAX_LEASE_MS 300000
#define SV_INFO_F_CHILD_AWARE 1

struct sv_root_v2 {
	__s32 fd;
	__u32 map_id;
	__u32 nr_ranges;
	__u32 reserved;
	struct sv_uid_range ranges[SV_MAX_RANGES];
};

/* Exactly one full UID per (map_id, name); distinct names may share a UID. */
struct sv_package_v2 {
	__u32 map_id;
	__u32 uid;
	char name[SV_PACKAGE_NAME_SIZE];
};

struct sv_snapshot_v2 {
	__u32 version;
	__u32 flags;
	__aligned_u64 expected_generation;
	__u32 nr_roots;
	__u32 nr_packages;
	__aligned_u64 roots_ptr;
	__aligned_u64 packages_ptr;
	/* Running monotonic time; suspend does not consume the lease. */
	__aligned_u64 lease_ms;
	__aligned_u64 reserved;
};

struct sv_info_v2 {
	__u32 version;
	__u32 flags;
	__aligned_u64 generation;
	__u32 nr_entries;
	__u32 nr_packages;
	/* Rounded up; zero for expired policies and version-1 policies. */
	__aligned_u64 lease_remaining_ms;
	struct sv_object_info objects[SV_MAX_ENTRIES];
};

/* Local experimental range, not an upstream allocation or stable ABI. */
#define SV_IOC_MAGIC 0xF7
#define SV_IOC_GET_INFO _IOR(SV_IOC_MAGIC, 0x00, struct sv_info)
#define SV_IOC_REPLACE _IOW(SV_IOC_MAGIC, 0x01, struct sv_snapshot)

#define SV_IOC_REPLACE_V2 _IOW(SV_IOC_MAGIC, 0x02, struct sv_snapshot_v2)
#define SV_IOC_GET_INFO_V2 _IOR(SV_IOC_MAGIC, 0x03, struct sv_info_v2)

#endif
