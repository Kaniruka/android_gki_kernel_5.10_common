// SPDX-License-Identifier: GPL-2.0-only
/*
 * Baseband Guard, derived from vc-teahouse/Baseband-guard
 * 028ff7fd509e2104596da7cc1ef8e6ce2a0c9082, by 秋刀鱼 / TG@qdykernel.
 * Android common 5.10 adaptation: no device-number cache; independent LSM
 * credential blob; exec checks after credentials have been computed.
 */
#include <linux/binfmts.h>
#include <linux/blkdev.h>
#include <linux/blkpg.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/genhd.h>
#include <linux/init.h>
#include <linux/lsm_hooks.h>
#include <linux/module.h>
#include <linux/security.h>
#include <linux/string.h>
#include "objsec.h"
#include "security.h"
#include "policy.h"

struct bbg_cred {
	/* Keep the following LSM blob naturally aligned, regardless of order. */
	unsigned long restricted;
};

static struct lsm_blob_sizes bbg_blob_sizes __lsm_ro_after_init = {
	.lbs_cred = sizeof(struct bbg_cred),
};

static const char *bbg_slot __ro_after_init;

static struct bbg_cred *bbg_cred(const struct cred *cred)
{
	return cred->security + bbg_blob_sizes.lbs_cred;
}

/* Do not cache SIDs across policy reloads or race lazy static initialization. */
static bool bbg_root_domain(const struct cred *cred)
{
	static const char * const contexts[] = {
		"u:r:su:s0", "u:r:magisk:s0", "u:r:ksu:s0",
	};
	const struct task_security_struct *sec;
	u32 sid = 0;
	int i, ret;

	if (!selinux_initialized(&selinux_state))
		return false;
	sec = selinux_cred(cred);
	for (i = 0; i < ARRAY_SIZE(contexts); i++) {
		ret = security_secctx_to_secid(contexts[i], strlen(contexts[i]),
					       &sid);
		if (bbg_domain_restricted(ret, sid, sec->sid, sec->osid))
			return true;
	}
	return false;
}

static bool bbg_restricted(void)
{
	const struct cred *cred = current_cred();

	return bbg_cred(cred)->restricted || bbg_root_domain(cred);
}

static int bbg_cred_prepare(struct cred *new, const struct cred *old, gfp_t gfp)
{
	*bbg_cred(new) = *bbg_cred(old);
	return 0;
}

static void bbg_cred_transfer(struct cred *new, const struct cred *old)
{
	*bbg_cred(new) = *bbg_cred(old);
}

static int bbg_bprm_check(struct linux_binprm *bprm)
{
	/* Sticky across fork, exec and later SELinux transitions. */
	bbg_cred(bprm->cred)->restricted |= bbg_restricted() ||
					  bbg_root_domain(bprm->cred);
	return 0;
}

static bool bbg_device_allowed(dev_t dev)
{
	struct gendisk *disk;
	struct hd_struct *part;
	bool allowed = false;
	int partno;

	/* get_gendisk pins both disk and its owner; never open a block device
	 * recursively from a permission hook. No persistent dev_t permissions:
	 * removal/repartitioning must not authorize a later reused number.
	 */
	disk = get_gendisk(dev, &partno);
	if (!disk)
		return false;
	if (!partno && !strncmp(disk->disk_name, "zram", 4)) {
		allowed = true;
		goto out;
	}
	if (partno <= 0)
		goto out;
	part = disk_get_part(disk, partno);
	if (!part)
		goto out;
	/* info is immutable after publication and freed with the partition. */
	if (part_devt(part) == dev && part->info)
		allowed = bbg_partition_allowed(part->info->volname,
						sizeof(part->info->volname), bbg_slot);
	disk_put_part(part);
out:
	put_disk_and_module(disk);
	return allowed;
}

static int bbg_check(struct inode *inode)
{
	if (!S_ISBLK(inode->i_mode) || !bbg_restricted() ||
	    bbg_device_allowed(inode->i_rdev))
		return 0;
	pr_warn_ratelimited("baseband_guard: denied dev=%u:%u pid=%d comm=%s\n",
			    MAJOR(inode->i_rdev), MINOR(inode->i_rdev),
			    task_pid_nr(current), current->comm);
	return -EPERM;
}

static int bbg_file_permission(struct file *file, int mask)
{
	return (mask & MAY_WRITE) ? bbg_check(file_inode(file)) : 0;
}

static int bbg_inode_setattr(struct dentry *dentry, struct iattr *attr)
{
	return bbg_check(d_inode(dentry));
}

static int bbg_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	return bbg_destructive_ioctl(cmd) ? bbg_check(file_inode(file)) : 0;
}

static struct security_hook_list bbg_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(file_permission, bbg_file_permission),
	LSM_HOOK_INIT(file_ioctl, bbg_file_ioctl),
	LSM_HOOK_INIT(file_ioctl_compat, bbg_file_ioctl),
	LSM_HOOK_INIT(inode_setattr, bbg_inode_setattr),
	LSM_HOOK_INIT(bprm_check_security, bbg_bprm_check),
	LSM_HOOK_INIT(cred_prepare, bbg_cred_prepare),
	LSM_HOOK_INIT(cred_transfer, bbg_cred_transfer),
};

static int __init bbg_init(void)
{
	bbg_slot = bbg_active_slot(saved_command_line);
	security_add_hooks(bbg_hooks, ARRAY_SIZE(bbg_hooks), "baseband_guard");
	pr_info("baseband_guard: enabled (upstream 028ff7fd509e2104596da7cc1ef8e6ce2a0c9082)\n");
	return 0;
}

DEFINE_LSM(baseband_guard) = {
	.name = "baseband_guard",
	.init = bbg_init,
	.blobs = &bbg_blob_sizes,
};

MODULE_DESCRIPTION("Baseband Guard raw block protection");
MODULE_AUTHOR("秋刀鱼 & https://t.me/qdykernel");
MODULE_LICENSE("GPL v2");
