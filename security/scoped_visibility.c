// SPDX-License-Identifier: GPL-2.0
/* Experimental object-scoped visibility registry; see filesystem docs. */
#include <linux/capability.h>
#include <linux/compat.h>
#include <linux/cred.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kdev_t.h>
#include <linux/mutex.h>
#include <linux/path.h>
#include <linux/rcupdate.h>
#include <linux/scoped_visibility.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/user_namespace.h>
#include <uapi/linux/scoped_visibility.h>

struct sv_rule {
	struct path path;
	struct inode *inode;
	u32 nr_ranges;
	struct sv_uid_range ranges[SV_MAX_RANGES];
};

struct sv_policy {
	u64 generation;
	u32 nr_entries;
	struct sv_rule rules[SV_MAX_ENTRIES];
};

static DEFINE_MUTEX(sv_mutex);
static struct sv_policy __rcu *sv_current;

/* No allocation, sleeping lock, or filesystem callback in RCU pathname walk. */
int scoped_visibility_check(struct inode *inode)
{
	const struct sv_policy *policy;
	u32 uid = __kuid_val(current_fsuid());
	u32 i, j;
	int ret = 0;

	if (!S_ISDIR(inode->i_mode))
		return 0;
	rcu_read_lock();
	policy = rcu_dereference(sv_current);
	if (!policy)
		goto out;
	for (i = 0; i < policy->nr_entries; i++) {
		const struct sv_rule *rule = &policy->rules[i];

		if (rule->inode != inode)
			continue;
		ret = -ENOENT;
		for (j = 0; j < rule->nr_ranges; j++) {
			if (uid >= rule->ranges[j].min &&
			    uid <= rule->ranges[j].max) {
				ret = 0;
				break;
			}
		}
		break;
	}
out:
	rcu_read_unlock();
	return ret;
}

/* Called only in process context, after readers of a retired policy finish. */
static void sv_free(struct sv_policy *policy)
{
	u32 i;

	if (!policy)
		return;
	for (i = 0; i < policy->nr_entries; i++) {
		iput(policy->rules[i].inode);
		path_put(&policy->rules[i].path);
	}
	kfree(policy);
}

static int sv_validate_entry(const struct sv_entry *entry)
{
	u32 j;

	if (entry->reserved || entry->reserved2 || !entry->nr_ranges ||
	    entry->nr_ranges > SV_MAX_RANGES)
		return -EINVAL;
	for (j = 0; j < entry->nr_ranges; j++) {
		const struct sv_uid_range *range = &entry->ranges[j];

		if (range->min > range->max ||
		    !uid_valid(make_kuid(&init_user_ns, range->min)) ||
		    !uid_valid(make_kuid(&init_user_ns, range->max)) ||
		    (j && range->min <= entry->ranges[j - 1].max))
			return -EINVAL;
	}
	if (memchr_inv(&entry->ranges[j], 0,
		       (SV_MAX_RANGES - j) * sizeof(entry->ranges[0])))
		return -EINVAL;
	return 0;
}

static long sv_replace(void __user *arg)
{
	struct sv_snapshot *input;
	struct sv_policy *next = NULL, *old;
	u64 generation;
	u32 i, j;
	int ret = 0;

	input = memdup_user(arg, sizeof(*input));
	if (IS_ERR(input))
		return PTR_ERR(input);
	if (input->version != SV_VERSION || input->flags || input->reserved ||
	    input->nr_entries > SV_MAX_ENTRIES) {
		ret = -EINVAL;
		goto out;
	}
	i = input->nr_entries;
	if (memchr_inv(&input->entries[i], 0,
		       (SV_MAX_ENTRIES - i) * sizeof(input->entries[0]))) {
		ret = -EINVAL;
		goto out;
	}
	next = kzalloc(sizeof(*next), GFP_KERNEL);
	if (!next) {
		ret = -ENOMEM;
		goto out;
	}
	for (i = 0; i < input->nr_entries; i++) {
		struct sv_rule *rule = &next->rules[i];
		const struct sv_entry *entry = &input->entries[i];
		struct fd fd;

		ret = sv_validate_entry(entry);
		if (ret)
			goto out;
		fd = fdget_raw(entry->fd);
		if (!fd.file) {
			ret = -EBADF;
			goto out;
		}
		if (!S_ISDIR(file_inode(fd.file)->i_mode)) {
			fdput(fd);
			ret = -ENOTDIR;
			goto out;
		}
		rule->inode = igrab(file_inode(fd.file));
		if (!rule->inode) {
			fdput(fd);
			ret = -ESTALE;
			goto out;
		}
		rule->path = fd.file->f_path;
		path_get(&rule->path);
		fdput(fd);
		next->nr_entries++;
		for (j = 0; j < i; j++) {
			if (next->rules[j].inode == rule->inode) {
				ret = -EINVAL;
				goto out;
			}
		}
		rule->nr_ranges = entry->nr_ranges;
		memcpy(rule->ranges, entry->ranges, sizeof(rule->ranges));
	}
	mutex_lock(&sv_mutex);
	old = rcu_dereference_protected(sv_current, lockdep_is_held(&sv_mutex));
	generation = old ? old->generation : 0;
	if (input->expected_generation != generation) {
		ret = -EAGAIN;
		goto unlock;
	}
	if (generation == U64_MAX) {
		ret = -EOVERFLOW;
		goto unlock;
	}
	next->generation = generation + 1;
	rcu_assign_pointer(sv_current, next);
	next = NULL;
	/* Serialize retirement too; never call path_put from an RCU callback. */
	synchronize_rcu();
	sv_free(old);
unlock:
	mutex_unlock(&sv_mutex);
out:
	sv_free(next);
	kfree(input);
	return ret;
}

static void sv_get_info(struct sv_info *info)
{
	const struct sv_policy *policy;
	u32 i;

	memset(info, 0, sizeof(*info));
	info->version = SV_VERSION;
	mutex_lock(&sv_mutex);
	policy = rcu_dereference_protected(sv_current, lockdep_is_held(&sv_mutex));
	if (policy) {
		info->generation = policy->generation;
		info->nr_entries = policy->nr_entries;
		for (i = 0; i < policy->nr_entries; i++) {
			struct inode *inode = policy->rules[i].inode;

			info->objects[i].ino = inode->i_ino;
			info->objects[i].dev_major = MAJOR(inode->i_sb->s_dev);
			info->objects[i].dev_minor = MINOR(inode->i_sb->s_dev);
		}
	}
	mutex_unlock(&sv_mutex);
}

static long sv_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct sv_info info;

	if (!ns_capable(&init_user_ns, CAP_SYS_ADMIN))
		return -EPERM;
	switch (cmd) {
	case SV_IOC_GET_INFO:
		sv_get_info(&info);
		return copy_to_user((void __user *)arg, &info, sizeof(info)) ?
			-EFAULT : 0;
	case SV_IOC_REPLACE:
		if (!(file->f_mode & FMODE_WRITE))
			return -EBADF;
		return sv_replace((void __user *)arg);
	default:
		return -ENOTTY;
	}
}

#ifdef CONFIG_COMPAT
static long sv_compat_ioctl(struct file *file, unsigned int cmd,
			   unsigned long arg)
{
	return sv_ioctl(file, cmd, (unsigned long)compat_ptr(arg));
}
#endif

static ssize_t sv_read(struct file *file, char __user *buf, size_t count,
		       loff_t *pos)
{
	struct sv_info info;

	if (!ns_capable(&init_user_ns, CAP_SYS_ADMIN))
		return -EPERM;
	/* Do not splice different generations across partial read calls. */
	if (!count || *pos)
		return 0;
	if (count < sizeof(info))
		return -EMSGSIZE;
	sv_get_info(&info);
	return simple_read_from_buffer(buf, count, pos, &info, sizeof(info));
}

static const struct file_operations sv_fops = {
	.read = sv_read,
	.unlocked_ioctl = sv_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = sv_compat_ioctl,
#endif
	.llseek = no_llseek,
};

static int __init sv_init(void)
{
	struct dentry *dir, *control;

	dir = securityfs_create_dir("scoped_visibility", NULL);
	if (IS_ERR(dir))
		return PTR_ERR(dir);
	control = securityfs_create_file("control", 0600, dir, NULL, &sv_fops);
	if (IS_ERR(control)) {
		securityfs_remove(dir);
		return PTR_ERR(control);
	}
	return 0;
}
late_initcall(sv_init);
