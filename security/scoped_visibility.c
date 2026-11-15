// SPDX-License-Identifier: GPL-2.0
/* Experimental object-scoped visibility registry; see filesystem docs. */
#include <linux/capability.h>
#include <linux/compat.h>
#include <linux/cred.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kdev_t.h>
#include <linux/ktime.h>
#include <linux/sort.h>
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
	u32 map_id;
	u32 nr_ranges;
	struct sv_uid_range ranges[SV_MAX_RANGES];
};

struct sv_policy {
	u64 generation;
	u64 expires_ns;
	bool child_aware;
	u32 nr_packages;
	struct sv_package_v2 *packages;
	u32 nr_entries;
	struct sv_rule rules[SV_MAX_ENTRIES];
};

static DEFINE_MUTEX(sv_mutex);
static struct sv_policy __rcu *sv_current;

static bool sv_allowed(const struct sv_rule *rule, u32 uid)
{
	u32 j;

	for (j = 0; j < rule->nr_ranges; j++)
		if (uid >= rule->ranges[j].min && uid <= rule->ranges[j].max)
			return true;
	return false;
}

/* No allocation, sleeping lock, or filesystem callback in RCU pathname walk. */
int scoped_visibility_check(struct inode *inode, int mask)
{
	const struct sv_policy *policy;
	u32 uid = __kuid_val(current_fsuid());
	u32 i;
	int ret = 0;

	if (!inode || !S_ISDIR(inode->i_mode))
		return 0;
	rcu_read_lock();
	policy = rcu_dereference(sv_current);
	if (!policy)
		goto out;
	for (i = 0; i < policy->nr_entries; i++) {
		const struct sv_rule *rule = &policy->rules[i];

		if (rule->inode != inode)
			continue;
		/* v2 exposes the container, but never its directory listing. */
		if (!sv_allowed(rule, uid) &&
		    (!policy->child_aware || (mask & MAY_READ)))
			ret = -ENOENT;
		break;
	}
out:
	rcu_read_unlock();
	return ret;
}

int scoped_visibility_lookup(struct inode *dir, const struct qstr *name)
{
	const struct sv_policy *policy;
	u32 uid = __kuid_val(current_fsuid());
	u32 i;
	int ret = 0;

	rcu_read_lock();
	policy = rcu_dereference(sv_current);
	if (!policy || !policy->child_aware)
		goto out;
	for (i = 0; i < policy->nr_entries; i++) {
		const struct sv_rule *rule = &policy->rules[i];

		if (rule->inode != dir)
			continue;
		if (sv_allowed(rule, uid))
			break;
		ret = -ENOENT;
		if (ktime_get_ns() >= policy->expires_ns)
			break;
		{
			u32 low = 0, high = policy->nr_packages;

			while (low < high) {
				u32 mid = low + (high - low) / 2;
				const struct sv_package_v2 *pkg = &policy->packages[mid];
				int cmp;

				if (rule->map_id != pkg->map_id)
					cmp = rule->map_id < pkg->map_id ? -1 : 1;
				else {
					size_t len = strlen(pkg->name);

					cmp = memcmp(name->name, pkg->name,
						     min_t(size_t, name->len, len));
					if (!cmp && name->len != len)
						cmp = name->len < len ? -1 : 1;
				}
				if (!cmp) {
					if (pkg->uid == uid)
						ret = 0;
					break;
				}
				if (cmp < 0)
					high = mid;
				else
					low = mid + 1;
			}
		}
		break;
	}
out:
	rcu_read_unlock();
	return ret;
}

/* Metadata through a held direct-child FD follows the current name rule. */
int scoped_visibility_dentry(struct dentry *dentry)
{
	struct dentry *parent;
	int ret;

	spin_lock(&dentry->d_lock);
	parent = dentry->d_parent;
	ret = parent == dentry ? 0 :
		scoped_visibility_lookup(d_inode(parent), &dentry->d_name);
	spin_unlock(&dentry->d_lock);
	return ret;
}

int scoped_visibility_readdir(struct inode *inode)
{
	const struct sv_policy *policy;
	u32 uid = __kuid_val(current_fsuid());
	u32 i;
	int ret = 0;

	rcu_read_lock();
	policy = rcu_dereference(sv_current);
	if (policy && policy->child_aware)
		for (i = 0; i < policy->nr_entries; i++)
			if (policy->rules[i].inode == inode &&
			    !sv_allowed(&policy->rules[i], uid)) {
				ret = -ENOENT;
				break;
			}
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
	kvfree(policy->packages);
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

static int sv_publish(struct sv_policy *next, u64 expected_generation)
{
	struct sv_policy *old;
	u64 generation;
	int ret = 0;

	mutex_lock(&sv_mutex);
	old = rcu_dereference_protected(sv_current, lockdep_is_held(&sv_mutex));
	generation = old ? old->generation : 0;
	if (expected_generation != generation) {
		ret = -EAGAIN;
		goto unlock;
	}
	if (generation == U64_MAX) {
		ret = -EOVERFLOW;
		goto unlock;
	}
	next->generation = generation + 1;
	if (next->child_aware)
		next->expires_ns += ktime_get_ns();
	rcu_assign_pointer(sv_current, next);
	/* Serialize retirement too; never call path_put from an RCU callback. */
	synchronize_rcu();
	sv_free(old);
unlock:
	mutex_unlock(&sv_mutex);
	return ret;
}

static long sv_replace(void __user *arg)
{
	struct sv_snapshot *input;
	struct sv_policy *next = NULL;
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
	ret = sv_publish(next, input->expected_generation);
	if (!ret)
		next = NULL;
out:
	sv_free(next);
	kfree(input);
	return ret;
}

static int sv_package_compare(const void *a, const void *b)
{
	const struct sv_package_v2 *x = a, *y = b;

	if (x->map_id != y->map_id)
		return x->map_id < y->map_id ? -1 : 1;
	return strcmp(x->name, y->name);
}

static long sv_replace_v2(void __user *arg)
{
	struct sv_snapshot_v2 input;
	struct sv_root_v2 *roots = NULL;
	struct sv_policy *next = NULL;
	u32 i, j;
	int ret;

	if (copy_from_user(&input, arg, sizeof(input)))
		return -EFAULT;
	if (input.version != SV_VERSION_V2 || input.flags || input.reserved ||
	    input.nr_roots > SV_MAX_ENTRIES ||
	    input.nr_packages > SV_MAX_PACKAGES ||
	    input.lease_ms < SV_MIN_LEASE_MS ||
	    input.lease_ms > SV_MAX_LEASE_MS ||
	    (!input.nr_roots && input.roots_ptr) ||
	    (!input.nr_packages && input.packages_ptr) ||
	    (!input.nr_roots && input.nr_packages))
		return -EINVAL;
	next = kzalloc(sizeof(*next), GFP_KERNEL);
	if (!next)
		return -ENOMEM;
	next->child_aware = true;
	/* Converted to a deadline immediately before publication. */
	next->expires_ns = input.lease_ms * NSEC_PER_MSEC;
	if (input.nr_roots) {
		roots = memdup_user(u64_to_user_ptr(input.roots_ptr),
				    input.nr_roots * sizeof(*roots));
		if (IS_ERR(roots)) {
			ret = PTR_ERR(roots);
			roots = NULL;
			goto out;
		}
	}
	if (input.nr_packages) {
		next->packages = kvmalloc_array(input.nr_packages,
					      sizeof(*next->packages), GFP_KERNEL);
		if (!next->packages) {
			ret = -ENOMEM;
			goto out;
		}
		if (copy_from_user(next->packages,
				   u64_to_user_ptr(input.packages_ptr),
				   input.nr_packages * sizeof(*next->packages))) {
			ret = -EFAULT;
			goto out;
		}
		next->nr_packages = input.nr_packages;
	}
	for (i = 0; i < input.nr_roots; i++) {
		const struct sv_root_v2 *root = &roots[i];
		struct sv_rule *rule = &next->rules[i];
		struct sv_entry entry = { .nr_ranges = root->nr_ranges };
		struct fd fd;

		memcpy(entry.ranges, root->ranges, sizeof(entry.ranges));
		ret = root->reserved ? -EINVAL : sv_validate_entry(&entry);
		if (ret)
			goto out;
		fd = fdget_raw(root->fd);
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
		for (j = 0; j < i; j++)
			if (next->rules[j].inode == rule->inode) {
				ret = -EINVAL;
				goto out;
			}
		rule->map_id = root->map_id;
		rule->nr_ranges = root->nr_ranges;
		memcpy(rule->ranges, root->ranges, sizeof(rule->ranges));
	}
	for (i = 0; i < next->nr_packages; i++) {
		const struct sv_package_v2 *pkg = &next->packages[i];
		size_t len = strnlen(pkg->name, sizeof(pkg->name));
		bool found = false;

		if (!len || len == sizeof(pkg->name) ||
		    strchr(pkg->name, '/') || !strcmp(pkg->name, ".") ||
		    !strcmp(pkg->name, "..") ||
		    memchr_inv(pkg->name + len, 0, sizeof(pkg->name) - len) ||
		    !uid_valid(make_kuid(&init_user_ns, pkg->uid))) {
			ret = -EINVAL;
			goto out;
		}
		for (j = 0; j < next->nr_entries; j++)
			if (next->rules[j].map_id == pkg->map_id)
				found = true;
		if (!found) {
			ret = -EINVAL;
			goto out;
		}
	}
	sort(next->packages, next->nr_packages, sizeof(*next->packages),
	     sv_package_compare, NULL);
	for (i = 1; i < next->nr_packages; i++)
		if (!sv_package_compare(&next->packages[i - 1], &next->packages[i])) {
			ret = -EINVAL;
			goto out;
		}
	ret = sv_publish(next, input.expected_generation);
	if (!ret)
		next = NULL;
out:
	kfree(roots);
	sv_free(next);
	return ret;
}

static void sv_get_info_v2(struct sv_info_v2 *info)
{
	const struct sv_policy *policy;
	u32 i;

	memset(info, 0, sizeof(*info));
	info->version = SV_VERSION_V2;
	mutex_lock(&sv_mutex);
	policy = rcu_dereference_protected(sv_current, lockdep_is_held(&sv_mutex));
	if (policy) {
		info->generation = policy->generation;
		info->nr_entries = policy->nr_entries;
		info->nr_packages = policy->nr_packages;
		if (policy->child_aware) {
			u64 now = ktime_get_ns();

			info->flags = SV_INFO_F_CHILD_AWARE;
			if (now < policy->expires_ns)
				info->lease_remaining_ms = DIV_ROUND_UP_ULL(
					policy->expires_ns - now, NSEC_PER_MSEC);
		}
		for (i = 0; i < policy->nr_entries; i++) {
			struct inode *inode = policy->rules[i].inode;

			info->objects[i].ino = inode->i_ino;
			info->objects[i].dev_major = MAJOR(inode->i_sb->s_dev);
			info->objects[i].dev_minor = MINOR(inode->i_sb->s_dev);
		}
	}
	mutex_unlock(&sv_mutex);
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
	struct sv_info_v2 info_v2;

	if (!ns_capable(&init_user_ns, CAP_SYS_ADMIN))
		return -EPERM;
	switch (cmd) {
	case SV_IOC_GET_INFO:
		sv_get_info(&info);
		return copy_to_user((void __user *)arg, &info, sizeof(info)) ?
			-EFAULT : 0;
	case SV_IOC_GET_INFO_V2:
		sv_get_info_v2(&info_v2);
		return copy_to_user((void __user *)arg, &info_v2, sizeof(info_v2)) ?
			-EFAULT : 0;
	case SV_IOC_REPLACE_V2:
		if (!(file->f_mode & FMODE_WRITE))
			return -EBADF;
		return sv_replace_v2((void __user *)arg);
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
