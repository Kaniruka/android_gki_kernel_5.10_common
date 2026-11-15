/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCOPED_VISIBILITY_H
#define _LINUX_SCOPED_VISIBILITY_H

struct inode;
struct dentry;
struct qstr;

#ifdef CONFIG_SECURITY_SCOPED_VISIBILITY
int scoped_visibility_check(struct inode *inode, int mask);
int scoped_visibility_lookup(struct inode *dir, const struct qstr *name);
int scoped_visibility_dentry(struct dentry *dentry);
int scoped_visibility_readdir(struct inode *inode);
#else
static inline int scoped_visibility_check(struct inode *inode, int mask)
{
	return 0;
}
static inline int scoped_visibility_lookup(struct inode *dir,
					 const struct qstr *name)
{
	return 0;
}
static inline int scoped_visibility_dentry(struct dentry *dentry)
{
	return 0;
}
static inline int scoped_visibility_readdir(struct inode *inode)
{
	return 0;
}
#endif

#endif
