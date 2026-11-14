/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCOPED_VISIBILITY_H
#define _LINUX_SCOPED_VISIBILITY_H

struct inode;

#ifdef CONFIG_SECURITY_SCOPED_VISIBILITY
int scoped_visibility_check(struct inode *inode);
#else
static inline int scoped_visibility_check(struct inode *inode)
{
	return 0;
}
#endif

#endif
