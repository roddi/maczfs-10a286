/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*      Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T     */
/*        All Rights Reserved   */

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 * Portions Copyright 2007 Apple Inc. All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Portions copyright (c) 2009 Apple Inc. All rights reserved.
 */

#ifndef _SYS_VFS_H
#define	_SYS_VFS_H

/*
 * In OS X, VFS KPI definitions reside in "sys/mount.h"
 */
#include <sys/types.h>
#include <sys/zfs_buf.h>
#include <sys/cred.h>
#include <sys/zfs_mount.h>
#include <sys/stat.h>
#include <sys/zfs_vnode.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct fid {
	ushort_t len;
	char	data[64];
} fid_t;

typedef struct mount vfs_t;

#define VT_ZFS 17

#define	VNFS_ADDFSREF	0x04	/* take fs (named) reference */

#define LK_NOWAIT	0x00000010	/* do not sleep to await lock */

#define vn_vfswlock(vp)   (0)

#define vn_vfsunlock(vp)  


/*
 * Note that we DO NOT want to map these to vfs_busy() and vfs_unbusy()
 * since those are meant to be temporary holds, not long term references.
 */
#define	VFS_HOLD(vfsp)
#define	VFS_RELE(vfsp)

extern int  VFS_ROOT(struct mount *, struct vnode **);

typedef enum vtype vtype_t;

/*
 * Root directory vnode for the system a.k.a. '/'
 *
 * Note: vfs_rootvnode() acquires a reference and vnode_put() releases it
 */
static inline vnode_t *getrootdir() { 
	vnode_t *rvnode = vfs_rootvnode(); 
	if (rvnode)
		vnode_put(rvnode);
	return rvnode; 
}


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_VFS_H */
