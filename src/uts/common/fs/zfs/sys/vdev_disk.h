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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Portions Copyright 2008 Apple Inc. All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_VDEV_DISK_H
#define	_SYS_VDEV_DISK_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/vdev.h>
#ifndef __APPLE__
#ifdef _KERNEL
#include <sys/sunldi.h>
#include <sys/sunddi.h>
#endif
#endif /* !__APPLE__ */

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct vdev_disk {
#ifdef __APPLE__
	char		*vd_minor;
	vnode_t		*vd_devvp;
#else
	ddi_devid_t	vd_devid;
	char		*vd_minor;
	ldi_handle_t	vd_lh;
#endif
} vdev_disk_t;

#ifdef _KERNEL
#ifdef __APPLE__
extern int vdev_disk_physio(struct vnode *, caddr_t, size_t, uint64_t, int);
#else
extern int vdev_disk_physio(ldi_handle_t, caddr_t, size_t, uint64_t, int);
#endif /* __APPLE__ */
#endif
#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_VDEV_DISK_H */
