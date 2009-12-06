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
 * Portions Copyright 2007 Apple Inc. All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Portions copyright (c) 2009 Apple Inc. All rights reserved.
 */

#ifndef _SYS_PATHNAME_H
#define	_SYS_PATHNAME_H

#include <sys/zfs_vnode.h>
#include <sys/cred.h>
#include <sys/uio.h>
#include <sys/dirent.h>

typedef struct pathname {
	char	*pn_buf;
	char	*pn_path;
	size_t	pn_pathlen;
	size_t	pn_bufsize;
} pathname_t;

#endif	/* _SYS_PATHNAME_H */
