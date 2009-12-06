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
 */

/*
 * Copyright (c) 2009 Apple Inc. All rights reserved.
 */

#ifndef _SYS_CRED_H
#define	_SYS_CRED_H

#include <sys/zfs_context.h>
#include <sys/zfs_kauth.h>
#include <sys/ucred.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

typedef struct kauth_cred  cred_t;

#define kcred 	(cred_t *)kauth_cred_get()

#define	CRED()	(cred_t *)kauth_cred_get()

#define crgetuid(cr)	kauth_cred_getuid((kauth_cred_t)cr)
#define crgetgid(cr)	kauth_cred_getgid((kauth_cred_t)cr)

#else /* User code */

typedef int  cred_t;

#define kcred   (cred_t *)NOCRED

#define	CRED()	(cred_t *)NOCRED

extern uid_t crgetuid(const cred_t *);
extern gid_t crgetgid(const cred_t *);
extern int crgetngroups(cred_t *cr);
extern gid_t *crgetgroups(cred_t *cr);

#endif /*_KERNEL */


#define	crgetzone(cr)		((zone_t *)0)

#define	crgetsid(cr, gr)	(struct ksid *)0

#define	crgetsidlist(cr)	((struct ksidlist *)0)


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_CRED_H */
