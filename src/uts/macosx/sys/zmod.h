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

#ifndef	_SYS_ZMOD_H
#define	_SYS_ZMOD_H

#ifdef _KERNEL
/* Grab the kernel zlib implementation interfaces */
#include <libkern/zlib.h>
#else
#define	Z_OK	0
#endif

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

extern int z_uncompress(void *, size_t *, const void *, size_t);
extern int z_compress(void *, size_t *, const void *, size_t);
extern int z_compress_level(void *, size_t *, const void *, size_t, int);
extern const char *z_strerror(int);

extern size_t gzip_compress(void *, void *, size_t, size_t, int);
extern int gzip_decompress(void *, void *, size_t, size_t, int);

#else

/* XXX we need an implementation for ztest... */
#define	z_uncompress(dst,dstlen,src,srclen)		(-1)
#define	z_compress_level(dst,dstlen,src,srclen,level)	(-1)
#define	z_compress(dst, dstlen, src, srclen)		(-1)

#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ZMOD_H */
