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
 * Portions Copyright 2009 Apple Inc. All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_ARC_H
#define	_SYS_ARC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/zfs_context.h>

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/zio.h>
#include <sys/dmu.h>
#include <sys/spa.h>

typedef struct arc_buf_hdr arc_buf_hdr_t;
typedef struct arc_buf arc_buf_t;
typedef void arc_done_func_t(zio_t *zio, arc_buf_t *buf, void *private);
typedef int arc_evict_func_t(void *private);

/* generic arc_done_func_t's which you can use */
arc_done_func_t arc_bcopy_func;
arc_done_func_t arc_getbuf_func;

struct arc_buf {
	arc_buf_hdr_t		*b_hdr;
	arc_buf_t		*b_next;
	void			*b_data;
#ifdef __APPLE_KERNEL__
	uplinfo_t		*b_uplinfo;
#endif
	arc_evict_func_t	*b_efunc;
	void			*b_private;
};

typedef enum arc_buf_contents {
	ARC_BUFC_DATA,				/* buffer contains data */
	ARC_BUFC_METADATA,			/* buffer contains metadata */
	ARC_BUFC_NUMTYPES
} arc_buf_contents_t;
/*
 * These are the flags we pass into calls to the arc
 */
#define	ARC_WAIT	(1 << 1)	/* perform I/O synchronously */
#define	ARC_NOWAIT	(1 << 2)	/* perform I/O asynchronously */
#define	ARC_PREFETCH	(1 << 3)	/* I/O is a prefetch */
#define	ARC_CACHED	(1 << 4)	/* I/O was already in cache */

void arc_space_consume(uint64_t space);
void arc_space_return(uint64_t space);
void *arc_data_buf_alloc(uint64_t space);
void arc_data_buf_free(void *buf, uint64_t space);
#ifdef __APPLE_KERNEL__
arc_buf_t *arc_buf_alloc(spa_t *spa, int size, void *tag,
    arc_buf_contents_t type, int alloc_data);
#else
arc_buf_t *arc_buf_alloc(spa_t *spa, int size, void *tag,
    arc_buf_contents_t type);
#endif
void arc_buf_add_ref(arc_buf_t *buf, void *tag);
int arc_buf_remove_ref(arc_buf_t *buf, void *tag);
int arc_buf_size(arc_buf_t *buf);
void arc_release(arc_buf_t *buf, void *tag);
int arc_released(arc_buf_t *buf);
int arc_has_callback(arc_buf_t *buf);
void arc_buf_freeze(arc_buf_t *buf);
void arc_buf_thaw(arc_buf_t *buf);
int arc_referenced(arc_buf_t *buf);

typedef struct writeprops {
	dmu_object_type_t wp_type;
	uint8_t wp_copies;
	uint8_t wp_level;
	uint8_t wp_dncompress, wp_oscompress;
	uint8_t wp_dnchecksum, wp_oschecksum;
} writeprops_t;

#ifdef __APPLE_KERNEL__

#ifdef ZFS_DEBUG
void insert_upli(uplinfo_t *new_upli);
void remove_upli(uplinfo_t *upli);
#else
#define insert_upli(x)
#define remove_upli(x)
#endif

uint32_t arc_buf_hdr_realdatacnt(arc_buf_hdr_t *hdr);
void arc_buf_hdr_set_realdatacnt(arc_buf_hdr_t *hdr, uint32_t n);
void arc_get_data_buf(arc_buf_t *buf);

typedef struct dmu_buf_impl dmu_buf_impl_t;
int arc_read_fill_buf(dmu_buf_impl_t *db, uplinfo_t *upli, boolean_t lock_db);

#define	arc_read(pio, spa, bp, pbuf, done, priv, priority, flags, arc_flags, zb) \
	arc_read_osx(pio, spa, bp, pbuf, done, priv, priority, flags, arc_flags, zb, NULL)

#define	arc_read_nolock(pio, spa, bp, done, priv, priority, flags, arc_flags, zb) \
	arc_read_nolock_osx(pio, spa, bp, done, priv, priority, flags, arc_flags, zb, NULL)

int arc_read_osx(zio_t *pio, spa_t *spa, blkptr_t *bp, arc_buf_t *pbuf,
    arc_done_func_t *done, void *priv, int priority, int flags,
    uint32_t *arc_flags, const zbookmark_t *zb, uplinfo_t *upli);

int arc_read_nolock_osx(zio_t *pio, spa_t *spa, blkptr_t *bp,
    arc_done_func_t *done, void *priv, int priority, int flags,
    uint32_t *arc_flags, const zbookmark_t *zb, uplinfo_t *upli);

#else /* Open Solaris */

int arc_read(zio_t *pio, spa_t *spa, blkptr_t *bp, arc_buf_t *pbuf,
    arc_done_func_t *done, void *private, int priority, int flags,
    uint32_t *arc_flags, const zbookmark_t *zb);
int arc_read_nolock(zio_t *pio, spa_t *spa, blkptr_t *bp,
    arc_done_func_t *done, void *private, int priority, int flags,
    uint32_t *arc_flags, const zbookmark_t *zb);

#endif /*__APPLE_KERNEL__ */

zio_t *arc_write(zio_t *pio, spa_t *spa, const writeprops_t *wp,
    uint64_t txg, blkptr_t *bp, arc_buf_t *buf,
    arc_done_func_t *ready, arc_done_func_t *done, void *private, int priority,
    int flags, const zbookmark_t *zb);
int arc_free(zio_t *pio, spa_t *spa, uint64_t txg, blkptr_t *bp,
    zio_done_func_t *done, void *private, uint32_t arc_flags);
int arc_tryread(spa_t *spa, blkptr_t *bp, void *data);

void arc_set_callback(arc_buf_t *buf, arc_evict_func_t *func, void *private);
int arc_buf_evict(arc_buf_t *buf);

void arc_flush(spa_t *spa);
void arc_tempreserve_clear(uint64_t reserve);
int arc_tempreserve_space(uint64_t reserve, uint64_t txg);

void arc_init(void);
void arc_fini(void);

/*
 * Level 2 ARC
 */

void l2arc_add_vdev(spa_t *spa, vdev_t *vd, uint64_t start, uint64_t end);
void l2arc_remove_vdev(vdev_t *vd);
boolean_t l2arc_vdev_present(vdev_t *vd);
void l2arc_init(void);
void l2arc_fini(void);


#ifdef	__cplusplus
}
#endif

#endif /* _SYS_ARC_H */
