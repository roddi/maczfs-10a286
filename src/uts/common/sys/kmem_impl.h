/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 1993-2001, 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Portions Copyright 2007 Apple Inc. All rights reserved.
 * Use is subject to license terms.
 */


#ifndef _SYS_KMEM_IMPL_H
#define	_SYS_KMEM_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/kmem.h>
#include <sys/vmem.h>
#include <sys/thread.h>
//#include <sys/t_lock.h>
#include <sys/time.h>
//#include <sys/kstat.h>
//#include <sys/cpuvar.h>
#include <sys/systm.h>
//#include <vm/page.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * kernel memory allocator: implementation-private data structures
 */

#define	KMF_AUDIT	0x00000001	/* transaction auditing */
#define	KMF_DEADBEEF	0x00000002	/* deadbeef checking */
#define	KMF_REDZONE	0x00000004	/* redzone checking */
#define	KMF_CONTENTS	0x00000008	/* freed-buffer content logging */
#define	KMF_STICKY	0x00000010	/* if set, override /etc/system */
#define	KMF_NOMAGAZINE	0x00000020	/* disable per-cpu magazines */
#define	KMF_FIREWALL	0x00000040	/* put all bufs before unmapped pages */
#define	KMF_LITE	0x00000100	/* lightweight debugging */

#define	KMF_HASH	0x00000200	/* cache has hash table */
#define	KMF_RANDOMIZE	0x00000400	/* randomize other kmem_flags */

#define	KMF_BUFTAG	(KMF_DEADBEEF | KMF_REDZONE)
#define	KMF_TOUCH	(KMF_BUFTAG | KMF_LITE | KMF_CONTENTS)
#define	KMF_RANDOM	(KMF_TOUCH | KMF_AUDIT | KMF_NOMAGAZINE)
#define	KMF_DEBUG	(KMF_RANDOM | KMF_FIREWALL)

#define	KMEM_STACK_DEPTH	15

#define	KMEM_FREE_PATTERN		0xdeadbeefdeadbeefULL
#define	KMEM_UNINITIALIZED_PATTERN	0xbaddcafebaddcafeULL
#define	KMEM_REDZONE_PATTERN		0xfeedfacefeedfaceULL
#define	KMEM_REDZONE_BYTE		0xbb

/*
 * Redzone size encodings for kmem_alloc() / kmem_free().  We encode the
 * allocation size, rather than storing it directly, so that kmem_free()
 * can distinguish frees of the wrong size from redzone violations.
 *
 * A size of zero is never valid.
 */
#define	KMEM_SIZE_ENCODE(x)	(251 * (x) + 1)
#define	KMEM_SIZE_DECODE(x)	((x) / 251)
#define	KMEM_SIZE_VALID(x)	((x) % 251 == 1 && (x) != 1)

/*
 * The bufctl (buffer control) structure keeps some minimal information
 * about each buffer: its address, its slab, and its current linkage,
 * which is either on the slab's freelist (if the buffer is free), or
 * on the cache's buf-to-bufctl hash table (if the buffer is allocated).
 * In the case of non-hashed, or "raw", caches (the common case), only
 * the freelist linkage is necessary: the buffer address is at a fixed
 * offset from the bufctl address, and the slab is at the end of the page.
 *
 * NOTE: bc_next must be the first field; raw buffers have linkage only.
 */
typedef struct kmem_bufctl {
	struct kmem_bufctl	*bc_next;	/* next bufctl struct */
	void			*bc_addr;	/* address of buffer */
	struct kmem_slab	*bc_slab;	/* controlling slab */
} kmem_bufctl_t;

/*
 * The KMF_AUDIT version of the bufctl structure.  The beginning of this
 * structure must be identical to the normal bufctl structure so that
 * pointers are interchangeable.
 */
#ifndef __APPLE__
typedef struct kmem_bufctl_audit {
	struct kmem_bufctl	*bc_next;	/* next bufctl struct */
	void			*bc_addr;	/* address of buffer */
	struct kmem_slab	*bc_slab;	/* controlling slab */
	kmem_cache_t		*bc_cache;	/* controlling cache */
	hrtime_t		bc_timestamp;	/* transaction time */
	kthread_t		*bc_thread;	/* thread doing transaction */
	struct kmem_bufctl	*bc_lastlog;	/* last log entry */
	void			*bc_contents;	/* contents at last free */
	int			bc_depth;	/* stack depth */
	pc_t			bc_stack[KMEM_STACK_DEPTH];	/* pc stack */
} kmem_bufctl_audit_t;
#endif /*!__APPLE__*/

/*
 * A kmem_buftag structure is appended to each buffer whenever any of the
 * KMF_BUFTAG flags (KMF_DEADBEEF, KMF_REDZONE, KMF_VERIFY) are set.
 */
typedef struct kmem_buftag {
	uint64_t		bt_redzone;	/* 64-bit redzone pattern */
	kmem_bufctl_t		*bt_bufctl;	/* bufctl */
	intptr_t		bt_bxstat;	/* bufctl ^ (alloc/free) */
} kmem_buftag_t;

/*
 * A variant of the kmem_buftag structure used for KMF_LITE caches.
 * Previous callers are stored in reverse chronological order. (i.e. most
 * recent first)
 */
typedef struct kmem_buftag_lite {
	kmem_buftag_t		bt_buftag;	/* a normal buftag */
#ifndef __APPLE__
	pc_t			bt_history[1];	/* zero or more callers */
#endif
} kmem_buftag_lite_t;

#define	KMEM_BUFTAG_LITE_SIZE(f)	\
	(offsetof(kmem_buftag_lite_t, bt_history[f]))

#define	KMEM_BUFTAG(cp, buf)		\
	((kmem_buftag_t *)((char *)(buf) + (cp)->cache_buftag))

#define	KMEM_BUFCTL(cp, buf)		\
	((kmem_bufctl_t *)((char *)(buf) + (cp)->cache_bufctl))

#define	KMEM_BUF(cp, bcp)		\
	((void *)((char *)(bcp) - (cp)->cache_bufctl))

#define	KMEM_SLAB(cp, buf)		\
	((kmem_slab_t *)P2END((uintptr_t)(buf), (cp)->cache_slabsize) - 1)

#ifdef __APPLE__
#define	KMEM_CPU_CACHE(cp)		\
	(&cp->cache_cpu[0])

#define	KMEM_MAGAZINE_VALID(cp, mp)	\
	(((kmem_slab_t *)P2END((uintptr_t)(mp), PAGESIZE) - 1)->slab_cache == \
	    (cp)->cache_magtype->mt_cache)

#else
#define	KMEM_CPU_CACHE(cp)		\
	(kmem_cpu_cache_t *)((char *)cp + CPU->cpu_cache_offset)

#define	KMEM_MAGAZINE_VALID(cp, mp)	\
	(((kmem_slab_t *)P2END((uintptr_t)(mp), PAGESIZE) - 1)->slab_cache == \
	    (cp)->cache_magtype->mt_cache)
#endif /* __APPLE__ */


#define	KMEM_SLAB_MEMBER(sp, buf)	\
	((size_t)(buf) - (size_t)(sp)->slab_base < \
	    (sp)->slab_cache->cache_slabsize)

#define	KMEM_BUFTAG_ALLOC	0xa110c8edUL
#define	KMEM_BUFTAG_FREE	0xf4eef4eeUL

typedef struct kmem_slab {
	struct kmem_cache	*slab_cache;	/* controlling cache */
	void			*slab_base;	/* base of allocated memory */
	struct kmem_slab	*slab_next;	/* next slab on freelist */
	struct kmem_slab	*slab_prev;	/* prev slab on freelist */
	struct kmem_bufctl	*slab_head;	/* first free buffer */
	long			slab_refcnt;	/* outstanding allocations */
	long			slab_chunks;	/* chunks (bufs) in this slab */
} kmem_slab_t;

#define	KMEM_HASH_INITIAL	64

#define	KMEM_HASH(cp, buf)	\
	((cp)->cache_hash_table +	\
	(((uintptr_t)(buf) >> (cp)->cache_hash_shift) & (cp)->cache_hash_mask))

typedef struct kmem_magazine {
	void	*mag_next;
	void	*mag_round[1];		/* one or more rounds */
} kmem_magazine_t;

/*
 * The magazine types for fast per-cpu allocation
 */
typedef struct kmem_magtype {
	int		mt_magsize;	/* magazine size (number of rounds) */
	int		mt_align;	/* magazine alignment */
	size_t		mt_minbuf;	/* all smaller buffers qualify */
	size_t		mt_maxbuf;	/* no larger buffers qualify */
	kmem_cache_t	*mt_cache;	/* magazine cache */
} kmem_magtype_t;

#if __LP64__
#define	KMEM_CPU_CACHE_SIZE	128	/* must be power of 2 */
#else
#define	KMEM_CPU_CACHE_SIZE	64	/* must be power of 2 */
#endif
#define	KMEM_CPU_PAD		(KMEM_CPU_CACHE_SIZE - sizeof (kmutex_t) - \
	2 * sizeof (uint64_t) - 2 * sizeof (void *) - 4 * sizeof (int))

#define	KMEM_CACHE_SIZE(ncpus)	\
	((size_t)(&((kmem_cache_t *)0)->cache_cpu[ncpus]))

typedef struct kmem_cpu_cache {
	kmutex_t	cc_lock;	/* protects this cpu's local cache */
	uint64_t	cc_alloc;	/* allocations from this cpu */
	uint64_t	cc_free;	/* frees to this cpu */
	kmem_magazine_t	*cc_loaded;	/* the currently loaded magazine */
	kmem_magazine_t	*cc_ploaded;	/* the previously loaded magazine */
	int		cc_rounds;	/* number of objects in loaded mag */
	int		cc_prounds;	/* number of objects in previous mag */
	int		cc_magsize;	/* number of rounds in a full mag */
	int		cc_flags;	/* CPU-local copy of cache_flags */
	char		cc_pad[KMEM_CPU_PAD]; /* for nice alignment */
} kmem_cpu_cache_t;

/*
 * The magazine lists used in the depot.
 */
typedef struct kmem_maglist {
	kmem_magazine_t	*ml_list;	/* magazine list */
	long		ml_total;	/* number of magazines */
	long		ml_min;		/* min since last update */
	long		ml_reaplimit;	/* max reapable magazines */
	uint64_t	ml_alloc;	/* allocations from this list */
} kmem_maglist_t;

#define	KMEM_CACHE_NAMELEN	31

struct kmem_cache {
	/*
	 * Statistics
	 */
	uint64_t	cache_slab_create;	/* slab creates */
	uint64_t	cache_slab_destroy;	/* slab destroys */
	uint64_t	cache_slab_alloc;	/* slab layer allocations */
	uint64_t	cache_slab_free;	/* slab layer frees */
	uint64_t	cache_alloc_fail;	/* total failed allocations */
	uint64_t	cache_buftotal;		/* total buffers */
	uint64_t	cache_bufmax;		/* max buffers ever */
	uint64_t	cache_rescale;		/* # of hash table rescales */
	uint64_t	cache_lookup_depth;	/* hash lookup depth */
	uint64_t	cache_depot_contention;	/* mutex contention count */
	uint64_t	cache_depot_contention_prev; /* previous snapshot */

	/*
	 * Cache properties
	 */
	char		cache_name[KMEM_CACHE_NAMELEN + 1];
	size_t		cache_bufsize;		/* object size */
	size_t		cache_align;		/* object alignment */
	int		(*cache_constructor)(void *, void *, int);
	void		(*cache_destructor)(void *, void *);
	void		(*cache_reclaim)(void *);
	void		*cache_private;		/* opaque arg to callbacks */
	vmem_t		*cache_arena;		/* vmem source for slabs */
	int		cache_cflags;		/* cache creation flags */
	int		cache_flags;		/* various cache state info */
	uint32_t	cache_mtbf;		/* induced alloc failure rate */
	uint32_t	cache_pad1;		/* to align cache_lock */

#ifdef __APPLE__
	uint32_t	cache_buf_inuse;
#else
	kstat_t		*cache_kstat;		/* exported statistics */
#endif /* __APPLE__ */

	kmem_cache_t	*cache_next;		/* forward cache linkage */
	kmem_cache_t	*cache_prev;		/* backward cache linkage */

	/*
	 * Slab layer
	 */
	kmutex_t	cache_lock;		/* protects slab layer */
	size_t		cache_chunksize;	/* buf + alignment [+ debug] */
	size_t		cache_slabsize;		/* size of a slab */
	size_t		cache_bufctl;		/* buf-to-bufctl distance */
	size_t		cache_buftag;		/* buf-to-buftag distance */
	size_t		cache_verify;		/* bytes to verify */
	size_t		cache_contents;		/* bytes of saved content */
	size_t		cache_color;		/* next slab color */
	size_t		cache_mincolor;		/* maximum slab color */
	size_t		cache_maxcolor;		/* maximum slab color */
	size_t		cache_hash_shift;	/* get to interesting bits */
	size_t		cache_hash_mask;	/* hash table mask */
	kmem_slab_t	*cache_freelist;	/* slab free list */
	kmem_slab_t	cache_nullslab;		/* end of freelist marker */
	kmem_cache_t	*cache_bufctl_cache;	/* source of bufctls */
	kmem_bufctl_t	**cache_hash_table;	/* hash table base */
	void		*cache_pad2;		/* to align depot_lock */

	/*
	 * Depot layer
	 */
	kmutex_t	cache_depot_lock;	/* protects depot */
	kmem_magtype_t	*cache_magtype;		/* magazine type */
	void		*cache_pad3;		/* to align cache_cpu */
	kmem_maglist_t	cache_full;		/* full magazines */
	kmem_maglist_t	cache_empty;		/* empty magazines */

	/*
	 * Per-CPU layer
	 */
	kmem_cpu_cache_t cache_cpu[1];		/* max_ncpus actual elements */
};

typedef struct kmem_cpu_log_header {
	kmutex_t	clh_lock;
	char		*clh_current;
	size_t		clh_avail;
	int		clh_chunk;
	int		clh_hits;
	char		clh_pad[64 - sizeof (kmutex_t) - sizeof (char *) -
				sizeof (size_t) - 2 * sizeof (int)];
} kmem_cpu_log_header_t;

typedef struct kmem_log_header {
	kmutex_t	lh_lock;
	char		*lh_base;
	int		*lh_free;
	size_t		lh_chunksize;
	int		lh_nchunks;
	int		lh_head;
	int		lh_tail;
	int		lh_hits;
	kmem_cpu_log_header_t lh_cpu[1];	/* ncpus actually allocated */
} kmem_log_header_t;

#define	KMEM_ALIGN		8	/* min guaranteed alignment */
#define	KMEM_ALIGN_SHIFT	3	/* log2(KMEM_ALIGN) */
#define	KMEM_VOID_FRACTION	8	/* never waste more than 1/8 of slab */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_KMEM_IMPL_H */
