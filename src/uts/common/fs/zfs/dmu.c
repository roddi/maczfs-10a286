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
 * Portions Copyright 2007-2009 Apple Inc. All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/dmu.h>
#include <sys/dmu_impl.h>
#include <sys/dmu_tx.h>
#include <sys/dbuf.h>
#include <sys/dnode.h>
#include <sys/zfs_context.h>
#include <sys/dmu_objset.h>
#include <sys/dmu_traverse.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_dir.h>
#include <sys/dsl_pool.h>
#include <sys/dsl_synctask.h>
#include <sys/dsl_prop.h>
#include <sys/dmu_zfetch.h>
#include <sys/zfs_ioctl.h>
#include <sys/zap.h>
#include <sys/zio_checksum.h>
#ifdef _KERNEL
#include <sys/vmsystm.h>
#endif
#ifdef __APPLE__
#include <sys/zfs_znode.h>
#ifdef _KERNEL
#include <sys/zfs_ubc.h>
#endif
#endif
#include <coverage.h>
CODE_COVERAGE_CHECK_INIT;

const dmu_object_type_info_t dmu_ot[DMU_OT_NUMTYPES] = {
	{	byteswap_uint8_array,	TRUE,	"unallocated"		},
	{	zap_byteswap,		TRUE,	"object directory"	},
	{	byteswap_uint64_array,	TRUE,	"object array"		},
	{	byteswap_uint8_array,	TRUE,	"packed nvlist"		},
	{	byteswap_uint64_array,	TRUE,	"packed nvlist size"	},
	{	byteswap_uint64_array,	TRUE,	"bplist"		},
	{	byteswap_uint64_array,	TRUE,	"bplist header"		},
	{	byteswap_uint64_array,	TRUE,	"SPA space map header"	},
	{	byteswap_uint64_array,	TRUE,	"SPA space map"		},
	{	byteswap_uint64_array,	TRUE,	"ZIL intent log"	},
	{	dnode_buf_byteswap,	TRUE,	"DMU dnode"		},
	{	dmu_objset_byteswap,	TRUE,	"DMU objset"		},
	{	byteswap_uint64_array,	TRUE,	"DSL directory"		},
	{	zap_byteswap,		TRUE,	"DSL directory child map"},
	{	zap_byteswap,		TRUE,	"DSL dataset snap map"	},
	{	zap_byteswap,		TRUE,	"DSL props"		},
	{	byteswap_uint64_array,	TRUE,	"DSL dataset"		},
	{	zfs_znode_byteswap,	TRUE,	"ZFS znode"		},
	{	zfs_oldacl_byteswap,	TRUE,	"ZFS V0 ACL"		},
	{	byteswap_uint8_array,	FALSE,	"ZFS plain file"	},
	{	zap_byteswap,		TRUE,	"ZFS directory"		},
	{	zap_byteswap,		TRUE,	"ZFS master node"	},
	{	zap_byteswap,		TRUE,	"ZFS delete queue"	},
	{	byteswap_uint8_array,	FALSE,	"zvol object"		},
	{	zap_byteswap,		TRUE,	"zvol prop"		},
	{	byteswap_uint8_array,	FALSE,	"other uint8[]"		},
	{	byteswap_uint64_array,	FALSE,	"other uint64[]"	},
	{	zap_byteswap,		TRUE,	"other ZAP"		},
	{	zap_byteswap,		TRUE,	"persistent error log"	},
	{	byteswap_uint8_array,	TRUE,	"SPA history"		},
	{	byteswap_uint64_array,	TRUE,	"SPA history offsets"	},
	{	zap_byteswap,		TRUE,	"Pool properties"	},
	{	zap_byteswap,		TRUE,	"DSL permissions"	},
	{	zfs_acl_byteswap,	TRUE,	"ZFS ACL"		},
	{	byteswap_uint8_array,	TRUE,	"ZFS SYSACL"		},
	{	byteswap_uint8_array,	TRUE,	"FUID table"		},
	{	byteswap_uint64_array,	TRUE,	"FUID table size"	},
	{	zap_byteswap,		TRUE,	"DSL dataset next clones"},
	{	zap_byteswap,		TRUE,	"scrub work queue"	},
};

SInt32 num_upli = 0;

int
dmu_buf_hold(objset_t *os, uint64_t object, uint64_t offset,
    void *tag, dmu_buf_t **dbp)
{
	dnode_t *dn;
	uint64_t blkid;
	dmu_buf_impl_t *db;
	int err;

	err = dnode_hold(os->os, object, FTAG, &dn);
	if (err)
		return (err);
	blkid = dbuf_whichblock(dn, offset);
	rw_enter(&dn->dn_struct_rwlock, RW_READER);
	db = dbuf_hold(dn, blkid, tag);
	rw_exit(&dn->dn_struct_rwlock);
	if (db == NULL) {
		err = EIO;
	} else {
		err = dbuf_read(db, NULL, DB_RF_CANFAIL);
		if (err) {
			dbuf_rele(db, tag);
			db = NULL;
		}
	}

	dnode_rele(dn, FTAG);
	*dbp = &db->db;
	return (err);
}

int
dmu_bonus_max(void)
{
	return (DN_MAX_BONUSLEN);
}

int
dmu_set_bonus(dmu_buf_t *db, int newsize, dmu_tx_t *tx)
{
	dnode_t *dn = ((dmu_buf_impl_t *)db)->db_dnode;

	if (dn->dn_bonus != (dmu_buf_impl_t *)db) {
		printf("dmu_set_bonus: dn->dn_bonus != db\n");
		return (EINVAL);
	}
	if (newsize < 0 || newsize > db->db_size) {
		printf("dmu_set_bonus: bad newsize %d (%d)\n", newsize, (int)db->db_size);
		return (EINVAL);
	}
	dnode_setbonuslen(dn, newsize, tx);
	return (0);
}

/*
 * returns ENOENT, EIO, or 0.
 */
int
dmu_bonus_hold(objset_t *os, uint64_t object, void *tag, dmu_buf_t **dbp)
{
	dnode_t *dn;
	dmu_buf_impl_t *db;
	int error;

	error = dnode_hold(os->os, object, FTAG, &dn);
	if (error)
		return (error);

	rw_enter(&dn->dn_struct_rwlock, RW_READER);
	if (dn->dn_bonus == NULL) {
		rw_exit(&dn->dn_struct_rwlock);
		rw_enter(&dn->dn_struct_rwlock, RW_WRITER);
		if (dn->dn_bonus == NULL)
			dbuf_create_bonus(dn);
	}
	db = dn->dn_bonus;
	rw_exit(&dn->dn_struct_rwlock);

	/* as long as the bonus buf is held, the dnode will be held */
	if (refcount_add(&db->db_holds, tag) == 1)
		VERIFY(dnode_add_ref(dn, db));

	dnode_rele(dn, FTAG);

	VERIFY(0 == dbuf_read(db, NULL, DB_RF_MUST_SUCCEED));

	*dbp = &db->db;
	return (0);
}

/*
 * Note: longer-term, we should modify all of the dmu_buf_*() interfaces
 * to take a held dnode rather than <os, object> -- the lookup is wasteful,
 * and can induce severe lock contention when writing to several files
 * whose dnodes are in the same block.
 */
static int
dmu_buf_hold_array_by_dnode(dnode_t *dn, uint64_t offset,
    uint64_t length, int read, void *tag, int *numbufsp, dmu_buf_t ***dbpp)
{
	dmu_buf_t **dbp;
	uint64_t blkid, nblks, i;
	uint32_t flags;
	int err;
	zio_t *zio;

	ASSERT(length <= DMU_MAX_ACCESS);

	flags = DB_RF_CANFAIL | DB_RF_NEVERWAIT;
	if (length > zfetch_array_rd_sz)
		flags |= DB_RF_NOPREFETCH;

	rw_enter(&dn->dn_struct_rwlock, RW_READER);
	if (dn->dn_datablkshift) {
		int blkshift = dn->dn_datablkshift;
		nblks = (P2ROUNDUP(offset+length, 1ULL<<blkshift) -
		    P2ALIGN(offset, 1ULL<<blkshift)) >> blkshift;
	} else {
		if (offset + length > dn->dn_datablksz) {
			zfs_panic_recover("zfs: accessing past end of object "
			    "%llx/%llx (size=%u access=%llu+%llu)",
			    (longlong_t)dn->dn_objset->
			    os_dsl_dataset->ds_object,
			    (longlong_t)dn->dn_object, dn->dn_datablksz,
			    (longlong_t)offset, (longlong_t)length);
			return (EIO);
		}
		nblks = 1;
	}
	dbp = kmem_zalloc(sizeof (dmu_buf_t *) * nblks, KM_SLEEP);

	zio = zio_root(dn->dn_objset->os_spa, NULL, NULL, TRUE);
	blkid = dbuf_whichblock(dn, offset);
	for (i = 0; i < nblks; i++) {
		dmu_buf_impl_t *db = dbuf_hold(dn, blkid+i, tag);
		if (db == NULL) {
			rw_exit(&dn->dn_struct_rwlock);
			dmu_buf_rele_array(dbp, nblks, tag);
			zio_nowait(zio);
			return (EIO);
		}
		/* initiate async i/o */
		if (read) {
			rw_exit(&dn->dn_struct_rwlock);
			(void) dbuf_read(db, zio, flags);
			rw_enter(&dn->dn_struct_rwlock, RW_READER);
		}
		dbp[i] = &db->db;
	}
	rw_exit(&dn->dn_struct_rwlock);

	/* wait for async i/o */
	err = zio_wait(zio);
	if (err) {
		dmu_buf_rele_array(dbp, nblks, tag);
		return (err);
	}

	/* wait for other io to complete */
	if (read) {
		for (i = 0; i < nblks; i++) {
			dmu_buf_impl_t *db = (dmu_buf_impl_t *)dbp[i];
			mutex_enter(&db->db_mtx);
			while (db->db_state == DB_READ ||
			    db->db_state == DB_FILL)
				cv_wait(&db->db_changed, &db->db_mtx);
			if (db->db_state == DB_UNCACHED)
				err = EIO;
			mutex_exit(&db->db_mtx);
			if (err) {
				dmu_buf_rele_array(dbp, nblks, tag);
				return (err);
			}
		}
	}

	*numbufsp = nblks;
	*dbpp = dbp;
	return (0);
}

static int
dmu_buf_hold_array(objset_t *os, uint64_t object, uint64_t offset,
    uint64_t length, int read, void *tag, int *numbufsp, dmu_buf_t ***dbpp)
{
	dnode_t *dn;
	int err;

	err = dnode_hold(os->os, object, FTAG, &dn);
	if (err)
		return (err);

	err = dmu_buf_hold_array_by_dnode(dn, offset, length, read, tag,
	    numbufsp, dbpp);

	dnode_rele(dn, FTAG);

	return (err);
}

int
dmu_buf_hold_array_by_bonus(dmu_buf_t *db, uint64_t offset,
    uint64_t length, int read, void *tag, int *numbufsp, dmu_buf_t ***dbpp)
{
	dnode_t *dn = ((dmu_buf_impl_t *)db)->db_dnode;
	int err;

	err = dmu_buf_hold_array_by_dnode(dn, offset, length, read, tag,
	    numbufsp, dbpp);

	return (err);
}

void
dmu_buf_rele_array(dmu_buf_t **dbp_fake, int numbufs, void *tag)
{
	int i;
	dmu_buf_impl_t **dbp = (dmu_buf_impl_t **)dbp_fake;

	if (numbufs == 0)
		return;

	for (i = 0; i < numbufs; i++) {
		if (dbp[i])
			dbuf_rele(dbp[i], tag);
	}

	kmem_free(dbp, sizeof (dmu_buf_t *) * numbufs);
}

void
dmu_prefetch(objset_t *os, uint64_t object, uint64_t offset, uint64_t len)
{
	dnode_t *dn;
	uint64_t blkid;
	int nblks, i, err;

	if (zfs_prefetch_disable)
		return;

	if (len == 0) {  /* they're interested in the bonus buffer */
		dn = os->os->os_meta_dnode;

		if (object == 0 || object >= DN_MAX_OBJECT)
			return;

		rw_enter(&dn->dn_struct_rwlock, RW_READER);
		blkid = dbuf_whichblock(dn, object * sizeof (dnode_phys_t));
		dbuf_prefetch(dn, blkid);
		rw_exit(&dn->dn_struct_rwlock);
		return;
	}

	/*
	 * XXX - Note, if the dnode for the requested object is not
	 * already cached, we will do a *synchronous* read in the
	 * dnode_hold() call.  The same is true for any indirects.
	 */
	err = dnode_hold(os->os, object, FTAG, &dn);
	if (err != 0)
		return;

	rw_enter(&dn->dn_struct_rwlock, RW_READER);
	if (dn->dn_datablkshift) {
		int blkshift = dn->dn_datablkshift;
		nblks = (P2ROUNDUP(offset+len, 1<<blkshift) -
		    P2ALIGN(offset, 1<<blkshift)) >> blkshift;
	} else {
		nblks = (offset < dn->dn_datablksz);
	}

	if (nblks != 0) {
		blkid = dbuf_whichblock(dn, offset);
		for (i = 0; i < nblks; i++)
			dbuf_prefetch(dn, blkid+i);
	}

	rw_exit(&dn->dn_struct_rwlock);

	dnode_rele(dn, FTAG);
}

static int
get_next_chunk(dnode_t *dn, uint64_t *offset, uint64_t limit)
{
	uint64_t len = limit - *offset;
	uint64_t chunk_len = dn->dn_datablksz * DMU_MAX_DELETEBLKCNT;
	uint64_t dn_used;
	int err;

	ASSERT(limit <= *offset);

	dn_used = dn->dn_phys->dn_used <<
	    (dn->dn_phys->dn_flags & DNODE_FLAG_USED_BYTES ? 0 : DEV_BSHIFT);
	if (len <= chunk_len || dn_used <= chunk_len) {
		*offset = limit;
		return (0);
	}

	while (*offset > limit) {
		uint64_t initial_offset = *offset;
		uint64_t delta;

		/* skip over allocated data */
		err = dnode_next_offset(dn,
		    DNODE_FIND_HOLE|DNODE_FIND_BACKWARDS, offset, 1, 1, 0);
		if (err == ESRCH)
			*offset = limit;
		else if (err)
			return (err);

		ASSERT3U(*offset, <=, initial_offset);
		delta = initial_offset - *offset;
		if (delta >= chunk_len) {
			*offset += delta - chunk_len;
			return (0);
		}
		chunk_len -= delta;

		/* skip over unallocated data */
		err = dnode_next_offset(dn,
		    DNODE_FIND_BACKWARDS, offset, 1, 1, 0);
		if (err == ESRCH)
			*offset = limit;
		else if (err)
			return (err);

		if (*offset < limit)
			*offset = limit;
		ASSERT3U(*offset, <, initial_offset);
	}
	return (0);
}

static int
dmu_free_long_range_impl(objset_t *os, dnode_t *dn, uint64_t offset,
    uint64_t length, boolean_t free_dnode)
{
	dmu_tx_t *tx;
	uint64_t object_size, start, end, len;
	boolean_t trunc = (length == DMU_OBJECT_END);
	int align, err;

	align = 1 << dn->dn_datablkshift;
	ASSERT(align > 0);
	object_size = align == 1 ? dn->dn_datablksz :
	    (dn->dn_maxblkid + 1) << dn->dn_datablkshift;

	if (trunc || (end = offset + length) > object_size)
		end = object_size;
	if (end <= offset)
		return (0);
	length = end - offset;

	while (length) {
		start = end;
		err = get_next_chunk(dn, &start, offset);
		if (err)
			return (err);
		len = trunc ? DMU_OBJECT_END : end - start;

		tx = dmu_tx_create(os);
		dmu_tx_hold_free(tx, dn->dn_object, start, len);
		err = dmu_tx_assign(tx, TXG_WAIT);
		if (err) {
			dmu_tx_abort(tx);
			return (err);
		}

		dnode_free_range(dn, start, trunc ? -1 : len, tx);

		if (start == 0 && trunc && free_dnode)
			dnode_free(dn, tx);

		length -= end - start;

		dmu_tx_commit(tx);
		end = start;
		trunc = FALSE;
	}
	return (0);
}

int
dmu_free_long_range(objset_t *os, uint64_t object,
    uint64_t offset, uint64_t length)
{
	dnode_t *dn;
	int err;

	err = dnode_hold(os->os, object, FTAG, &dn);
	if (err != 0)
		return (err);
	err = dmu_free_long_range_impl(os, dn, offset, length, FALSE);
	dnode_rele(dn, FTAG);
	return (err);
}

int
dmu_free_object(objset_t *os, uint64_t object)
{
	dnode_t *dn;
	dmu_tx_t *tx;
	int err;

	err = dnode_hold_impl(os->os, object, DNODE_MUST_BE_ALLOCATED,
	    FTAG, &dn);
	if (err != 0)
		return (err);
	if (dn->dn_nlevels == 1) {
		tx = dmu_tx_create(os);
		dmu_tx_hold_bonus(tx, object);
		dmu_tx_hold_free(tx, dn->dn_object, 0, DMU_OBJECT_END);
		err = dmu_tx_assign(tx, TXG_WAIT);
		if (err == 0) {
			dnode_free_range(dn, 0, DMU_OBJECT_END, tx);
			dnode_free(dn, tx);
			dmu_tx_commit(tx);
		} else {
			dmu_tx_abort(tx);
		}
	} else {
		err = dmu_free_long_range_impl(os, dn, 0, DMU_OBJECT_END, TRUE);
	}
	dnode_rele(dn, FTAG);
	return (err);
}

int
dmu_free_range(objset_t *os, uint64_t object, uint64_t offset,
    uint64_t size, dmu_tx_t *tx)
{
	dnode_t *dn;
	int err = dnode_hold(os->os, object, FTAG, &dn);
	if (err)
		return (err);
	ASSERT(offset < UINT64_MAX);
	ASSERT(size == -1ULL || size <= UINT64_MAX - offset);
	dnode_free_range(dn, offset, size, tx);
	dnode_rele(dn, FTAG);
	return (0);
}

int
dmu_read(objset_t *os, uint64_t object, uint64_t offset, uint64_t size,
    void *buf)
{
	dnode_t *dn;
	dmu_buf_t **dbp;
	int numbufs, i, err;

	err = dnode_hold(os->os, object, FTAG, &dn);
	if (err)
		return (err);

	/*
	 * Deal with odd block sizes, where there can't be data past the first
	 * block.  If we ever do the tail block optimization, we will need to
	 * handle that here as well.
	 */
	if (dn->dn_datablkshift == 0) {
		int newsz = offset > dn->dn_datablksz ? 0 :
		    MIN(size, dn->dn_datablksz - offset);
		bzero((char *)buf + newsz, size - newsz);
		size = newsz;
	}

	while (size > 0) {
		uint64_t mylen = MIN(size, DMU_MAX_ACCESS / 2);

		/*
		 * NB: we could do this block-at-a-time, but it's nice
		 * to be reading in parallel.
		 */
		err = dmu_buf_hold_array_by_dnode(dn, offset, mylen,
		    TRUE, FTAG, &numbufs, &dbp);
		if (err)
			break;

		for (i = 0; i < numbufs; i++) {
			int tocpy;
			int bufoff;
			dmu_buf_t *db = dbp[i];

			ASSERT(size > 0);

			bufoff = offset - db->db_offset;
			tocpy = (int)MIN(db->db_size - bufoff, size);

			bcopy((char *)db->db_data + bufoff, buf, tocpy);

			offset += tocpy;
			size -= tocpy;
			buf = (char *)buf + tocpy;
		}
		dmu_buf_rele_array(dbp, numbufs, FTAG);
	}
	dnode_rele(dn, FTAG);
	return (err);
}

void
dmu_write(objset_t *os, uint64_t object, uint64_t offset, uint64_t size,
    const void *buf, dmu_tx_t *tx)
{
	dmu_buf_t **dbp;
	int numbufs, i;

	if (size == 0)
		return;

	VERIFY(0 == dmu_buf_hold_array(os, object, offset, size,
	    FALSE, FTAG, &numbufs, &dbp));

	for (i = 0; i < numbufs; i++) {
		int tocpy;
		int bufoff;
		dmu_buf_t *db = dbp[i];

		ASSERT(size > 0);

		bufoff = offset - db->db_offset;
		tocpy = (int)MIN(db->db_size - bufoff, size);

		ASSERT(i == 0 || i == numbufs-1 || tocpy == db->db_size);

		if (tocpy == db->db_size)
			dmu_buf_will_fill(db, tx);
		else
			dmu_buf_will_dirty(db, tx);

		bcopy(buf, (char *)db->db_data + bufoff, tocpy);

		if (tocpy == db->db_size)
			dmu_buf_fill_done(db, tx);

		offset += tocpy;
		size -= tocpy;
		buf = (char *)buf + tocpy;
	}
	dmu_buf_rele_array(dbp, numbufs, FTAG);
}

#ifdef _KERNEL
int
#ifdef __APPLE__
dmu_read_uio(objset_t *os, uint64_t object, struct uio *uio, uint64_t size)
#else
dmu_read_uio(objset_t *os, uint64_t object, uio_t *uio, uint64_t size)
#endif
{
	dmu_buf_t **dbp;
	int numbufs, i, err;

	/*
	 * NB: we could do this block-at-a-time, but it's nice
	 * to be reading in parallel.
	 */
#ifdef __APPLE__
	err = dmu_buf_hold_array(os, object, uio_offset(uio), size, TRUE, FTAG,
	    &numbufs, &dbp);
#else
	err = dmu_buf_hold_array(os, object, uio->uio_loffset, size, TRUE, FTAG,
	    &numbufs, &dbp);
#endif
	if (err)
		return (err);

	for (i = 0; i < numbufs; i++) {
		int tocpy;
		int bufoff;
		dmu_buf_t *db = dbp[i];

		ASSERT(size > 0);

#ifdef __APPLE__
		bufoff = uio_offset(uio) - db->db_offset;
		tocpy = (int)MIN(db->db_size - bufoff, size);

		err = uio_move((char *)db->db_data + bufoff, tocpy, UIO_READ, uio);
#else
		bufoff = uio->uio_loffset - db->db_offset;
		tocpy = (int)MIN(db->db_size - bufoff, size);

		err = uiomove((char *)db->db_data + bufoff, tocpy, UIO_READ, uio);
#endif
		if (err)
			break;

		size -= tocpy;
	}
	dmu_buf_rele_array(dbp, numbufs, FTAG);

	return (err);
}

#ifdef __APPLE__

static int
is_valid_upli(uplinfo_t *upli)
{
	if (upli->ui_f_off % 512 == 0)
		return TRUE;
	else
		return FALSE;
}

char *
getuplvaddr(uplinfo_t *upli, boolean_t for_read)
{
	sharedupl_t *supl;
	ASSERT(is_valid_upli(upli));
	if (upli_sharedupl(upli) == NULL) {
		sharedupl_get(upli, for_read);
	}
	supl = upli_sharedupl(upli);
	if (supl->su_vaddr == 0) {
		mutex_enter(&supl->su_lock);
		if (supl->su_vaddr == 0) { /* check again to make sure it is not already mapped */
			ubc_upl_map(supl->su_upl, &supl->su_vaddr);
			debug_msg("%s: upli=%p supl=%p upl=%p mapped to %p", __func__, upli, supl, supl->su_upl, (void*)supl->su_vaddr);
			supl->su_vaddr += supl->su_upl_off;
		}
		mutex_exit(&supl->su_lock);
	}
	return (char*)supl->su_vaddr;
}

void sharedupl_get(uplinfo_t *upli, boolean_t for_read)
{
	struct znode *zp;
	sharedupl_t uplwanted;
	sharedupl_t *supl;
	avl_index_t where;

	ASSERT(is_valid_upli(upli));
	if (for_read && upli->ui_for_read) {
		/* all information is ready to use */
		return;
	}
	/* now stop using the su_sharedupl_for_read, and will always use su_sharedupl_for_write */
	upli->ui_for_read = FALSE;
	mutex_enter(&upli->ui_lock);
	if (upli->ui_sharedupl_for_write != NULL) {
		OSIncrementAtomic(&upli->ui_sharedupl_for_write->su_refcount);
		mutex_exit(&upli->ui_lock);
		return;
	}

	if (vnode_vid(upli->ui_vp) != upli->ui_vid) {
		panic("found stale vp in ARC");
	}
	zp = VTOZ(upli->ui_vp);
	uplwanted.su_upl_f_off = upli->ui_f_off & ~PAGE_MASK;
	uplwanted.su_upl_size = (upli->ui_f_off + upli->ui_size - uplwanted.su_upl_f_off + PAGE_SIZE - 1) & ~PAGE_MASK;
	
	mutex_enter(&zp->z_upltree_lock);
	upli->ui_sharedupl_for_write = avl_find(&zp->z_upltree, &uplwanted, &where);
	mutex_exit(&zp->z_upltree_lock);

	if (!upli->ui_sharedupl_for_write) { /* create a new one and put it onto the AVL tree */
		/* creating upl may block, we don't want to block while holding the ui_lock mutex */
		mutex_exit(&upli->ui_lock);
		supl = kmem_alloc(sizeof(sharedupl_t), KM_SLEEP);
		supl->su_upl_f_off = uplwanted.su_upl_f_off;
		supl->su_upl_size = uplwanted.su_upl_size;
		supl->su_upl_off = 0;
		supl->su_err = ubc_create_upl(upli->ui_vp, supl->su_upl_f_off,
													supl->su_upl_size, &supl->su_upl,
													&supl->su_pl,
													UPL_FILE_IO | UPL_SET_LITE | UPL_UBC_PAGEOUT);
		debug_msg("%s: created upl %p err=%d (vp %p off %d size %d) upli:%p supl:%p stack: %p %p %p %p %p %p %p %p", __func__,
				  supl->su_upl, supl->su_err,
				  upli->ui_vp, (int)supl->su_upl_f_off, (int)supl->su_upl_size,
				  upli, supl,
				  __builtin_return_address(1), __builtin_return_address(2),
				  __builtin_return_address(3), __builtin_return_address(4), __builtin_return_address(5),
				  __builtin_return_address(6), __builtin_return_address(7), __builtin_return_address(8));
#ifdef ZFS_DEBUG
		int page_index, num_pages;
		num_pages = howmany(supl->su_upl_size, PAGE_SIZE);
		if (supl->su_pl) {
			for (page_index = 0; page_index < num_pages; page_index++) {
				if (!upl_valid_page(supl->su_pl, page_index)) {
					//panic("found invalid page");
					debug_msg("%s upl=%p invalid page=%d", __func__, supl->su_upl, page_index);
				}
			}
		}
#endif

		supl->su_vaddr = 0;
		supl->su_refcount = 1;
		supl->su_err = 0;
		mutex_init(&supl->su_lock, NULL, MUTEX_DEFAULT, NULL);
		mutex_enter(&upli->ui_lock);
		mutex_enter(&zp->z_upltree_lock);
		if ((upli->ui_sharedupl_for_write == NULL) &&
		    avl_find(&zp->z_upltree, &uplwanted, &where) == NULL){
			upli->ui_sharedupl_for_write = supl;
			avl_add(&zp->z_upltree, upli->ui_sharedupl_for_write);
			mutex_exit(&zp->z_upltree_lock);
		} else {				/* somebody else already created the upl */
			OSIncrementAtomic(&upli->ui_sharedupl_for_write->su_refcount);
			mutex_exit(&zp->z_upltree_lock);
			mutex_destroy(&supl->su_lock);
			kmem_free(supl, sizeof(sharedupl_t));
		}
	} else {
		OSIncrementAtomic(&upli->ui_sharedupl_for_write->su_refcount);
	}
	mutex_exit(&upli->ui_lock);
}

void sharedupl_put(uplinfo_t *upli, boolean_t clear_dirty)
{
	struct znode *zp = VTOZ(upli->ui_vp);
	sharedupl_t *supl = upli->ui_sharedupl_for_write;
	SInt32 old_ref_count;

	debug_msg("%s:%d upli=%p refcnt=%d", __func__, __LINE__, upli, (int)supl->su_refcount);
	ASSERT(is_valid_upli(upli) && !upli->ui_for_read);
	mutex_enter(&upli->ui_lock);
	old_ref_count = OSDecrementAtomic(&supl->su_refcount);
	ASSERT(old_ref_count >= 1);
	if (old_ref_count == 1) { /* this sharedupl is not needed anymore */
		mutex_enter(&supl->su_lock);
		if (supl->su_refcount != 0) { /* somebody gets a reference to this upl again, do not release it */
			mutex_exit(&supl->su_lock);
		} else {
			mutex_enter(&zp->z_upltree_lock);
			avl_remove(&zp->z_upltree, supl);
			mutex_exit(&zp->z_upltree_lock);
			if (supl->su_vaddr) {
				debug_msg("%s unmapped upl %p", __func__, supl->su_upl);
				ubc_upl_unmap(supl->su_upl);
				supl->su_vaddr = 0;
			}
			debug_msg("%s will commit upl %p", __func__, supl->su_upl);
			if (supl->su_upl) {
				if (!clear_dirty) {
					debug_msg("%s:%d upl=%p off=%d size=%d aborted", __func__, __LINE__, supl->su_upl,
							  0, (int)supl->su_upl_size);
					ubc_upl_abort_range(supl->su_upl, supl->su_upl_off, supl->su_upl_size, UPL_ABORT_FREE_ON_EMPTY);
				} else if (supl->su_err) {
					debug_msg("%s:%d upl=%p off=%d size=%d aborted due to error", __func__, __LINE__, supl->su_upl,
							  0, (int)supl->su_upl_size);
					ubc_upl_abort_range(supl->su_upl, supl->su_upl_off, supl->su_upl_size, UPL_ABORT_ERROR | UPL_ABORT_FREE_ON_EMPTY);
				} else {
					debug_msg("%s:%d upl=%p off=%d size=%d committed", __func__, __LINE__, supl->su_upl,
							  0, (int)supl->su_upl_size);
					ubc_upl_commit_range(supl->su_upl, supl->su_upl_off, supl->su_upl_size, UPL_COMMIT_CLEAR_DIRTY | UPL_COMMIT_FREE_ON_EMPTY);
				}
			}
			mutex_exit(&supl->su_lock);
			mutex_destroy(&supl->su_lock);
			kmem_free(supl, sizeof(sharedupl_t));
			upli->ui_sharedupl_for_write = NULL;
		}
	}
	mutex_exit(&upli->ui_lock);
}

int sharedupl_cmp(const void *p1, const void *p2)
{
	sharedupl_t *u1 = (sharedupl_t*)p1;
	sharedupl_t *u2 = (sharedupl_t*)p2;
	
	if (u1->su_upl_f_off + u1->su_upl_size <= u2->su_upl_f_off)
		return -1;
	if (u2->su_upl_f_off + u2->su_upl_size <= u1->su_upl_f_off)
		return 1;
	return 0;
}


int
copy_upl_to_mem(upl_t upl, int upl_offset, void *data, int nbytes, upl_page_info_t *pl)
{
	int err;
	uio_t uio;
#ifdef ZFS_DEBUG
	/* make sure there are no holes in the upl */
	int page_index_start, page_index_end, i;
	page_index_start = upl_offset / PAGE_SIZE;
	page_index_end = howmany(upl_offset + nbytes, PAGE_SIZE);
	for (i = page_index_start; i < page_index_end; i++) {
		ASSERT(upl_valid_page(pl, i));
	}
#endif
	uio = uio_create(1, 0, UIO_SYSSPACE, UIO_READ);
	uio_addiov(uio, CAST_USER_ADDR_T(data), nbytes);
	err = cluster_copy_upl_data(uio, upl, upl_offset, &nbytes);
	ASSERT(err == 0);
	uio_free(uio);
	return err;
}

int
copy_mem_to_upl(upl_t upl, int upl_offset, void *data, int nbytes, upl_page_info_t *pl)
{
	int err;
	uio_t uio;
#ifdef ZFS_DEBUG
	/* make sure there are no holes in the upl */
	int page_index_start, page_index_end, i;
	if (pl) {
		page_index_start = upl_offset / PAGE_SIZE;
		page_index_end = howmany(upl_offset + nbytes, PAGE_SIZE);
		for (i = page_index_start; i < page_index_end; i++) {
			ASSERT(upl_valid_page(pl, i));
		}
	}
#endif
	uio = uio_create(1, 0, UIO_SYSSPACE, UIO_WRITE);
	uio_addiov(uio, CAST_USER_ADDR_T(data), nbytes);
	err = cluster_copy_upl_data(uio, upl, upl_offset, &nbytes);
	uio_free(uio);
	return err;
}

static int
dmu_upl_read_by_dnode(dnode_t *dn, uplinfo_t *upli)
{
	int err = 0;
	uint64_t blkid;
	size_t num_fsblks, i;
	dmu_buf_impl_t *db;
	uio_t uio;
	uint32_t flags = 0;

	debug_msg("%s: upl=%p uploff=%d fs_off=%d", __func__, upli_sharedupl(upli)->su_upl, (int)upli_sharedupl(upli)->su_upl_f_off, (int)upli->ui_f_off);

	blkid = dbuf_whichblock(dn, upli->ui_f_off);

  top:
	rw_enter(&dn->dn_struct_rwlock, RW_READER);
#ifdef __APPLE__
	db = dbuf_hold_osx(dn, blkid, FTAG, TRUE/*for_read*/, upli->ui_sharedupl_for_read);
#else
	db = dbuf_hold(dn, blkid, FTAG);
#endif
	rw_exit(&dn->dn_struct_rwlock);

	if (db == NULL) {
		err = EIO;
		goto exit;
	}
		
	switch (db->db_state) {
	default:
		/* wait for I/O to finish, copied from dbuf_read */
		debug_msg("%s: wait for I/O to finish upl=%p", __func__, upli_sharedupl(upli)->su_upl);
		mutex_enter(&db->db_mtx);
		if ((flags & DB_RF_NEVERWAIT) == 0) {
			while (db->db_state == DB_READ ||
				   db->db_state == DB_FILL) {
				ASSERT(db->db_state == DB_READ ||
					   (flags & DB_RF_HAVESTRUCT) == 0);
				cv_wait(&db->db_changed, &db->db_mtx);
			}
			if (db->db_state == DB_UNCACHED) {
				err = EIO;
				goto exit;
			}
		}
		mutex_exit(&db->db_mtx);
		/* fall through to copy data into upl */
	case DB_CACHED: /* data already cached, so copy data into upl */
		if (db->db.db_data) {
			sharedupl_t *supl = upli_sharedupl(upli);
			debug_msg("%s: db=%p buf=%p buf->upli=%p data=%p copy mem to upl %p", __func__, db, db->db_buf,
					  db->db_buf->b_uplinfo, db->db.db_data, supl->su_upl);
			err = copy_mem_to_upl(supl->su_upl, upli->ui_f_off - supl->su_upl_f_off, db->db.db_data, upli->ui_size, supl->su_pl);
			if (err) {
				debug_msg("%s copy failed err=%d", __func__, err);
				goto exit;
			}
		} else {
			/* this buffer has a buf containing a stale upli.  read the real data right now, right here! */
			ASSERT(db->db_buf->b_uplinfo != NULL);
			err = arc_read_fill_buf(db, upli, TRUE/*lock_db*/);
		}
		break;
	case DB_UNCACHED:
		debug_msg("%s: will read data upli=%p upl=%p", __func__, upli, upli_sharedupl(upli)->su_upl);
		flags = DB_RF_CANFAIL;
		uplinfo_t *new_upli;
		sharedupl_t *new_supl;
		new_upli = kmem_alloc(sizeof(uplinfo_t), KM_SLEEP);
		debug_msg_level(MSG_LEVEL - 10, "%s:%d alloc upli=%p stack:%p %p %p %p", __func__, __LINE__, new_upli, __builtin_return_address(1), __builtin_return_address(2), __builtin_return_address(3), __builtin_return_address(4));
		atomic_inc_32(&num_upli);
		memcpy(new_upli, upli, sizeof(uplinfo_t));
		mutex_init(&new_upli->ui_lock, NULL, MUTEX_DEFAULT, NULL);
		err = dbuf_read_osx(db, NULL/*zio*/, flags, new_upli);
		break;
	}

  exit:
	if (db != NULL)
		dbuf_rele(db, FTAG);
	return err;
}

off_t
dmu_get_fsblksz(dnode_t *dn)
{
	off_t fsblksz;
	rw_enter(&dn->dn_struct_rwlock, RW_READER);
	if (dn->dn_datablkshift) {
		fsblksz = 1ULL << dn->dn_datablkshift;
	} else {
		fsblksz = dn->dn_datablksz;
	}
	rw_exit(&dn->dn_struct_rwlock);
	return fsblksz;
}

/* Upon entry, dnode_hold is already called */
static int
dmu_copy_file_to_upl(dnode_t *dn, size_t fsblksz, off_t file_off, size_t nbytes, uplinfo_t *upli, uint64_t maxblkid)
{
	int err = 0;
	off_t offset, blknum, startblk, endblk;
	uint64_t start_off, end_off;
	size_t bytes_left;
	int bytes_to_copy;
	uint64_t blkid;
	sharedupl_t *supl;

	/* find all fs blocks need to be read */
	startblk = file_off / fsblksz;
	endblk = MIN(howmany(file_off + nbytes, fsblksz), maxblkid + 1);

	/* read all necessary blocks into upl.  We may need to copy partial blocks */
	bytes_left = nbytes;
	for (blknum = startblk; blknum < endblk; blknum++) {
		offset = blknum * fsblksz;
		/* blk is not totally covered by requested range */
		if (offset < file_off || (uint64_t)(offset + fsblksz) > (uint64_t)(file_off + nbytes)) {
			start_off = MAX(offset, file_off);
			end_off = MIN((uint64_t)(offset + fsblksz), (uint64_t)(file_off + nbytes));
			/* read into ARC and copy into upl */
			blkid = dbuf_whichblock(dn, offset);
			rw_enter(&dn->dn_struct_rwlock, RW_READER);
			dmu_buf_impl_t *db = dbuf_hold(dn, blkid, FTAG);
			rw_exit(&dn->dn_struct_rwlock);
			if (db == NULL) {
				err = EIO;
				goto exit;
			}
			err = dbuf_read(db, NULL/*zio*/, 0/*flags*/);
			if (err) {
				dbuf_rele(db, FTAG);
				goto exit;
			}

			bytes_to_copy = end_off - start_off;
			ASSERT(bytes_to_copy <= bytes_left);
			supl = upli_sharedupl(upli);
			err = copy_mem_to_upl(supl->su_upl, start_off - upli_sharedupl(upli)->su_upl_f_off,
								  db->db.db_data + start_off - offset, bytes_to_copy, NULL);
			if (err) {
				dbuf_rele(db, FTAG);
				goto exit;
			}
		
			dbuf_rele(db, FTAG);
		} else { /* blk is within upl, read directly into upl */
			bytes_to_copy = MIN(bytes_left, fsblksz);
			ASSERT(bytes_to_copy >= fsblksz);
			upli->ui_f_off = offset;
			upli->ui_size = bytes_to_copy;
			err = dmu_upl_read_by_dnode(dn, upli);
			bytes_left -= bytes_to_copy;
		}
	} /* for each blocknum in range */

  exit:
	return err;
} /* dmu_copy_file_to_upl */

/* create UPL at block boundary and directly read data into UPL */
int
dmu_read_upl(vnode_t *vp, objset_t *os, uint64_t object, struct uio *uio, uint64_t nbytes, int flags)
{
	znode_t *zp = VTOZ(vp);
	dnode_t *dn;
	int err;
	sharedupl_t supl;
	uplinfo_t *upli;

	CODE_COVERAGE_CHECK;
	err = dnode_hold(os->os, object, FTAG, &dn);
	if (err)
		goto exit;

	/* create UPL that cover the requested range */
	off_t blksz;
	upl_t upl;
	upl_page_info_t *pl;
	off_t upl_f_offset;
	size_t upl_size;
	size_t num_pages_per_blk, fsblksz;
	uint64_t maxblkid;

	fsblksz = dmu_get_fsblksz(dn);
	maxblkid = howmany(zp->z_phys->zp_size, fsblksz) - 1;

	if (fsblksz < PAGE_SIZE) {
		blksz = PAGE_SIZE;
		num_pages_per_blk = 1;
		ASSERT((PAGE_SIZE % blksz) == 0);
	} else {
		blksz = fsblksz;
		num_pages_per_blk = fsblksz / PAGE_SIZE;
	}

	/* make upl start on both PAGE_SIZE and FS block size. */
	upl_f_offset = uio_offset(uio) / blksz * blksz;
	while ((upl_f_offset % PAGE_SIZE) != 0) { /* loop always stop when upl_f_offset is 0 */
		upl_f_offset -= blksz;
	}

	/* make upl finish on both PAGE_SIZE and FS block size */
	upl_size = roundup(uio_offset(uio) + nbytes - upl_f_offset, blksz);
	while ((upl_size % PAGE_SIZE) != 0) { /* loop always stop on greatest-common-multiple of blksz and PAGE_SIZE */
		upl_size += blksz;
	}
	if (upl_f_offset + upl_size > zp->z_phys->zp_size) { /* we don't want a too long UPL */
		upl_size = roundup(zp->z_phys->zp_size - upl_f_offset, PAGE_SIZE);
	}

	err = ubc_create_upl(vp, upl_f_offset, upl_size, &upl, &pl, UPL_FILE_IO | UPL_SET_LITE);
	if (err) {
		goto exit_rele_dnode;
	}

	upli = kmem_alloc(sizeof(uplinfo_t), KM_SLEEP);
	debug_msg_level(MSG_LEVEL - 10, "%s:%d alloc upli=%p stack:%p %p %p %p", __func__, __LINE__, upli, __builtin_return_address(1), __builtin_return_address(2), __builtin_return_address(3), __builtin_return_address(4));
	atomic_inc_32(&num_upli);
	bzero(upli, sizeof(uplinfo_t));
	bzero(&supl, sizeof(supl));
	upli->ui_sharedupl_for_read = &supl;
	upli->ui_vp = vp;
	upli->ui_vid = vnode_vid(vp);
	upli->ui_for_read = TRUE;
	mutex_init(&upli->ui_lock, NULL, MUTEX_DEFAULT, NULL);
	supl.su_upl_f_off = upl_f_offset;
	supl.su_upl_size = upl_size;
	supl.su_upl = upl;

	size_t first_invalid_page, first_valid_page;
	size_t num_invalid_pages, num_valid_pages;

	size_t nblks_to_read, maxblks, i, bytes_left;
	off_t *blks_to_read, offset, blknum;
	int bytes_to_copy;
	int page_index, page_index_end, page_index_hole_end;
	uint8_t *should_commit;

	/* fill in the hole of the upl with valid data */
	page_index_end = howmany(upl_size, PAGE_SIZE);
	bytes_left = MIN((maxblkid + 1) * fsblksz, upl_size);
	page_index = 0;
	should_commit = kmem_alloc(page_index_end * sizeof(uint8_t), KM_SLEEP);
	memset(should_commit, TRUE, page_index_end * sizeof(uint8_t));
	while (page_index < page_index_end) {
		CODE_COVERAGE_CHECK;
		if (upl_valid_page(pl, page_index)) {
			should_commit[page_index] = FALSE; /* this page will be aborted to reserve its status */
			page_index++;
			CODE_COVERAGE_CHECK;
			continue;
		}
		/* there is a hole in UPL */

		/* find the end of the hole */
		for (page_index_hole_end = page_index + 1; page_index_hole_end < page_index_end; page_index_hole_end++) {
			if (upl_valid_page(pl, page_index_hole_end))
				break;
		}
		bytes_to_copy = MIN((page_index_hole_end - page_index) * PAGE_SIZE, bytes_left);
		bytes_left -= bytes_to_copy;

		offset = upl_f_offset + page_index * PAGE_SIZE;
		err = dmu_copy_file_to_upl(dn, fsblksz, offset, bytes_to_copy, upli, maxblkid);
		if (err)
			break;

		page_index = page_index_hole_end;
	}

	int io_requested;
	offset = uio_offset(uio) - upl_f_offset;
	io_requested = nbytes;
	err = cluster_copy_upl_data(uio, upl, (int)offset, &io_requested);

	if (upli_sharedupl(upli)->su_vaddr) {
		ubc_upl_unmap(upl);
		debug_msg("upl %p unmapped from %p off=%d size=%d", upl, (void*)upli_sharedupl(upli)->su_vaddr, (int)upl_f_offset, (int)upl_size);
		upli_sharedupl(upli)->su_vaddr = 0;
	}

	/* must release UPL */
	for (page_index = 0; page_index < page_index_end; page_index++) {
		CODE_COVERAGE_CHECK;
		offset = page_index * PAGE_SIZE;
		if (should_commit[page_index]) {
			CODE_COVERAGE_CHECK;
			if (err) {
				debug_msg("%s:%d upl=%p off=%d size=%d aborted", __func__, __LINE__, upl, (int)offset, (int)PAGE_SIZE);
				VERIFY(ubc_upl_abort_range(upl, offset, PAGE_SIZE, UPL_ABORT_ERROR | UPL_ABORT_FREE_ON_EMPTY) == 0);
			} else {
				VERIFY(ubc_upl_commit_range(upl, offset, PAGE_SIZE, UPL_COMMIT_FREE_ON_EMPTY) == 0);
			}
		} else {
			CODE_COVERAGE_CHECK;
			VERIFY(ubc_upl_abort_range(upl, offset, PAGE_SIZE, UPL_ABORT_FREE_ON_EMPTY) == 0);
		}
	}
	kmem_free(should_commit, page_index_end * sizeof(uint8_t));

  exit_rele_dnode:
	dnode_rele(dn, FTAG);

  exit:
	mutex_destroy(&upli->ui_lock);
	atomic_dec_32(&num_upli);
#ifdef ZFS_DEBUG
	memset(upli, 0xC7, sizeof(uplinfo_t));
#endif
	debug_msg_level(MSG_LEVEL - 10, "%s:%d free upli=%p stack:%p %p %p %p", __func__, __LINE__, upli, __builtin_return_address(1), __builtin_return_address(2), __builtin_return_address(3), __builtin_return_address(4));
	kmem_free(upli, sizeof(uplinfo_t));
	return err;
}

int
dmu_pagein(vnode_t *vp, objset_t *os, uint64_t objset, off_t file_off, size_t nbytes, upl_t upl, vm_offset_t upl_offset)
{
	znode_t *zp = VTOZ(vp);
	dnode_t *dn;
	int err = dnode_hold(os->os, objset, FTAG, &dn);
	size_t fsblksz = dmu_get_fsblksz(dn);
	uint64_t maxblkid = howmany(zp->z_phys->zp_size, fsblksz) - 1;
 	if (err == 0) {
		uplinfo_t upli;
		sharedupl_t supl;
		bzero(&upli, sizeof(upli));
		bzero(&supl, sizeof(supl));
		upli.ui_sharedupl_for_read = &supl;
		upli.ui_vp = vp;
		upli.ui_vid = vnode_vid(vp);
		upli.ui_for_read = TRUE;
		mutex_init(&upli.ui_lock, NULL, MUTEX_DEFAULT, NULL);
		supl.su_upl = upl;
		supl.su_upl_f_off = file_off - upl_offset;
		CODE_COVERAGE_CHECK;
		err = dmu_copy_file_to_upl(dn, fsblksz, file_off, nbytes, &upli, maxblkid);
		dnode_rele(dn, FTAG);
		mutex_destroy(&upli.ui_lock);
		if (upli_sharedupl(&upli)->su_vaddr) {
			ubc_upl_unmap(upl);
			debug_msg("upl %p unmapped from %p off=%d size=%d", upl, (void*)upli_sharedupl(&upli)->su_vaddr, (int)file_off, (int)nbytes);
			upli_sharedupl(&upli)->su_vaddr = 0;
		}
	}
	return err;
}

int
dmu_write_upl(vnode_t *vp, objset_t *os, uint64_t object, struct uio *uio, uint64_t nbytes, int flags, dmu_tx_t *tx)
{
	znode_t  *zp = VTOZ(vp);
	dnode_t *dn;
	int err = 0;
	off_t fsblksz;
	upl_t upl = NULL;
	upl_page_info_t *pl;
	off_t upl_f_off;
	size_t upl_size;
	off_t offset;
	int page_index;
	uplinfo_t upli;
	sharedupl_t supl;
	off_t org_uiooff = uio_offset(uio);
	size_t org_nbytes = nbytes;
	uint64_t end_size = org_uiooff + org_nbytes;
	uint64_t maxblkid;

	CODE_COVERAGE_CHECK;
	ASSERT(uio_resid(uio) >= nbytes);
	err = dnode_hold(os->os, object, FTAG, &dn);
	if (err) {
		debug_msg("%s:%d err=%d", __func__, __LINE__, err);
		dn = NULL;
		goto exit;
	}

	fsblksz = dmu_get_fsblksz(dn);
	maxblkid = howmany(end_size, fsblksz) - 1;

	/* create upl that just covers the asked range; */
	upl_f_off = uio_offset(uio) & ~PAGE_MASK;
	upl_size = (uio_offset(uio) + nbytes - upl_f_off + PAGE_SIZE - 1) & ~PAGE_MASK;

	/* debug_msg("%s: will create upl (vp %p off %d size %d)", __func__, vp, (int)upl_f_off, (int)upl_size); */
	err = ubc_create_upl(vp, upl_f_off, upl_size, &upl, &pl, UPL_FILE_IO | UPL_WILL_MODIFY | UPL_SET_LITE);
	if (err) {
		debug_msg("%s:%d err=%d", __func__, __LINE__, err);
		upl = NULL;
		goto exit;
	}

	bzero(&upli, sizeof(uplinfo_t));
	bzero(&supl, sizeof(sharedupl_t));
	mutex_init(&upli.ui_lock, NULL, MUTEX_DEFAULT, NULL);
	/* this upli is used for reading the first and last page, so it is used for read */
	upli.ui_sharedupl_for_read = &supl;
	upli.ui_sharedupl_for_read->su_upl = upl;
	upli.ui_sharedupl_for_read->su_upl_f_off = upl_f_off;
	upli.ui_sharedupl_for_read->su_upl_size = upl_size;
	upli.ui_for_read = TRUE;

	/* debug_msg("%s: upl=%p off=%d size=%d", __func__, upl, (int)upl_f_off, (int)upl_size); */

	/* check the first page */
	if ((uio_offset(uio) != upl_f_off) && /* uio doesn't start on page boundary, and */
		!upl_valid_page(pl, 0)) { /* this page does not contain valid data */
		/* read old content into this page up to uio_offset */
		/* debug_msg("%s: read first blk off=%d bytes=%d fsblksz=%d", __func__, (int)upl_f_off, (int)(uio_offset(uio) - upl_f_off),
		   (int)fsblksz); */
		CODE_COVERAGE_CHECK;
		err = dmu_copy_file_to_upl(dn, fsblksz, upl_f_off, uio_offset(uio) - upl_f_off, &upli, maxblkid);
		if (err) {
			debug_msg("%s:%d err=%d", __func__, __LINE__, err);
			goto exit;
		}
	}

	/* check the last page */
	offset = uio_offset(uio) + nbytes;
	page_index = upl_size / PAGE_SIZE - 1;
	if ((offset & PAGE_MASK) &&  /* uio doesn't finish on page boundary, and */
		!upl_valid_page(pl, page_index)) { /* page doesn't contain valid data */
		CODE_COVERAGE_CHECK;
		/* read old content from where uio finishes till page end or EOF */
		err = dmu_copy_file_to_upl(dn, fsblksz, offset, PAGE_SIZE - (offset & PAGE_MASK), &upli, maxblkid);
		if (err) {
			debug_msg("%s:%d err=%d", __func__, __LINE__, err);
			goto exit;
		}
		off_t eof = MAX(zp->z_phys->zp_size, offset);
		off_t page_end_off = (page_index + 1) * PAGE_SIZE + upl_f_off;
		if (eof < page_end_off) {	/* zero fill the part of the page after EOF */
			off_t zerofill_bytes = PAGE_SIZE - (eof & PAGE_MASK);
			ASSERT(eof + zerofill_bytes == upl_f_off + upl_size);
			cluster_zero(upl, eof - upl_f_off, zerofill_bytes, NULL);
		}
	}

	/* copy uio into upl */
	int io_requested;
	offset = uio_offset(uio) - upl_f_off;
	io_requested = nbytes;
	err = cluster_copy_upl_data(uio, upl, (int)offset, &io_requested); /* now data are in UBC */
	if (err) {
		debug_msg("%s:%d err=%d", __func__, __LINE__, err);
		goto exit;
	}

  exit:
	if (upli_sharedupl(&upli)->su_vaddr) {
		ubc_upl_unmap(upl);
		debug_msg("upl %p unmapped from %p off=%d size=%d", upl, (void*)upli_sharedupl(&upli)->su_vaddr, (int)0, (int)upl_size);
		upli_sharedupl(&upli)->su_vaddr = 0;
	}
	/* now we copied the pages into UPL, mark these pages as dirty */
	if (err) {
		debug_msg("%s:%d err=%d upl=%p off=%d size=%d aborted", __func__, __LINE__, err, upl, 0, (int)upl_size);
		ubc_upl_abort_range(upl, 0, upl_size, UPL_ABORT_FREE_ON_EMPTY | UPL_ABORT_ERROR);
	} else {
		/* debug_msg("%s:%d upl=%p off=%d size=%d committed", __func__, __LINE__, upl, 0, (int)upl_size); */
		ubc_upl_commit_range(upl, 0, upl_size, UPL_COMMIT_SET_DIRTY | UPL_COMMIT_INACTIVATE | UPL_COMMIT_FREE_ON_EMPTY);
	}

	if (dn != NULL)
		dnode_rele(dn, FTAG);
	mutex_destroy(&upli.ui_lock);
	return err;
} /* dmu_write_upl */

#endif	/* __APPLE__ */


int
#ifdef __APPLE__
dmu_write_uio(objset_t *os, uint64_t object, struct uio *uio, uint64_t size, dmu_tx_t *tx)
#else
dmu_write_uio(objset_t *os, uint64_t object, uio_t *uio, uint64_t size, dmu_tx_t *tx)
#endif
{
	dmu_buf_t **dbp;
	int numbufs, i;
	int err = 0;

	if (size == 0)
		return (0);

#ifdef __APPLE__
	err = dmu_buf_hold_array(os, object, uio_offset(uio), size,
	    FALSE, FTAG, &numbufs, &dbp);
#else
	err = dmu_buf_hold_array(os, object, uio->uio_loffset, size,
	    FALSE, FTAG, &numbufs, &dbp);
#endif
	if (err)
		return (err);

	for (i = 0; i < numbufs; i++) {
		int tocpy;
		int bufoff;
		dmu_buf_t *db = dbp[i];

		ASSERT(size > 0);

#ifdef __APPLE__
		bufoff = uio_offset(uio) - db->db_offset;
#else
		bufoff = uio->uio_loffset - db->db_offset;
#endif
		tocpy = (int)MIN(db->db_size - bufoff, size);

		ASSERT(i == 0 || i == numbufs-1 || tocpy == db->db_size);

		if (tocpy == db->db_size)
			dmu_buf_will_fill(db, tx);
		else
			dmu_buf_will_dirty(db, tx);

		/*
		 * XXX uiomove could block forever (eg. nfs-backed
		 * pages).  There needs to be a uiolockdown() function
		 * to lock the pages in memory, so that uiomove won't
		 * block.
		 */
#ifdef __APPLE__
		err = uio_move((char *)db->db_data + bufoff, tocpy, UIO_WRITE, uio);
#else
		err = uiomove((char *)db->db_data + bufoff, tocpy, UIO_WRITE, uio);
#endif
		if (tocpy == db->db_size)
			dmu_buf_fill_done(db, tx);

		if (err)
			break;

		size -= tocpy;
	}
	dmu_buf_rele_array(dbp, numbufs, FTAG);
	return (err);
}

int
dmu_write_pages(objset_t *os, uint64_t object, uint64_t offset, uint64_t size,
#ifdef __APPLE__
    page_t *pp, dmu_tx_t *tx)
#else
    struct page *pp, dmu_tx_t *tx)
#endif
{
	dmu_buf_t **dbp;
	int numbufs, i;
	int err;

	if (size == 0)
		return (0);

	err = dmu_buf_hold_array(os, object, offset, size,
	    FALSE, FTAG, &numbufs, &dbp);
	if (err)
		return (err);

	for (i = 0; i < numbufs; i++) {
		int tocpy, copied, thiscpy;
		int bufoff;
		dmu_buf_t *db = dbp[i];
		caddr_t va;

		ASSERT(size > 0);
		ASSERT3U(db->db_size, >=, PAGESIZE);

		bufoff = offset - db->db_offset;
		tocpy = (int)MIN(db->db_size - bufoff, size);

		ASSERT(i == 0 || i == numbufs-1 || tocpy == db->db_size);

		if (tocpy == db->db_size)
			dmu_buf_will_fill(db, tx);
		else
			dmu_buf_will_dirty(db, tx);

#ifdef __APPLE__
		ubc_upl_map(pp, (vm_offset_t *)&va);
		for (copied = 0; copied < tocpy; copied += PAGESIZE) {
			thiscpy = MIN(PAGESIZE, tocpy - copied);
			bcopy(va, (char *)db->db_data + bufoff, thiscpy);
			va += PAGESIZE;
			bufoff += PAGESIZE;
		}
		ubc_upl_unmap(pp);
#else
		for (copied = 0; copied < tocpy; copied += PAGESIZE) {
			ASSERT3U(pp->p_offset, ==, db->db_offset + bufoff);
			thiscpy = MIN(PAGESIZE, tocpy - copied);
			va = ppmapin(pp, PROT_READ, (caddr_t)-1);
			bcopy(va, (char *)db->db_data + bufoff, thiscpy);
			ppmapout(va);
			pp = pp->p_next;
			bufoff += PAGESIZE;
		}
#endif
		if (tocpy == db->db_size)
			dmu_buf_fill_done(db, tx);

		if (err)
			break;

		offset += tocpy;
		size -= tocpy;
	}
	dmu_buf_rele_array(dbp, numbufs, FTAG);
	return (err);
}
#endif

typedef struct {
	dbuf_dirty_record_t	*dr;
	dmu_sync_cb_t		*done;
	void			*arg;
} dmu_sync_arg_t;

/* ARGSUSED */
static void
dmu_sync_done(zio_t *zio, arc_buf_t *buf, void *varg)
{
	dmu_sync_arg_t *in = varg;
	dbuf_dirty_record_t *dr = in->dr;
	dmu_buf_impl_t *db = dr->dr_dbuf;
	dmu_sync_cb_t *done = in->done;

	if (!BP_IS_HOLE(zio->io_bp)) {
		zio->io_bp->blk_fill = 1;
		BP_SET_TYPE(zio->io_bp, db->db_dnode->dn_type);
		BP_SET_LEVEL(zio->io_bp, 0);
	}

	mutex_enter(&db->db_mtx);
	ASSERT(dr->dt.dl.dr_override_state == DR_IN_DMU_SYNC);
	dr->dt.dl.dr_overridden_by = *zio->io_bp; /* structure assignment */
	dr->dt.dl.dr_override_state = DR_OVERRIDDEN;
	cv_broadcast(&db->db_changed);
	mutex_exit(&db->db_mtx);

	if (done)
		done(&(db->db), in->arg);

	kmem_free(in, sizeof (dmu_sync_arg_t));
}

/*
 * Intent log support: sync the block associated with db to disk.
 * N.B. and XXX: the caller is responsible for making sure that the
 * data isn't changing while dmu_sync() is writing it.
 *
 * Return values:
 *
 *	EEXIST: this txg has already been synced, so there's nothing to to.
 *		The caller should not log the write.
 *
 *	ENOENT: the block was dbuf_free_range()'d, so there's nothing to do.
 *		The caller should not log the write.
 *
 *	EALREADY: this block is already in the process of being synced.
 *		The caller should track its progress (somehow).
 *
 *	EINPROGRESS: the IO has been initiated.
 *		The caller should log this blkptr in the callback.
 *
 *	0: completed.  Sets *bp to the blkptr just written.
 *		The caller should log this blkptr immediately.
 */
int
dmu_sync(zio_t *pio, dmu_buf_t *db_fake,
    blkptr_t *bp, uint64_t txg, dmu_sync_cb_t *done, void *arg)
{
	dmu_buf_impl_t *db = (dmu_buf_impl_t *)db_fake;
	objset_impl_t *os = db->db_objset;
	dsl_pool_t *dp = os->os_dsl_dataset->ds_dir->dd_pool;
	tx_state_t *tx = &dp->dp_tx;
	dbuf_dirty_record_t *dr;
	dmu_sync_arg_t *in;
	zbookmark_t zb;
	writeprops_t wp = { 0 };
	zio_t *zio;
	int zio_flags;
	int err;

	ASSERT(BP_IS_HOLE(bp));
	ASSERT(txg != 0);


	dprintf("dmu_sync txg=%llu, s,o,q %llu %llu %llu\n",
	    txg, tx->tx_synced_txg, tx->tx_open_txg, tx->tx_quiesced_txg);

	/*
	 * XXX - would be nice if we could do this without suspending...
	 */
	txg_suspend(dp);

	/*
	 * If this txg already synced, there's nothing to do.
	 */
	if (txg <= tx->tx_synced_txg) {
		txg_resume(dp);
		/*
		 * If we're running ziltest, we need the blkptr regardless.
		 */
		if (txg > spa_freeze_txg(dp->dp_spa)) {
			/* if db_blkptr == NULL, this was an empty write */
			if (db->db_blkptr)
				*bp = *db->db_blkptr; /* structure assignment */
			return (0);
		}
		return (EEXIST);
	}

	mutex_enter(&db->db_mtx);

	if (txg == tx->tx_syncing_txg) {
		while (db->db_data_pending) {
			/*
			 * IO is in-progress.  Wait for it to finish.
			 * XXX - would be nice to be able to somehow "attach"
			 * this zio to the parent zio passed in.
			 */
			cv_wait(&db->db_changed, &db->db_mtx);
			if (!db->db_data_pending &&
			    db->db_blkptr && BP_IS_HOLE(db->db_blkptr)) {
				/*
				 * IO was compressed away
				 */
				*bp = *db->db_blkptr; /* structure assignment */
				mutex_exit(&db->db_mtx);
				txg_resume(dp);
				return (0);
			}
			ASSERT(db->db_data_pending ||
			    (db->db_blkptr && db->db_blkptr->blk_birth == txg));
		}

		if (db->db_blkptr && db->db_blkptr->blk_birth == txg) {
			/*
			 * IO is already completed.
			 */
			*bp = *db->db_blkptr; /* structure assignment */
			mutex_exit(&db->db_mtx);
			txg_resume(dp);
			return (0);
		}
	}

	dr = db->db_last_dirty;
	while (dr && dr->dr_txg > txg)
		dr = dr->dr_next;
	if (dr == NULL || dr->dr_txg < txg) {
		/*
		 * This dbuf isn't dirty, must have been free_range'd.
		 * There's no need to log writes to freed blocks, so we're done.
		 */
		mutex_exit(&db->db_mtx);
		txg_resume(dp);
		return (ENOENT);
	}

	ASSERT(dr->dr_txg == txg);
	if (dr->dt.dl.dr_override_state == DR_IN_DMU_SYNC) {
		/*
		 * We have already issued a sync write for this buffer.
		 */
		mutex_exit(&db->db_mtx);
		txg_resume(dp);
		return (EALREADY);
	} else if (dr->dt.dl.dr_override_state == DR_OVERRIDDEN) {
		/*
		 * This buffer has already been synced.  It could not
		 * have been dirtied since, or we would have cleared the state.
		 */
		*bp = dr->dt.dl.dr_overridden_by; /* structure assignment */
		mutex_exit(&db->db_mtx);
		txg_resume(dp);
		return (0);
	}

	dr->dt.dl.dr_override_state = DR_IN_DMU_SYNC;
	in = kmem_alloc(sizeof (dmu_sync_arg_t), KM_SLEEP);
	in->dr = dr;
	in->done = done;
	in->arg = arg;
	mutex_exit(&db->db_mtx);
	txg_resume(dp);

	zb.zb_objset = os->os_dsl_dataset->ds_object;
	zb.zb_object = db->db.db_object;
	zb.zb_level = db->db_level;
	zb.zb_blkid = db->db_blkid;
	zio_flags = ZIO_FLAG_MUSTSUCCEED;
	if (dmu_ot[db->db_dnode->dn_type].ot_metadata || zb.zb_level != 0)
		zio_flags |= ZIO_FLAG_METADATA;
	wp.wp_type = db->db_dnode->dn_type;
	wp.wp_copies = os->os_copies;
	wp.wp_level = db->db_level;
	wp.wp_dnchecksum = db->db_dnode->dn_checksum;
	wp.wp_oschecksum = os->os_checksum;
	wp.wp_dncompress = db->db_dnode->dn_compress;
	wp.wp_oscompress = os->os_compress;
	zio = arc_write(pio, os->os_spa, &wp,
	    txg, bp, dr->dt.dl.dr_data, NULL, dmu_sync_done, in,
	    ZIO_PRIORITY_SYNC_WRITE, zio_flags, &zb);

	if (pio) {
		zio_nowait(zio);
		err = EINPROGRESS;
	} else {
		err = zio_wait(zio);
		ASSERT(err == 0);
	}
	return (err);
}

int
dmu_object_set_blocksize(objset_t *os, uint64_t object, uint64_t size, int ibs,
	dmu_tx_t *tx)
{
	dnode_t *dn;
	int err;

	err = dnode_hold(os->os, object, FTAG, &dn);
	if (err)
		return (err);
	err = dnode_set_blksz(dn, size, ibs, tx);
	dnode_rele(dn, FTAG);
	return (err);
}

void
dmu_object_set_checksum(objset_t *os, uint64_t object, uint8_t checksum,
	dmu_tx_t *tx)
{
	dnode_t *dn;

	/* XXX assumes dnode_hold will not get an i/o error */
	(void) dnode_hold(os->os, object, FTAG, &dn);
	ASSERT(checksum < ZIO_CHECKSUM_FUNCTIONS);
	dn->dn_checksum = checksum;
	dnode_setdirty(dn, tx);
	dnode_rele(dn, FTAG);
}

void
dmu_object_set_compress(objset_t *os, uint64_t object, uint8_t compress,
	dmu_tx_t *tx)
{
	dnode_t *dn;

	/* XXX assumes dnode_hold will not get an i/o error */
	(void) dnode_hold(os->os, object, FTAG, &dn);
	ASSERT(compress < ZIO_COMPRESS_FUNCTIONS);
	dn->dn_compress = compress;
	dnode_setdirty(dn, tx);
	dnode_rele(dn, FTAG);
}

int
dmu_offset_next(objset_t *os, uint64_t object, boolean_t hole, uint64_t *off)
{
	dnode_t *dn;
	int i, err;

	err = dnode_hold(os->os, object, FTAG, &dn);
	if (err)
		return (err);
	/*
	 * Sync any current changes before
	 * we go trundling through the block pointers.
	 */
	for (i = 0; i < TXG_SIZE; i++) {
		if (list_link_active(&dn->dn_dirty_link[i]))
			break;
	}
	if (i != TXG_SIZE) {
		dnode_rele(dn, FTAG);
		txg_wait_synced(dmu_objset_pool(os), 0);
		err = dnode_hold(os->os, object, FTAG, &dn);
		if (err)
			return (err);
	}

	err = dnode_next_offset(dn, (hole ? DNODE_FIND_HOLE : 0), off, 1, 1, 0);
	dnode_rele(dn, FTAG);

	return (err);
}

void
dmu_object_info_from_dnode(dnode_t *dn, dmu_object_info_t *doi)
{
	rw_enter(&dn->dn_struct_rwlock, RW_READER);
	mutex_enter(&dn->dn_mtx);

	doi->doi_data_block_size = dn->dn_datablksz;
	doi->doi_metadata_block_size = dn->dn_indblkshift ?
	    1ULL << dn->dn_indblkshift : 0;
	doi->doi_indirection = dn->dn_nlevels;
	doi->doi_checksum = dn->dn_checksum;
	doi->doi_compress = dn->dn_compress;
	doi->doi_physical_blks = (DN_USED_BYTES(dn->dn_phys) +
	    SPA_MINBLOCKSIZE/2) >> SPA_MINBLOCKSHIFT;
	doi->doi_max_block_offset = dn->dn_phys->dn_maxblkid;
	doi->doi_type = dn->dn_type;
	doi->doi_bonus_size = dn->dn_bonuslen;
	doi->doi_bonus_type = dn->dn_bonustype;

	mutex_exit(&dn->dn_mtx);
	rw_exit(&dn->dn_struct_rwlock);
}

/*
 * Get information on a DMU object.
 * If doi is NULL, just indicates whether the object exists.
 */
int
dmu_object_info(objset_t *os, uint64_t object, dmu_object_info_t *doi)
{
	dnode_t *dn;
	int err = dnode_hold(os->os, object, FTAG, &dn);

	if (err)
		return (err);

	if (doi != NULL)
		dmu_object_info_from_dnode(dn, doi);

	dnode_rele(dn, FTAG);
	return (0);
}

/*
 * As above, but faster; can be used when you have a held dbuf in hand.
 */
void
dmu_object_info_from_db(dmu_buf_t *db, dmu_object_info_t *doi)
{
	dmu_object_info_from_dnode(((dmu_buf_impl_t *)db)->db_dnode, doi);
}

/*
 * Faster still when you only care about the size.
 * This is specifically optimized for zfs_getattr().
 */
void
dmu_object_size_from_db(dmu_buf_t *db, uint32_t *blksize, u_longlong_t *nblk512)
{
	dnode_t *dn = ((dmu_buf_impl_t *)db)->db_dnode;

	*blksize = dn->dn_datablksz;
	/* add 1 for dnode space */
	*nblk512 = ((DN_USED_BYTES(dn->dn_phys) + SPA_MINBLOCKSIZE/2) >>
	    SPA_MINBLOCKSHIFT) + 1;
}

void
byteswap_uint64_array(void *vbuf, size_t size)
{
	uint64_t *buf = vbuf;
	size_t count = size >> 3;
	int i;

	ASSERT((size & 7) == 0);

	for (i = 0; i < count; i++)
		buf[i] = BSWAP_64(buf[i]);
}

void
byteswap_uint32_array(void *vbuf, size_t size)
{
	uint32_t *buf = vbuf;
	size_t count = size >> 2;
	int i;

	ASSERT((size & 3) == 0);

	for (i = 0; i < count; i++)
		buf[i] = BSWAP_32(buf[i]);
}

void
byteswap_uint16_array(void *vbuf, size_t size)
{
	uint16_t *buf = vbuf;
	size_t count = size >> 1;
	int i;

	ASSERT((size & 1) == 0);

	for (i = 0; i < count; i++)
		buf[i] = BSWAP_16(buf[i]);
}

/* ARGSUSED */
void
byteswap_uint8_array(void *vbuf, size_t size)
{
}

void
dmu_init(void)
{
	dbuf_init();
	dnode_init();
	arc_init();
	l2arc_init();
}

void
dmu_fini(void)
{
	arc_fini();
	dnode_fini();
	dbuf_fini();
	l2arc_fini();
}

#ifdef __APPLE__
int
dmu_allocate_check(objset_t *z_os, off_t length)
{
	dsl_dataset_t *d_data = z_os->os->os_dsl_dataset;
	uint64_t avail;

	avail = dsl_dir_space_available(d_data->ds_dir, NULL, 0, FALSE);

	if (length < avail)
		return (0);
	else 
		return (ENOSPC);
}
#endif /* __APPLE__ */
