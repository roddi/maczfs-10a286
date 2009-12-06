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

/* Portions Copyright 2007 Jeremy Teo */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/fcntl.h>
#include <vfs/vfs_support.h>
#include <sys/zfs_vnode.h>
#include <sys/zfs_vnode_if.h>
#include <sys/stat.h>
#include <sys/ucred.h>
#include <sys/unistd.h>
#include <sys/xattr.h>

#include <sys/zfs_context.h>
#include <sys/zfs_vfsops.h>
#include <sys/zfs_dir.h>
#include <sys/zfs_acl.h>
#include <sys/zfs_acl_kauth.h>
#include <sys/zfs_ioctl.h>
#include <sys/fs/zfs.h>
#include <sys/dmu.h>
#include <sys/dmu_objset.h>
#include <sys/dmu_tx.h>
#include <sys/dnode.h>
#include <sys/spa.h>
#include <sys/txg.h>
#include <sys/dbuf.h>
#include <sys/zap.h>
#include <sys/dirent.h>
#include <sys/sunddi.h>
#include <sys/zfs_ctldir.h>
#include <sys/zfs_fuid.h>
#include <sys/zfs_rlock.h>
#include <sys/unistd.h>
#include <sys/utfconv.h>
#include <sys/zil_impl.h>
#include <sys/zfs_ubc.h>
#include <miscfs/fifofs/fifo.h>
#include <sys/fs/zfs_fsctl.h>
#include <coverage.h>

CODE_COVERAGE_CHECK_INIT;

/*
 * Programming rules.
 *
 * Each vnode op performs some logical unit of work.  To do this, the ZPL must
 * properly lock its in-core state, create a DMU transaction, do the work,
 * record this work in the intent log (ZIL), commit the DMU transaction,
 * and wait for the intent log to commit if it is a synchronous operation.
 * Moreover, the vnode ops must work in both normal and log replay context.
 * The ordering of events is important to avoid deadlocks and references
 * to freed memory.  The example below illustrates the following Big Rules:
 *
 *  (1) A check must be made in each zfs thread for a mounted file system.
 *	This is done avoiding races using ZFS_ENTER(zfsvfs).
 *      A ZFS_EXIT(zfsvfs) is needed before all returns.  Any znodes
 *      must be checked with ZFS_VERIFY_ZP(zp).  Both of these macros
 *      can return EIO from the calling function.
 *
 *  (2)	vnode_put() should always be the last thing except for zil_commit()
 *	(if necessary) and ZFS_EXIT(). This is for 3 reasons:
 *	First, if it's the last reference, the vnode/znode
 *	can be freed, so the zp may point to freed memory.  Second, the last
 *	reference will call zfs_zinactive(), which may induce a lot of work --
 *	pushing cached pages (which acquires range locks) and syncing out
 *	cached atime changes.  Third, zfs_zinactive() may require a new tx,
 *	which could deadlock the system if you were already holding one.
 *
 *  (3)	All range locks must be grabbed before calling dmu_tx_assign(),
 *	as they can span dmu_tx_assign() calls.
 *
 *  (4)	Always pass zfsvfs->z_assign as the second argument to dmu_tx_assign().
 *	In normal operation, this will be TXG_NOWAIT.  During ZIL replay,
 *	it will be a specific txg.  Either way, dmu_tx_assign() never blocks.
 *	This is critical because we don't want to block while holding locks.
 *	Note, in particular, that if a lock is sometimes acquired before
 *	the tx assigns, and sometimes after (e.g. z_lock), then failing to
 *	use a non-blocking assign can deadlock the system.  The scenario:
 *
 *	Thread A has grabbed a lock before calling dmu_tx_assign().
 *	Thread B is in an already-assigned tx, and blocks for this lock.
 *	Thread A calls dmu_tx_assign(TXG_WAIT) and blocks in txg_wait_open()
 *	forever, because the previous txg can't quiesce until B's tx commits.
 *
 *	If dmu_tx_assign() returns ERESTART and zfsvfs->z_assign is TXG_NOWAIT,
 *	then drop all locks, call dmu_tx_wait(), and try again.
 *
 *  (5)	If the operation succeeded, generate the intent log entry for it
 *	before dropping locks.  This ensures that the ordering of events
 *	in the intent log matches the order in which they actually occurred.
 *
 *  (6)	At the end of each vnode op, the DMU tx must always commit,
 *	regardless of whether there were any errors.
 *
 *  (7)	After dropping all locks, invoke zil_commit(zilog, seq, foid)
 *	to ensure that synchronous semantics are provided when necessary.
 *
 * In general, this is how things should be ordered in each vnode op:
 *
 *	ZFS_ENTER(zfsvfs);		// exit if unmounted
 * top:
 *	zfs_dirent_lock(&dl, ...)	// lock directory entry (may VN_HOLD())
 *	rw_enter(...);			// grab any other locks you need
 *	tx = dmu_tx_create(...);	// get DMU tx
 *	dmu_tx_hold_*();		// hold each object you might modify
 *	error = dmu_tx_assign(tx, zfsvfs->z_assign);	// try to assign
 *	if (error) {
 *		rw_exit(...);		// drop locks
 *		zfs_dirent_unlock(dl);	// unlock directory entry
 *		vnode_put(...);		// release held vnodes
 *		if (error == ERESTART && zfsvfs->z_assign == TXG_NOWAIT) {
 *			dmu_tx_wait(tx);
 *			dmu_tx_abort(tx);
 *			goto top;
 *		}
 *		dmu_tx_abort(tx);	// abort DMU tx
 *		ZFS_EXIT(zfsvfs);	// finished in zfs
 *		return (error);		// really out of space
 *	}
 *	error = do_real_work();		// do whatever this VOP does
 *	if (error == 0)
 *		zfs_log_*(...);		// on success, make ZIL entry
 *	dmu_tx_commit(tx);		// commit DMU tx -- error or not
 *	rw_exit(...);			// drop locks
 *	zfs_dirent_unlock(dl);		// unlock directory entry
 *	vnode_put(...);			// release held vnodes
 *	zil_commit(zilog, seq, foid);	// synchronous when necessary
 *	ZFS_EXIT(zfsvfs);		// finished in zfs
 *	return (error);			// done, report error
 */



static int zfs_getsecattr(znode_t *, kauth_acl_t *, cred_t *);

static int zfs_setsecattr(znode_t *, kauth_acl_t, cred_t *);

int zfs_obtain_xattr(znode_t *, const char *, mode_t, cred_t *,
                     vnode_t **, int);

int zfs_vnop_fsync(struct vnop_fsync_args *ap);

int zfs_bulkaccess_check(zfsvfs_t *zfsvfs, struct vnop_ioctl_args *ap);


static int
zfs_vnop_open(struct vnop_open_args *ap)
{
	znode_t	*zp = VTOZ(ap->a_vp);
	int fmode = ap->a_mode;

	if ((fmode & FWRITE) && (zp->z_phys->zp_flags & ZFS_APPENDONLY) &&
	    ((fmode & O_APPEND) == 0)) {
		return (EPERM);
	}

	return (0);
}

static int
zfs_vnop_close(struct vnop_close_args *ap)
{
	return (0);
}

/*
 * Spotlight specific fsctl()'s.  When these get added to the system
 * fsctl.h we should delete them from here.  For now I'm putting ifdef
 * guards around them to avoid a dependency on xnu.
 */
#ifndef SPOTLIGHT_IOC_GET_MOUNT_TIME
#define SPOTLIGHT_IOC_GET_MOUNT_TIME _IOR('h', 18, u_int32_t)
#define SPOTLIGHT_FSCTL_GET_MOUNT_TIME IOCBASECMD(SPOTLIGHT_IOC_GET_MOUNT_TIME)
#endif
 
#ifndef SPOTLIGHT_IOC_GET_LAST_MTIME
#define SPOTLIGHT_IOC_GET_LAST_MTIME _IOR('h', 19, u_int32_t)
#define SPOTLIGHT_FSCTL_GET_LAST_MTIME IOCBASECMD(SPOTLIGHT_IOC_GET_LAST_MTIME)
#endif

static int
zfs_vnop_ioctl(struct vnop_ioctl_args *ap)
{
	user_addr_t	useraddr = CAST_USER_ADDR_T(ap->a_data);

	znode_t		*zp = VTOZ(ap->a_vp);
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	int		error;

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(zp);

	switch (ap->a_command) {
	case F_FULLFSYNC: {
		(void)zfs_vfs_sync(zfsvfs->z_vfs, 1/*waitfor*/, NULL/*vfs_context_t context*/);
		error = 0;
		break;
	}

	case SPOTLIGHT_FSCTL_GET_MOUNT_TIME:
		*(uint32_t *)ap->a_data = zfsvfs->z_mount_time;
		error = 0;
		break;

	case SPOTLIGHT_FSCTL_GET_LAST_MTIME:
		*(uint32_t *)ap->a_data = zfsvfs->z_last_unmount_time;
		error = 0;
		break;

	case ZFS_BULKACCESS_FSCTL: 
		error = zfs_bulkaccess_check(zfsvfs, ap);
		break;

	default:
		error = ENOTTY;
	}

	ZFS_EXIT(zfsvfs);
	return (error);
}

uint_t zfs_read_chunk_size = MAX_UPL_TRANSFER * PAGE_SIZE; /* Tunable */

static int
zfs_vnop_read(struct vnop_read_args *ap)
{
	vnode_t		*vp = ap->a_vp;
	struct uio	*uio = ap->a_uio;
	int		ioflag = ap->a_ioflag;

	znode_t		*zp = VTOZ(vp);
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	objset_t	*os;
	ssize_t		n, nbytes;
	int		error;
	rl_t		*rl;

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(zp);
	os = zfsvfs->z_os;

	/*
	 * Validate file offset
	 */
	if (uio_offset(uio) < (offset_t)0) {
		ZFS_EXIT(zfsvfs);
		return (EINVAL);
	}

	/*
	 * Fasttrack empty reads
	 */
	if (uio_resid(uio) == 0) {
		ZFS_EXIT(zfsvfs);
		return (0);
	}

	/*
	 * Note: In Mac OS X, mandatory lock checking occurs up in VFS layer.
	 */

	/*
	 * If we're in FRSYNC mode, sync out this znode before reading it.
	 */
	if (ioflag & FRSYNC)
		zil_commit(zfsvfs->z_log, zp->z_last_itx, zp->z_id);

	/*
	 * Lock the range against changes.
	 */
	rl = zfs_range_lock(zp, uio_offset(uio), uio_resid(uio), RL_READER);

	/*
	 * If we are reading past end-of-file we can skip
	 * to the end; but we might still need to set atime.
	 */
	if (uio_offset(uio) >= zp->z_phys->zp_size) {
		error = 0;
		goto out;
	}

	ASSERT(uio_offset(uio) < zp->z_phys->zp_size);
	n = MIN(uio_resid(uio), zp->z_phys->zp_size - uio_offset(uio));

	while (n > 0) {
		nbytes = MIN(n, zfs_read_chunk_size -
		    P2PHASE(uio_offset(uio), zfs_read_chunk_size));

		error = dmu_read_upl(vp, os, zp->z_id, uio, nbytes, ioflag);

		if (error)
			break;

		n -= nbytes;
	}

out:
	zfs_range_unlock(rl);

	ZFS_ACCESSTIME_STAMP(zfsvfs, zp);
	ZFS_EXIT(zfsvfs);
	return (error);
}

int
zfs_read(vnode_t *vp, struct uio *uio)
{
	struct vnop_read_args args;

	bzero(&args, sizeof(struct vnop_read_args));
	args.a_vp = vp;
	args.a_uio = uio;

	return zfs_vnop_read(&args);
}

/* 
 * Push VM pages in the given range to the ARC.
 * 
 * The zfs_range_lock lock must be held
 */
static int
zfs_cluster_push_now_impl(vnode_t *vp, objset_t *os, uint64_t object, upl_t upl,
    upl_page_info_t *pl, off_t f_offset, off_t upl_offset, size_t upl_size,
    int flags, dmu_tx_t *tx)
{
	/*
	 * For the first and last block, copy data into ARC and mark as clean.
	 * For other blocks, create a upli for each block with the proper vp,
	 * offset, and size
	 */
	int err;
	znode_t *zp = VTOZ(vp);
	dnode_t *dn = NULL;
	off_t fsblksz;
	uplinfo_t *upli = NULL;
	ssize_t		tx_bytes = 0;
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	zilog_t		*zilog = zfsvfs->z_log;
	off_t new_f_offset;
	int copy_to_arc = FALSE;
	sharedupl_t tmpsu;
	objset_impl_t *dnos;
	int compress, checksum;
	boolean_t commit_upl = (upl == NULL);
	int create_tx = (tx == NULL);

	ASSERT((f_offset & PAGE_MASK) == 0);
	/* upl_offset is meaningful only when upl is not empty */
	ASSERT(upl_offset == 0 || upl != NULL);

	debug_msg("%s: upl %p (vp %p vid %d off %d size %d)", __func__, upl, vp,
	    (int)vnode_vid(vp), (int)f_offset, (int)upl_size);

	if (create_tx) {
	  again:
		/* Start a transaction. */
		tx = dmu_tx_create(zfsvfs->z_os);
		dmu_tx_hold_bonus(tx, zp->z_id);
		dmu_tx_hold_write(tx, zp->z_id, f_offset, upl_size);
		err = dmu_tx_assign(tx, zfsvfs->z_assign);
		if (err) {
			if (err == ERESTART &&
				zfsvfs->z_assign == TXG_NOWAIT) {
				dmu_tx_wait(tx);
				dmu_tx_abort(tx);
				goto again;
			}
			dmu_tx_abort(tx);
			debug_msg("%s:%d err=%d", __func__, __LINE__, err);
			goto exit_no_commit;
		}
	}

	err = dnode_hold(os->os, object, FTAG, &dn);
	if (err) {
		debug_msg("%s:%d err=%d", __func__, __LINE__, err);
		dn = NULL;
		goto exit;
	}

	dnos = dn->dn_objset;
	compress = zio_compress_select(dn->dn_compress, dnos->os_compress);
	checksum = zio_checksum_select(dn->dn_checksum, dnos->os_checksum);
	fsblksz = dmu_get_fsblksz(dn);

	uint64_t maxblkid;
	maxblkid = howmany(zp->z_phys->zp_size, fsblksz) - 1;
	if (fsblksz < PAGE_SIZE && maxblkid > 0) {
		/* 
		 * This is a rare case that happens only on a close-to-full
		 * file system, we fall back to always use ARC to avoid the
		 * complexity that only part of the page is cleaned.
		 */
		upli = NULL;
		copy_to_arc = TRUE;
	} else {
		ASSERT((fsblksz & PAGE_MASK) == 0 || maxblkid == 0);
		upli = kmem_alloc(sizeof(uplinfo_t), KM_SLEEP);
		debug_msg_level(MSG_LEVEL - 10, "%s:%d alloc upli=%p stack:%p %p %p %p", __func__, __LINE__, upli, __builtin_return_address(1), __builtin_return_address(2), __builtin_return_address(3), __builtin_return_address(4));
		atomic_inc_32(&num_upli);
		bzero(upli, sizeof(uplinfo_t));
		upli->ui_vp = vp;
		upli->ui_vid = vnode_vid(vp);
		mutex_init(&upli->ui_lock, NULL, MUTEX_DEFAULT, NULL);
	}
	/* create upl in order to copy data to ARC for partial fill blocks */
	if (upl == NULL) {
		/* create upl that covers the asked range */
		upl_size = roundup(upl_size, PAGE_SIZE);
		uint64_t size = roundup(zp->z_phys->zp_size, PAGE_SIZE_64);
		if (f_offset + upl_size > size)
			upl_size = size - f_offset;
		ASSERT(upl_size);
		err = ubc_create_upl(vp, f_offset, upl_size, &upl, &pl, UPL_COPYOUT_FROM | UPL_SET_LITE);
		if (err) {
			debug_msg("%s:%d err=%d", __func__, __LINE__, err);
			goto exit;
		}
	}
	bzero(&tmpsu, sizeof(tmpsu));
	tmpsu.su_upl = upl;
	tmpsu.su_pl = pl;
	tmpsu.su_upl_f_off = f_offset;
	tmpsu.su_upl_size = upl_size;
	/* if file is opened for write and checksum or compress is on, the page could be changed while ZFS is checksuming or
	   compressing, thus getting inconsistent file.  So we have to copy the data to ARC.  Fortunately, this does not
	   happen often */
	if (zp->z_mmapped_for_write && (checksum != ZIO_CHECKSUM_OFF || compress != ZIO_COMPRESS_OFF)) {
		copy_to_arc = TRUE;
	}

	/* fill in the hole of the upl with valid data */
	off_t offset;
	int page_index, page_index_offset, page_index_end, page_index_hole_end;
	sharedupl_t supl;
	int bytes_to_copy;

	off_t blknum, startblk, endblk;
	uint64_t blkid;
	size_t num_io_pending = 0;
	upl_offset_t uploff;
	upl_size_t uplsize;
	int has_hole;
	off_t start, end;
	size_t total_valid_pages;

	/* find all fs blocks need to be read */
	startblk = f_offset / fsblksz;
	endblk = MIN(howmany(f_offset + upl_size, fsblksz), maxblkid + 1);

	/* find out total valid pages in advance, since upl will disappear after the last valid page is committed */

	total_valid_pages = 0;
	page_index_offset = upl_offset / PAGE_SIZE;
	page_index_end = howmany(upl_size, PAGE_SIZE) + page_index_offset;
	ASSERT(pl);
	ASSERT((upl_offset & PAGE_MASK) == 0); /* must be on page boundary */
	for (page_index = page_index_offset; page_index < page_index_end; page_index++) {
		if (upl_valid_page(pl, page_index))
			total_valid_pages++;
	}

	if (total_valid_pages == 0) { /* don't need to do anything besides abort the upl */
		CODE_COVERAGE_CHECK;
		ASSERT(upli != NULL);
		if (commit_upl)
			ubc_upl_abort_range(upl, upl_offset, upl_size, UPL_ABORT_FREE_ON_EMPTY);
		debug_msg("%s: total_valid_pages=0 aborted upl %p (vp %p off %d size %d)", __func__, upl, vp,
				  (int)f_offset, (int)upl_size);
		goto exit;
	}
	debug_msg("%s: vp=%p vid=%d valid_pages=%d startblk=%d endblk=%d fsblksz=%d", __func__, vp, (int)vnode_vid(vp), (int)total_valid_pages, (int)startblk, (int)endblk, (int)fsblksz);
	for (blknum = startblk; blknum < endblk; blknum++) {
		CODE_COVERAGE_CHECK;
		offset = blknum * fsblksz;
		blkid = dbuf_whichblock(dn, offset);
		rw_enter(&dn->dn_struct_rwlock, RW_READER);
		dmu_buf_impl_t *db = dbuf_hold(dn, blkid, FTAG);
		rw_exit(&dn->dn_struct_rwlock);
		if (db == NULL) {
			err = EIO;
			debug_msg("%s:%d err=%d", __func__, __LINE__, err);
			goto exit;
		}

		/* find whether there are holes in this upl */
		start = MAX(f_offset, offset);
		end = MIN(f_offset + upl_size, offset + fsblksz);
		has_hole = FALSE;
		if (fsblksz >= PAGE_SIZE) {
			page_index = (start - f_offset) / PAGE_SIZE + page_index_offset;
			page_index_end = howmany(end - f_offset, PAGE_SIZE) + page_index_offset;
			for (; page_index < page_index_end; page_index++) {
				if (!upl_valid_page(pl, page_index)) {
					has_hole = TRUE;
					break;
				}
			}
		}

		if (has_hole || offset < f_offset || offset + fsblksz > f_offset + upl_size) {
			CODE_COVERAGE_CHECK;
			/* blk is partially outside of upl, do read-modify-write */
			debug_msg("%s buf=%p partial fill state=%d db->db_buf->b_uplinfo=%p", __func__, db->db_buf, (int)db->db_state, 
					  db->db_buf ? db->db_buf->b_uplinfo : NULL);
			dmu_buf_will_dirty_osx(&db->db, tx, &tmpsu);
			bytes_to_copy = end - start;
			uploff = start - f_offset + upl_offset;
			uplsize = roundup(bytes_to_copy, PAGE_SIZE);
			if (db->db.db_data == NULL) { /* data is referred by the b_uplinfo */
				CODE_COVERAGE_CHECK;
				ASSERT(db->db_buf->b_uplinfo != NULL);

				/* 
				 * There are several different cases to handle here:
				 * 1. the existing upl does not cover this block, we need keep the fresh data in ARC other than UBC
				 *    if the upl has hole, we need to read the block from disk; we also need to copy data from upl to
				 *    ARC buffer; we also need to create additional upls for the uncovered range and copy data from
				 *    those upl into the ARC buffer.  We then can mark all pages this block covers as clean
				 * 2. if the upl has no hole and covers the block, all data are available in UBC:
				 *    we need to mark all pages dirty, so they won't disappear when we need them (when writing them)
				 * 3. if the upl has hole and covers the block:
				 *    we need to allocate a buffer for ARC, read the block from disk, and copy valid UBC data
				 *    into the buffer, then commit the upl pages and mark them clean
				 */

				boolean_t need_read_mod_write, need_more_ubc_data = FALSE;
				int num_uncoverred_part = 0;
				off_t more_upl_f_off[2], more_upl_size[2];
				/* upl doesn't fully cover the block */
				if (offset < f_offset || offset + fsblksz > f_offset + upl_size) {
					if (db->db_blkptr) { /* this buffer has an on-disk copy */
						CODE_COVERAGE_CHECK;
						need_read_mod_write = TRUE;
						need_more_ubc_data = TRUE;
						if (offset < f_offset) { /* the uncovered part is at the beginning */
							CODE_COVERAGE_CHECK;
							more_upl_f_off[num_uncoverred_part] = offset;
							more_upl_size[num_uncoverred_part] = roundup(f_offset - offset, PAGE_SIZE);
							num_uncoverred_part++;
						}
						if (offset + fsblksz > f_offset + upl_size) { /* the uncovered part is at the end */
							CODE_COVERAGE_CHECK;
							more_upl_f_off[num_uncoverred_part] = f_offset + upl_size;
							ASSERT(more_upl_f_off[num_uncoverred_part] % PAGE_SIZE == 0);
							more_upl_size[num_uncoverred_part] = 
								roundup(offset + fsblksz - more_upl_f_off[num_uncoverred_part], PAGE_SIZE);
							num_uncoverred_part++;
						}
					} else {	/* this buffer does not have on-disk copy, so everything is in UBC */
						CODE_COVERAGE_CHECK;
						need_read_mod_write = FALSE;
					}
				} else {														   /* upl covers the full block */
					if (!has_hole) { /* all pages of this block are in UBC.  Mark them dirty to keep them there */
						need_read_mod_write = FALSE;
					} else {
						/* keep data in ARC other than UBC, so we won't have undefined data when writing this block */
						need_read_mod_write = TRUE;
					}
				}
				ASSERT(!need_more_ubc_data || need_read_mod_write);
				if (need_read_mod_write) { // convert the ARC buffer to use internal buffer, and read data
					dbuf_conv_db_upl_to_arc(db, FALSE/*copy_data*/);
					/* read data from media so the data not covered by this upl will have valid data */
					err = arc_read_fill_buf(db, NULL/*upli*/, TRUE/*lock_db*/);
					if (err)
						debug_msg("%s:%d err=%d", __func__, __LINE__, err);

					/* since data in UPL is newer than data from media, copy all data we can find from upl into the
					 * block.  skip holes in the UPL */
					boolean_t has_valid_pages = FALSE;
					if (has_hole) {
						CODE_COVERAGE_CHECK;
						off_t page_start, page_end;
						for (page_index = (start - f_offset) / PAGE_SIZE + page_index_offset;
							 page_index < page_index_end; page_index++) {
							if (!upl_valid_page(pl, page_index)) {
								CODE_COVERAGE_CHECK;
								continue;
							}
							CODE_COVERAGE_CHECK;
							has_valid_pages = TRUE;
							page_start = (page_index - page_index_offset) * PAGE_SIZE + f_offset;
							page_end = MIN(f_offset + upl_size, page_start + PAGE_SIZE);
							err = copy_upl_to_mem(upl, page_start - f_offset + upl_offset, db->db.db_data + page_start - offset,
												  page_end - page_start, pl);
							if (err)
								debug_msg("%s:%d err=%d", __func__, __LINE__, err);
							debug_msg("%s:%d commit valid page only off=%d size=%d", __func__, __LINE__, (int)page_start, (int)(page_end - page_start));
						}
					} else {
						CODE_COVERAGE_CHECK;
						has_valid_pages = TRUE;
						err = copy_upl_to_mem(upl, uploff, db->db.db_data + start - offset, bytes_to_copy, pl);
						ASSERT(err == 0);
					}
					
					if (commit_upl && !(flags & UPL_NOCOMMIT)) {
						debug_msg("%s:%d upl=%p off=%d size=%d aborted offset=%d blknum=%d buf=%p upli=%p vid=%d", __func__, __LINE__,
								  upl, (int)uploff, (int)uplsize, (int)offset, (int)blknum, db->db_buf, 
								  db->db_buf->b_uplinfo ? db->db_buf->b_uplinfo : NULL,
								  db->db_buf->b_uplinfo ? (int)vnode_vid(db->db_buf->b_uplinfo->ui_vp) : 0);
						ubc_upl_commit_range(upl, uploff, uplsize, UPL_COMMIT_CLEAR_DIRTY | UPL_COMMIT_FREE_ON_EMPTY);
					}

					if (need_more_ubc_data) {
						int last_valid_page;
						upl_t more_upl;
						upl_page_info_t *more_pl;
						off_t page_start, page_end;
						int i;
						CODE_COVERAGE_CHECK;
						for (i = 0; i < num_uncoverred_part; i++) {
							CODE_COVERAGE_CHECK;
							debug_msg("%s: create upl f_off=%lld size=%lld", __func__, more_upl_f_off[i], more_upl_size[i]);
							err = ubc_create_upl(vp, more_upl_f_off[i], more_upl_size[i], &more_upl, &more_pl,
												 UPL_COPYOUT_FROM | UPL_SET_LITE);
							if (err)
								debug_msg("%s:%d err=%d", __func__, __LINE__, err);
							page_index_end = howmany(more_upl_size[i], PAGE_SIZE);
							/* find the last valid page */
							for (last_valid_page = page_index_end - 1; last_valid_page >= 0; last_valid_page--) {
								if (upl_valid_page(more_pl, last_valid_page))
									break;
							}
							/* copy every valid page */
							for (page_index = 0; page_index <= last_valid_page; page_index++) {
								if (!upl_valid_page(more_pl, page_index)) {
									CODE_COVERAGE_CHECK;
									continue;
								}
								CODE_COVERAGE_CHECK;
								page_start = page_index * PAGE_SIZE + more_upl_f_off[i];
								page_end = MIN(offset + fsblksz, page_start + PAGE_SIZE);
								if (page_start < page_end) {
									CODE_COVERAGE_CHECK;
									err = copy_upl_to_mem(more_upl, page_start - more_upl_f_off[i],
														  db->db.db_data + page_start - offset, page_end - page_start, more_pl);
								}
								if (err)
									debug_msg("%s:%d err=%d", __func__, __LINE__, err);
							}
							ubc_upl_commit_range(more_upl, 0, more_upl_size[i], UPL_COMMIT_CLEAR_DIRTY | UPL_COMMIT_FREE_ON_EMPTY);
						}
					} /* if need_more_ubc_data */
				} else {
					CODE_COVERAGE_CHECK;
					if (commit_upl && !(flags & UPL_NOCOMMIT)) {
						CODE_COVERAGE_CHECK;
						debug_msg("%s:%d upl=%p off=%d size=%d aborted offset=%d blknum=%d buf=%p upli=%p vid=%d", __func__, __LINE__,
								  upl, (int)uploff, (int)uplsize, (int)offset, (int)blknum, db->db_buf, db->db_buf->b_uplinfo,
								  (int)vnode_vid(db->db_buf->b_uplinfo->ui_vp));
						ubc_upl_commit_range(upl, uploff, uplsize, UPL_COMMIT_SET_DIRTY | UPL_COMMIT_FREE_ON_EMPTY);
					}
				}  /* if need_read_mod_write */
			} else {
				/* only copy & commit the valid pages, skip the invalid pages */
				boolean_t has_valid_pages = FALSE;
				if (has_hole) {
					CODE_COVERAGE_CHECK;
					off_t page_start, page_end;
					for (page_index = (start - f_offset) / PAGE_SIZE + page_index_offset;
						 page_index < page_index_end; page_index++) {
						if (!upl_valid_page(pl, page_index)) {
							CODE_COVERAGE_CHECK;
							continue;
						}
						CODE_COVERAGE_CHECK;
						has_valid_pages = TRUE;
						page_start = (page_index - page_index_offset) * PAGE_SIZE + f_offset;
						page_end = MIN(offset + fsblksz, page_start + PAGE_SIZE);
						err = copy_upl_to_mem(upl, page_start - f_offset + upl_offset, db->db.db_data + page_start - offset,
											  page_end - page_start, pl);
						if (err)
							debug_msg("%s:%d err=%d", __func__, __LINE__, err);
						debug_msg("%s:%d commit valid page only off=%d size=%d", __func__, __LINE__, (int)page_start, (int)(page_end - page_start));
					}
				} else {
					CODE_COVERAGE_CHECK;
					has_valid_pages = TRUE;
					err = copy_upl_to_mem(upl, uploff, db->db.db_data + start - offset, bytes_to_copy, pl);
					ASSERT(err == 0);
				}
				if (commit_upl && has_valid_pages && !(flags & UPL_NOCOMMIT)) {
					CODE_COVERAGE_CHECK;
					debug_msg("%s:%d upl=%p off=%d size=%d committed offset=%d start=%d end=%d blknum=%d", __func__, __LINE__, 
							  upl, (int)uploff, (int)uplsize, (int)offset, (int)start, (int)end, (int)blknum);
					ubc_upl_commit_range(upl, uploff, uplsize, UPL_COMMIT_FREE_ON_EMPTY);
				}
			}
			tx_bytes += bytes_to_copy;
		} else { 				/* block is totally within upl and does not have hole, simply write */
			uplinfo_t *cur_upli;
			if (copy_to_arc) {
				CODE_COVERAGE_CHECK;
				cur_upli = NULL;
			} else {
				CODE_COVERAGE_CHECK;
				cur_upli = kmem_alloc(sizeof(uplinfo_t), KM_SLEEP);
				debug_msg_level(MSG_LEVEL - 10, "%s:%d alloc upli=%p stack:%p %p %p %p", __func__, __LINE__, cur_upli, __builtin_return_address(1), __builtin_return_address(2), __builtin_return_address(3), __builtin_return_address(4));
				atomic_inc_32(&num_upli);
				memcpy(cur_upli, upli, sizeof(uplinfo_t));
				cur_upli->ui_f_off = offset;
				cur_upli->ui_size = fsblksz;
				mutex_init(&cur_upli->ui_lock, NULL, MUTEX_DEFAULT, NULL);
			}
			dmu_buf_will_fill_osx(&db->db, tx, cur_upli, &tmpsu);
			uploff = offset - f_offset + upl_offset;
			uplsize = roundup(db->db.db_size, PAGE_SIZE);
			debug_msg("%s:%d db_state=%d db_data=%p copy_to_arc=%d", __func__, __LINE__, db->db_state, db->db.db_data, copy_to_arc);
			if ((db->db_state == DB_CACHED && db->db.db_data != NULL) || copy_to_arc) { /* cannot use UBC.  copy into ARC */
				if (((dmu_buf_impl_t *)db)->db_buf->b_uplinfo != NULL) {
					CODE_COVERAGE_CHECK;
					dbuf_conv_db_upl_to_arc(db, TRUE/*copy_data*/);
				} else {
					CODE_COVERAGE_CHECK;
					err = copy_upl_to_mem(upl, uploff, db->db.db_data, db->db.db_size, pl);
					ASSERT(err == 0);
				}
				if (commit_upl && !(flags & UPL_NOCOMMIT) && upli != NULL) { /* when upli==NULL, upl will be committed as a whole below */
					CODE_COVERAGE_CHECK;
					debug_msg("%s:%d upl=%p off=%d size=%d committed", __func__, __LINE__, upl, (int)uploff, (int)uplsize);
					ubc_upl_commit_range(upl, uploff, uplsize, UPL_COMMIT_FREE_ON_EMPTY);
				}
				if (cur_upli != NULL) {
					CODE_COVERAGE_CHECK;
					debug_msg("%s:%d upli %p is freed", __func__, __LINE__, cur_upli);
					mutex_destroy(&cur_upli->ui_lock);
					atomic_dec_32(&num_upli);
#ifdef ZFS_DEBUG
					memset(cur_upli, 0xC4, sizeof(uplinfo_t));
#endif
					debug_msg_level(MSG_LEVEL - 10, "%s:%d upli=%p stack:%p %p %p %p", __func__, __LINE__, cur_upli, __builtin_return_address(1), __builtin_return_address(2), __builtin_return_address(3), __builtin_return_address(4));
					kmem_free(cur_upli, sizeof(uplinfo_t));
				}
			} else {
				CODE_COVERAGE_CHECK;
				/* this page is not cleared yet, we abort it so its dirty bit is left unchanged.  the write will happen
				 * some time later, and after the write is done this page will be marked as clean in sharedupl_put */
				ASSERT(upli != NULL);
				if (commit_upl && !(flags & UPL_NOCOMMIT)) {
					debug_msg("%s:%d upl=%p off=%d size=%d aborted", __func__, __LINE__, upl, (int)uploff, (int)uplsize);
					ubc_upl_abort_range(upl, uploff, uplsize, UPL_ABORT_FREE_ON_EMPTY);
				}
				if (db->db_buf->b_uplinfo != cur_upli) {
					CODE_COVERAGE_CHECK;
					debug_msg("%s:%d upli %p is freed", __func__, __LINE__, cur_upli);
					mutex_destroy(&cur_upli->ui_lock);
					atomic_dec_32(&num_upli);
#ifdef ZFS_DEBUG
					memset(cur_upli, 0xC5, sizeof(uplinfo_t));
#endif
					debug_msg_level(MSG_LEVEL - 10, "%s:%d upli=%p stack:%p %p %p %p", __func__, __LINE__, cur_upli, __builtin_return_address(1), __builtin_return_address(2), __builtin_return_address(3), __builtin_return_address(4));
					kmem_free(cur_upli, sizeof(uplinfo_t));
				}
			}
			dmu_buf_fill_done(&db->db, tx);
			tx_bytes += db->db.db_size;
		}
		dbuf_rele(db, FTAG);
	}

  exit:
	if (dn != NULL)
		dnode_rele(dn, FTAG);

	if (create_tx) {
		if (err == 0) {
			CODE_COVERAGE_CHECK;
			zfs_log_write(zilog, tx, TX_WRITE, zp, f_offset, tx_bytes, flags);
		} else {
			CODE_COVERAGE_CHECK;
			debug_msg("%s:%d err=%d", __func__, __LINE__, err);
		}
		dmu_tx_commit(tx);
	}

exit_no_commit:
	if (commit_upl && !(flags & UPL_NOCOMMIT) && upli == NULL) {
		CODE_COVERAGE_CHECK;
		debug_msg("%s:%d upl=%p off=0 size=%d committed", __func__, __LINE__, upl, (int)upl_size);
		ubc_upl_commit_range(upl, upl_offset, upl_size, UPL_COMMIT_FREE_ON_EMPTY);
	}
	if (upli != NULL) {
		CODE_COVERAGE_CHECK;
		mutex_destroy(&upli->ui_lock);
		atomic_dec_32(&num_upli);
#ifdef ZFS_DEBUG
		memset(upli, 0xC6, sizeof(uplinfo_t));
#endif
		debug_msg_level(MSG_LEVEL - 10, "%s:%d free upli=%p stack:%p %p %p %p", __func__, __LINE__, upli, __builtin_return_address(1), __builtin_return_address(2), __builtin_return_address(3), __builtin_return_address(4));
		kmem_free(upli, sizeof(uplinfo_t));
	}

	return err;
} /* zfs_cluster_push_now_impl */

static int
zfs_cluster_push_now(vnode_t *vp, objset_t *os, uint64_t object, upl_t upl, upl_page_info_t *pl, off_t f_offset,
					 off_t upl_offset, size_t nbytes, int flags, int max_push_size, dmu_tx_t *tx)
{
	int err;
	size_t bytes_to_push;

	/* we can never push more than a upl can handle in one shot */
	if (max_push_size > MAX_UPL_SIZE * PAGE_SIZE)
		max_push_size = MAX_UPL_SIZE * PAGE_SIZE;

	/* split into chunks of max_push_size on max_push_size boundary */
	while (nbytes > 0) {
		if (nbytes > max_push_size - (f_offset % max_push_size))
			bytes_to_push = max_push_size - (f_offset % max_push_size);
		else
			bytes_to_push = nbytes;
		err = zfs_cluster_push_now_impl(vp, os, object, upl, pl, f_offset, upl_offset, bytes_to_push, flags, tx);
		if (err != 0)
			break;
		f_offset += bytes_to_push;
		if (upl)				/* upl_offset is meaningful only when there is a upl */
			upl_offset += bytes_to_push;
		nbytes -= bytes_to_push;
	}
	return err;
}

static int
zfs_vnop_write(struct vnop_write_args *ap)
{
	vnode_t		*vp = ap->a_vp;
	struct uio	*uio = ap->a_uio;
	int		ioflag = ap->a_ioflag;
	cred_t		*cr = (cred_t *)vfs_context_ucred(ap->a_context);
	off_t		f_offset;
	size_t		upl_size;

	znode_t		*zp = VTOZ(vp);
	rlim64_t	limit = MAXOFFSET_T;
	ssize_t		start_resid = uio_resid(uio);
	ssize_t		tx_bytes;
	uint64_t	end_size;
	dmu_tx_t	*tx;
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	zilog_t		*zilog;
	offset_t	woff;
	ssize_t		n, nbytes;
	rl_t		*rl;
	int		max_blksz = zfsvfs->z_max_blksz;
	uint64_t	pflags;
	int		error = 0;
	offset_t	rl_off;
	ssize_t 	rl_len;

	/*
	 * Fasttrack empty write
	 */
	n = start_resid;
	if (n == 0)
		return (0);

	if (limit == RLIM64_INFINITY || limit > MAXOFFSET_T)
		limit = MAXOFFSET_T;

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(zp);

	/*
	 * If immutable or not appending then return EPERM
	 */
	pflags = zp->z_phys->zp_flags;
	if ((pflags & (ZFS_IMMUTABLE | ZFS_READONLY)) ||
	    ((pflags & ZFS_APPENDONLY) && !(ioflag & IO_APPEND) &&
	    (uio_offset(uio) < zp->z_phys->zp_size))) {
		ZFS_EXIT(zfsvfs);
		return (EPERM);
	}

	zilog = zfsvfs->z_log;

	/*
	 * Pre-fault the pages to ensure slow (eg NFS) pages
	 * don't hold up txg.
	 */
	zfs_prefault_write(n, uio);

	/*
	 * If in append mode, set the io offset pointer to eof.
	 *
	 * Note: OSX uses IO_APPEND flag in order to indicate to 
	 * append to a file as opposed to Solaris which uses the
	 * FAPPEND ioflag
	 */
	if (ioflag & IO_APPEND) {
		/*
		 * Range lock for a file append:
		 * The value for the start of range will be determined by
		 * zfs_range_lock() (to guarantee append semantics).
		 * If this write will cause the block size to increase,
		 * zfs_range_lock() will lock the entire file, so we must
		 * later reduce the range after we grow the block size.
		 */
		rl_off = 0;
		rl_len = n;
		rl = zfs_range_lock(zp, 0, n, RL_APPEND);
		if (rl->r_len == UINT64_MAX) {
			/* overlocked, zp_size can't change */
			woff = zp->z_phys->zp_size;
		} else {
			woff = rl->r_off;
		}
		uio_setoffset(uio, woff);
	} else {
		woff = uio_offset(uio);
		/*
		 * Validate file offset
		 */
		if (woff < 0) {
			ZFS_EXIT(zfsvfs);
			return (EINVAL);
		}

		/*
		 * If we need to grow the block size then zfs_range_lock()
		 * will lock a wider range than we request here.
		 * Later after growing the block size we reduce the range.
		 */
		off_t fsblksz;
		fsblksz = zp->z_blksz ? zp->z_blksz : PAGE_SIZE;
		rl_off = woff / fsblksz * fsblksz;
		rl_len = roundup(woff + n, fsblksz) - rl_off;
		rl = zfs_range_lock(zp, rl_off, rl_len, RL_WRITER);
	}

	if (woff >= limit) {
		zfs_range_unlock(rl);
		ZFS_EXIT(zfsvfs);
		return (EFBIG);
	}

	if ((woff + n) > limit || woff > (limit - n))
		n = limit - woff;

	/*
	 * Note: In Mac OS X, mandatory lock checking occurs up in VFS layer.
	 */

	end_size = MAX(zp->z_phys->zp_size, woff + n);

	/*
	 * Write the file in reasonable size chunks.  Each chunk is written
	 * in a separate transaction; this keeps the intent log records small
	 * and allows us to do more fine-grained space accounting.
	 */
	while (n > 0) {
		/*
		 * Start a transaction.
		 */
		woff = uio_offset(uio);
		tx = dmu_tx_create(zfsvfs->z_os);
		dmu_tx_hold_bonus(tx, zp->z_id);
		dmu_tx_hold_write(tx, zp->z_id, woff, MIN(n, max_blksz));
		error = dmu_tx_assign(tx, zfsvfs->z_assign);
		if (error) {
			if (error == ERESTART &&
			    zfsvfs->z_assign == TXG_NOWAIT) {
				dmu_tx_wait(tx);
				dmu_tx_abort(tx);
				CODE_COVERAGE_CHECK;
				continue;
			}
			dmu_tx_abort(tx);
			break;
		}

		/*
		 * If zfs_range_lock() over-locked we grow the blocksize
		 * and then reduce the lock range.  This will only happen
		 * on the first iteration since zfs_range_reduce() will
		 * shrink down r_len to the appropriate size.
		 */
		if (rl->r_len == UINT64_MAX) {
			uint64_t new_blksz;

			if (zp->z_blksz > max_blksz) {
				ASSERT(!ISP2(zp->z_blksz));
				new_blksz = MIN(end_size, SPA_MAXBLOCKSIZE);
			} else {
				new_blksz = MIN(end_size, max_blksz);
			}
			zfs_grow_blocksize(zp, new_blksz, tx);
			rl_off = woff / zp->z_blksz * zp->z_blksz;
			rl_len = roundup(woff + n, zp->z_blksz) - rl_off;
			zfs_range_reduce(rl, rl_off, rl_len);
			CODE_COVERAGE_CHECK;
		}

		/*
		 * XXX - should we really limit each write to z_max_blksz?
		 * Perhaps we should use SPA_MAXBLOCKSIZE chunks?
		 */
		nbytes = MIN(n, max_blksz - P2PHASE(woff, max_blksz));
		rw_enter(&zp->z_map_lock, RW_READER);

		tx_bytes = uio_resid(uio);

		rw_exit(&zp->z_map_lock);
		f_offset = uio_offset(uio) / PAGE_SIZE_64 * PAGE_SIZE_64;
		upl_size = roundup(uio_offset(uio) + nbytes, PAGE_SIZE_64) - f_offset;
		error = dmu_write_upl(vp, zfsvfs->z_os, zp->z_id, uio, nbytes, ioflag, tx);
		if (error) {
			dmu_tx_commit(tx);
			break;
		}
		tx_bytes -= uio_resid(uio);

		/*
		 * If we made no progress, we're done.  If we made even
		 * partial progress, update the znode and ZIL accordingly.
		 */
		if (tx_bytes == 0) {
			dmu_tx_commit(tx);
			ASSERT(error != 0);
			break;
		}

		/*
		 * Clear Set-UID/Set-GID bits on successful write if not
		 * privileged and at least one of the excute bits is set.
		 *
		 * It would be nice to to this after all writes have
		 * been done, but that would still expose the ISUID/ISGID
		 * to another app after the partial write is committed.
		 *
		 * Note: we don't call zfs_fuid_map_id() here because
		 * user 0 is not an ephemeral uid.
		 */
		mutex_enter(&zp->z_acl_lock);
		if ((zp->z_phys->zp_mode & (S_IXUSR | (S_IXUSR >> 3) |
		    (S_IXUSR >> 6))) != 0 &&
		    (zp->z_phys->zp_mode & (S_ISUID | S_ISGID)) != 0 &&
		    secpolicy_vnode_setid_retain(cr,
		    (zp->z_phys->zp_mode & S_ISUID) != 0 &&
		    zp->z_phys->zp_uid == 0) != 0) {
			zp->z_phys->zp_mode &= ~(S_ISUID | S_ISGID);
		}
		mutex_exit(&zp->z_acl_lock);

		/*
		 * Update time stamp.  NOTE: This marks the bonus buffer as
		 * dirty, so we don't have to do it again for zp_size.
		 */
		zfs_time_stamper(zp, CONTENT_MODIFIED, tx);

		/*
		 * Update the file size (zp_size) if it has changed;
		 * account for possible concurrent updates.
		 */
		while ((end_size = zp->z_phys->zp_size) < uio_offset(uio))
			(void) atomic_cas_64(&zp->z_phys->zp_size, end_size,
			    uio_offset(uio));

		/* let ARC know the dirty range of UBC */
		/* always give block aligned range, unless it's the last block */
		off_t f_off_aligned;
		size_t size_aligned;
		f_off_aligned = f_offset / zp->z_blksz * zp->z_blksz;
		size_aligned = f_offset + upl_size - f_off_aligned;
		if (roundup(f_off_aligned + size_aligned, zp->z_blksz) <= end_size) { /* not the last block */
			/* make it block aligned */
			size_aligned = roundup(roundup(f_off_aligned + size_aligned, zp->z_blksz), PAGE_SIZE) - f_off_aligned;
		}
		ASSERT((size_aligned % PAGE_SIZE) == 0);
		error = zfs_cluster_push_now(vp, zfsvfs->z_os, zp->z_id, NULL/*upl*/, NULL/*pl*/, f_off_aligned, 0, size_aligned,
									 0/*uplflags*/, max_blksz, tx);
		zfs_log_write(zilog, tx, TX_WRITE, zp, woff, tx_bytes, ioflag);
		dmu_tx_commit(tx);

		if (error != 0)
			break;
		ASSERT(tx_bytes == nbytes);
		n -= nbytes;
	}
	if (error) {
		debug_msg("%s: err=%d", __func__, error);
		//Debugger("write error");
	}

	zfs_range_unlock(rl);

	/*
	 * If we're in replay mode, or we made no progress, return error.
	 * Otherwise, it's at least a partial write, so it's successful.
	 */
	if (zfsvfs->z_assign >= TXG_INITIAL || uio_resid(uio) == start_resid) {
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	if (ioflag & IO_SYNC) {
		zil_commit(zilog, zp->z_last_itx, zp->z_id);
	}

	/* OS X: pageout requires that the UBC file size be current. */
	if (tx_bytes != 0) {
		ubc_setsize(vp, zp->z_phys->zp_size);
	}

	ZFS_EXIT(zfsvfs);
	return (error);
}

static void
zfs_get_done(dmu_buf_t *db, void *vzgd)
{
	zgd_t *zgd = (zgd_t *)vzgd;
	rl_t *rl = zgd->zgd_rl;
	vnode_t *vp = ZTOV(rl->r_zp);

	dmu_buf_rele(db, vzgd);
	zfs_range_unlock(rl);
	vnode_put(vp);
	zil_add_block(zgd->zgd_zilog, zgd->zgd_bp);
	kmem_free(zgd, sizeof (zgd_t));
}

/*
 * Get data to generate a TX_WRITE intent log record.
 */
int
zfs_get_data(void *arg, lr_write_t *lr, char *buf, zio_t *zio, znode_t *zp,
    rl_t *rl)
{
	zfsvfs_t *zfsvfs = arg;
	objset_t *os = zfsvfs->z_os;
	uint64_t off = lr->lr_offset;
	dmu_buf_t *db;
	zgd_t *zgd;
	int dlen = lr->lr_length;		/* length of user data */
	int error = 0;

	ASSERT(zio);
	ASSERT(dlen != 0);

	/*
	 * Write records come in two flavors: immediate and indirect.
	 * For small writes it's cheaper to store the data with the
	 * log record (immediate); for large writes it's cheaper to
	 * sync the data and get a pointer to it (indirect) so that
	 * we don't have to write the data twice.
	 */
	if (buf != NULL) { /* immediate write */
		CODE_COVERAGE_CHECK;
		/* Note that the caller already holds range lock */
		if (off >= zp->z_phys->zp_size) {
			error = ENOENT;
			goto out;
		}
		VERIFY(0 == dmu_read(os, lr->lr_foid, off, dlen, buf));
	} else { /* indirect write */
		CODE_COVERAGE_CHECK;
		uint64_t boff; /* block starting offset */

		/* Note that the caller already holds range lock */
		if (off >= zp->z_phys->zp_size) {
			error = ENOENT;
			goto out;
		}
		zgd = (zgd_t *)kmem_alloc(sizeof (zgd_t), KM_SLEEP);
		zgd->zgd_rl = rl;
		zgd->zgd_zilog = zfsvfs->z_log;
		zgd->zgd_bp = &lr->lr_blkptr;
		if (ISP2(zp->z_blksz)) {
			boff = P2ALIGN_TYPED(off, zp->z_blksz, uint64_t);
		} else {
			boff = 0;
		}
		VERIFY(0 == dmu_buf_hold(os, lr->lr_foid, boff, zgd, &db));
		ASSERT(boff == db->db_offset);
		lr->lr_blkoff = off - boff;
		error = dmu_sync(zio, db, &lr->lr_blkptr,
		    lr->lr_common.lrc_txg, zfs_get_done, zgd);
		ASSERT((error && error != EINPROGRESS) ||
		    lr->lr_length <= zp->z_blksz);
		if (error == 0)
			zil_add_block(zfsvfs->z_log, &lr->lr_blkptr);
		/*
		 * If we get EINPROGRESS, then we need to wait for a
		 * write IO initiated by dmu_sync() to complete before
		 * we can release this dbuf.  We will finish everything
		 * up in the zfs_get_done() callback.
		 */
		if (error == EINPROGRESS)
			return (0);
		dmu_buf_rele(db, zgd);
		kmem_free(zgd, sizeof (zgd_t));
	}
out:
	zfs_range_unlock(rl);
	vnode_put(ZTOV(zp));
	return (error);
}

static int
zfs_vnop_access(struct vnop_access_args *ap)
{
	vnode_t		*vp = ap->a_vp;
	int		mode = 0;
	int		action = ap->a_action;
	cred_t		*cr = (cred_t *)vfs_context_ucred(ap->a_context);

	znode_t		*zp = VTOZ(vp);
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	int		error;

	/* owner permissions */
	if (action & VREAD)
		mode |= S_IRUSR;
	if (action & VWRITE)
		mode |= S_IWUSR;
	if (action & VEXEC)
		mode |= S_IXUSR;

	/* group permissions */
	if (action & VREAD)
		mode |= S_IRGRP;
	if (action & VWRITE)
		mode |= S_IWGRP;
	if (action & VEXEC)
		mode |= S_IXGRP;

	/* world permissions */
	if (action & VREAD)
		mode |= S_IROTH;
	if (action & VWRITE)
		mode |= S_IWOTH;
	if (action & VEXEC)
		mode |= S_IXOTH;

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(zp);

	error = zfs_zaccess_rwx(zp, mode, 0, cr);

	ZFS_EXIT(zfsvfs);
	return (error);
}

/*
 * Lookup an entry in a directory
 */
static int
zfs_vnop_lookup(struct vnop_lookup_args *ap)
{
	vnode_t		*dvp = ap->a_dvp;
	vnode_t		**vpp = ap->a_vpp;
	cred_t		*cr = (cred_t *)vfs_context_ucred(ap->a_context);
	struct componentname  *cnp = ap->a_cnp;
	struct componentname  cn;
	char		smallname[64];
	char		*filename = NULL;
	char		* nm;
	int		flags;

	znode_t		*zdp = VTOZ(dvp);
	zfsvfs_t	*zfsvfs = zdp->z_zfsvfs;
	int		error;

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(zdp);

	*vpp = NULL;

	if (!vnode_isdir(dvp)) {
		ZFS_EXIT(zfsvfs);
		return (ENOTDIR);
	}

	/*
	 * Copy the component name so we can null terminate it.
	 */
	if (cnp->cn_namelen < sizeof(smallname)) {
		nm = &smallname[0];
	} else {
		nm = kmem_alloc(sizeof(char) * cnp->cn_namelen + 1, KM_SLEEP);
		if (nm == NULL) {
			ZFS_EXIT(zfsvfs);
			return (ENOMEM);
		}
	}
	bcopy(cnp->cn_nameptr, nm, cnp->cn_namelen);
	nm[cnp->cn_namelen] = '\0';
	bcopy(cnp, &cn, sizeof (cn));
	cn.cn_nameptr = nm;
	cn.cn_namelen = strlen(nm);

	flags = ZFS_IGNORECASE(zfsvfs) ? FIGNORECASE : 0;

	if (zfsvfs->z_utf8 && u8_validate(nm, strlen(nm),
	    NULL, U8_VALIDATE_ENTIRE, &error) < 0) {
		if (nm != &smallname[0])
			kmem_free(nm, sizeof(char) * cnp->cn_namelen + 1);
		ZFS_EXIT(zfsvfs);
		return (EILSEQ);
	}

	error = zfs_dirlook(zdp, nm, vpp, flags, &cn);

	if (nm != &smallname[0]) {
		kmem_free(nm, sizeof(char) * cnp->cn_namelen + 1);
	}

	switch (cnp->cn_nameiop) {
	case CREATE:
	case RENAME:
		if ((cnp->cn_flags & ISLASTCN) && (error == ENOENT)) {
			error = EJUSTRETURN;
		}
		break;
	}

	ZFS_EXIT(zfsvfs);
	return (error);
}

/*
 * Create a new file in a directory.
 */
static int
zfs_vnop_create(struct vnop_create_args *ap)
{
	vnode_t		*dvp = ap->a_dvp;
	vnode_t		**vpp = ap->a_vpp;
	struct vnode_attr     *vap = ap->a_vap;
	struct componentname  *cnp = ap->a_cnp;
	char * name = (char *)cnp->cn_nameptr;
	cred_t		*cr = (cred_t *)vfs_context_ucred(ap->a_context);
	struct kauth_acl	*kaclp = NULL;
	vcexcl_t	excl;
	int		mode;

	znode_t		*zp, *dzp = VTOZ(dvp);
	zfsvfs_t	*zfsvfs = dzp->z_zfsvfs;
	zilog_t		*zilog;
	objset_t	*os;
	zfs_dirlock_t	*dl;
	dmu_tx_t	*tx;
	int		error;
	zfs_acl_t	*aclp = NULL;
	zfs_fuid_info_t *fuidp = NULL;
	int		zflg;

	/*
	 * If we have an ephemeral id, then make
	 * sure file system is at proper version
	 */
	if ((zfsvfs->z_use_fuids == B_FALSE) &&
	    (IS_EPHEMERAL(crgetuid(cr)) || IS_EPHEMERAL(crgetgid(cr))))
		return (EINVAL);

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(dzp);
	os = zfsvfs->z_os;
	zilog = zfsvfs->z_log;

	if (zfsvfs->z_utf8 && u8_validate(name, strlen(name),
	    NULL, U8_VALIDATE_ENTIRE, &error) < 0) {
		ZFS_EXIT(zfsvfs);
		return (EILSEQ);
	}

	if (cnp->cn_namelen >= ZAP_MAXNAMELEN) {
		ZFS_EXIT(zfsvfs);
		return (ENAMETOOLONG);
	}

	if (VATTR_IS_ACTIVE(vap, va_acl) &&
	    (vap->va_acl != (kauth_acl_t) KAUTH_FILESEC_NONE) &&
	    (vap->va_acl->acl_entrycount != KAUTH_FILESEC_NOACL)) {
		kaclp = vap->va_acl;
		VATTR_SET_SUPPORTED(vap, va_acl);
	}

top:
	*vpp = NULL;

	excl = (vap->va_vaflags & VA_EXCLUSIVE) ? EXCL : NONEXCL;
	mode = MAKEIMODE(vap->va_type, vap->va_mode);
	zflg = ZFS_IGNORECASE(zfsvfs) ? ZCILOOK : 0;

	error = zfs_dirent_lock(&dl, dzp, name, &zp, zflg, cnp);
	if (error) {
		if (strcmp(name, "..") == 0)
			error = EISDIR;
		ZFS_EXIT(zfsvfs);
		if (aclp)
			zfs_acl_free(aclp);
		return (error);
	}

	if (kaclp && aclp == NULL) {
		error = zfs_kauth_2_aclp(zfsvfs, vap->va_type, kaclp, &aclp);
		if (error) {
			ZFS_EXIT(zfsvfs);
			if (dl)
				zfs_dirent_unlock(dl);
			return (error);
		}
	}

	if (zp == NULL) {
		uint64_t txtype;

		/*
		 * We only support the creation of regular files in
		 * extended attribute directories.
		 */
		if ((dzp->z_phys->zp_flags & ZFS_XATTR) &&
		    (vap->va_type != VREG)) {
			error = EINVAL;
			goto out;
		}

		tx = dmu_tx_create(os);
		dmu_tx_hold_bonus(tx, DMU_NEW_OBJECT);
		if ((aclp && aclp->z_has_fuids) || IS_EPHEMERAL(crgetuid(cr)) ||
		    IS_EPHEMERAL(crgetgid(cr))) {
			if (zfsvfs->z_fuid_obj == 0) {
				dmu_tx_hold_bonus(tx, DMU_NEW_OBJECT);
				dmu_tx_hold_write(tx, DMU_NEW_OBJECT, 0,
				    FUID_SIZE_ESTIMATE(zfsvfs));
				dmu_tx_hold_zap(tx, MASTER_NODE_OBJ,
				    FALSE, NULL);
			} else {
				dmu_tx_hold_bonus(tx, zfsvfs->z_fuid_obj);
				dmu_tx_hold_write(tx, zfsvfs->z_fuid_obj, 0,
				    FUID_SIZE_ESTIMATE(zfsvfs));
			}
		}
		dmu_tx_hold_bonus(tx, dzp->z_id);
		dmu_tx_hold_zap(tx, dzp->z_id, TRUE, name);
		if ((dzp->z_phys->zp_flags & ZFS_INHERIT_ACE) || aclp) {
			dmu_tx_hold_write(tx, DMU_NEW_OBJECT,
			    0, SPA_MAXBLOCKSIZE);
		}
		error = dmu_tx_assign(tx, zfsvfs->z_assign);
		if (error) {
			zfs_dirent_unlock(dl);
			if (error == ERESTART &&
			    zfsvfs->z_assign == TXG_NOWAIT) {
				dmu_tx_wait(tx);
				dmu_tx_abort(tx);
				goto top;
			}
			dmu_tx_abort(tx);
			ZFS_EXIT(zfsvfs);
			if (aclp)
				zfs_acl_free(aclp);
			return (error);
		}
		zfs_mknode(dzp, vap, tx, cr, 0, &zp, 0, aclp, &fuidp);
		(void) zfs_link_create(dl, zp, tx, ZNEW);
		txtype = TX_CREATE;
		if (ZFS_IGNORECASE(zfsvfs))
			txtype |= TX_CI;
		zfs_log_create(zilog, tx, txtype, dzp, zp, name, NULL, NULL, vap);
		if (fuidp)
			zfs_fuid_info_free(fuidp);
		dmu_tx_commit(tx);

		/*
		 * OS X - attach the vnode _after_ committing the transaction
		 */
		if ((error = zfs_attach_vnode(zp)) != 0) {
			zfs_zinactive(zp);
			zp = NULL;
		}
	} else {
		/*
		 * A directory entry already exists for this name.
		 */
		/*
		 * Can't truncate an existing file if in exclusive mode.
		 */
		if (excl == EXCL) {
			error = EEXIST;
			goto out;
		}
		/*
		 * Can't open a directory for writing.
		 */
		if (vnode_isdir(ZTOV(zp)) && (mode & S_IWRITE)) {
			error = EISDIR;
			goto out;
		}

		mutex_enter(&dzp->z_lock);
		dzp->z_seq++;
		mutex_exit(&dzp->z_lock);
	}
out:

	if (dl)
		zfs_dirent_unlock(dl);

	if (error) {
		if (zp)
			vnode_put(ZTOV(zp));
	} else {
		*vpp = ZTOV(zp);
	}
	if (aclp)
		zfs_acl_free(aclp);

	ZFS_EXIT(zfsvfs);
	return (error);
}

/*
 * Remove a file entry from a directory.
 *
 * Note: OS X doesn't support the "delete now" mode
 */
static int
zfs_vnop_remove(struct vnop_remove_args *ap)
{
	vnode_t		*dvp = ap->a_dvp;
	struct componentname  *cnp = ap->a_cnp;
	char * name = (char *)cnp->cn_nameptr;
	cred_t		*cr = (cred_t *)vfs_context_ucred(ap->a_context);

	znode_t		*zp, *dzp = VTOZ(dvp);
	vnode_t		*vp;
	zfsvfs_t	*zfsvfs = dzp->z_zfsvfs;
	zilog_t		*zilog;
	uint64_t	acl_obj, xattr_obj;
	zfs_dirlock_t	*dl;
	dmu_tx_t	*tx;
	boolean_t	unlinked;
	uint64_t	txtype;
	int		error;
	int		zflg = ZEXISTS;

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(dzp);
	zilog = zfsvfs->z_log;

	if (ZFS_IGNORECASE(zfsvfs)) {
		zflg |= ZCILOOK;
	}

top:
	/*
	 * Attempt to lock directory; fail if entry doesn't exist.
	 */
	if ((error = zfs_dirent_lock(&dl, dzp, name, &zp, zflg, cnp))) {
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	vp = ZTOV(zp);

	/*
	 * Need to use rmdir for removing directories.
	 */
	if (vnode_isdir(vp)) {
		error = EPERM;
		goto out;
	}

	/* Remove our entry from the namei cache. */
	cache_purge(vp);

	/*
	 * We may delete the znode now, or we may put it in the unlinked set;
	 * it depends on whether we're the last link, and on whether there are
	 * other holds on the vnode.  So we dmu_tx_hold() the right things to
	 * allow for either case.
	 */
	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_zap(tx, dzp->z_id, FALSE, name);
	dmu_tx_hold_bonus(tx, zp->z_id);

	/* are there any extended attributes? */
	if ((xattr_obj = zp->z_phys->zp_xattr) != 0) {
		/* XXX - do we need this if we are deleting? */
		dmu_tx_hold_bonus(tx, xattr_obj);
	}

	/* charge as an update -- would be nice not to charge at all */
	dmu_tx_hold_zap(tx, zfsvfs->z_unlinkedobj, FALSE, NULL);

	error = dmu_tx_assign(tx, zfsvfs->z_assign);
	if (error) {
		zfs_dirent_unlock(dl);
		vnode_put(vp);
		if (error == ERESTART && zfsvfs->z_assign == TXG_NOWAIT) {
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		dmu_tx_abort(tx);
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	/*
	 * Remove the directory entry.
	 */
	error = zfs_link_destroy(dl, zp, tx, zflg, &unlinked);

	if (error) {
		dmu_tx_commit(tx);
		goto out;
	}

	if (unlinked) {
		zfs_unlinked_add(zp, tx);
	}

	txtype = TX_REMOVE;
	if (ZFS_IGNORECASE(zfsvfs))
		txtype |= TX_CI;
	zfs_log_remove(zilog, tx, txtype, dzp, name);

	dmu_tx_commit(tx);
out:
	zfs_dirent_unlock(dl);

	vnode_put(vp);

	ZFS_EXIT(zfsvfs);
	return (error);
}

/*
 * Create a new directory.
 */
static int
zfs_vnop_mkdir(struct vnop_mkdir_args *ap)
{
	vnode_t		*dvp = ap->a_dvp;
	vnode_t		**vpp = ap->a_vpp;
	struct vnode_attr     *vap = ap->a_vap;
	struct componentname  *cnp = ap->a_cnp;
	char * dirname = (char *)cnp->cn_nameptr;
	cred_t		*cr = (cred_t *)vfs_context_ucred(ap->a_context);
	struct kauth_acl *kaclp = NULL;

	znode_t		*zp, *dzp = VTOZ(dvp);
	zfsvfs_t	*zfsvfs = dzp->z_zfsvfs;
	zilog_t		*zilog;
	zfs_dirlock_t	*dl;
	uint64_t	txtype;
	dmu_tx_t	*tx;
	int		error;
	zfs_acl_t	*aclp = NULL;
	zfs_fuid_info_t	*fuidp = NULL;
	int		zf = ZNEW;

	ASSERT(vap->va_type == VDIR);

	/*
	 * If we have an ephemeral id, then make
	 * sure file system is at proper version
	 */
	if ((zfsvfs->z_use_fuids == B_FALSE) &&
	    (IS_EPHEMERAL(crgetuid(cr)) || IS_EPHEMERAL(crgetgid(cr))))
		return (EINVAL);

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(dzp);
	zilog = zfsvfs->z_log;

	if (dzp->z_phys->zp_flags & ZFS_XATTR) {
		ZFS_EXIT(zfsvfs);
		return (EINVAL);
	}

	if (cnp->cn_namelen >= ZAP_MAXNAMELEN) {
		ZFS_EXIT(zfsvfs);
		return (ENAMETOOLONG);
	}
	if (zfsvfs->z_utf8 && u8_validate(dirname,
	    strlen(dirname), NULL, U8_VALIDATE_ENTIRE, &error) < 0) {
		ZFS_EXIT(zfsvfs);
		return (EILSEQ);
	}
	if (ZFS_IGNORECASE(zfsvfs))
		zf |= ZCILOOK;

	if (VATTR_IS_ACTIVE(vap, va_acl) &&
	    (vap->va_acl != (kauth_acl_t) KAUTH_FILESEC_NONE) &&
	    (vap->va_acl->acl_entrycount != KAUTH_FILESEC_NOACL)) {
		kaclp = vap->va_acl;
		VATTR_SET_SUPPORTED(vap, va_acl);
	}

	/*
	 * First make sure the new directory doesn't exist.
	 */
top:
	*vpp = NULL;

	if ((error = zfs_dirent_lock(&dl, dzp, dirname, &zp, zf, cnp))) {
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	if (kaclp && aclp == NULL) {
		error = zfs_kauth_2_aclp(zfsvfs, vap->va_type, kaclp, &aclp);
		if (error) {
			zfs_dirent_unlock(dl);
			ZFS_EXIT(zfsvfs);
			return (error);
		}
	}

	/*
	 * Add a new entry to the directory.
	 */
	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_zap(tx, dzp->z_id, TRUE, dirname);
	dmu_tx_hold_zap(tx, DMU_NEW_OBJECT, FALSE, NULL);
	if ((aclp && aclp->z_has_fuids) || IS_EPHEMERAL(crgetuid(cr)) ||
	    IS_EPHEMERAL(crgetgid(cr))) {
		if (zfsvfs->z_fuid_obj == 0) {
			dmu_tx_hold_bonus(tx, DMU_NEW_OBJECT);
			dmu_tx_hold_write(tx, DMU_NEW_OBJECT, 0,
			    FUID_SIZE_ESTIMATE(zfsvfs));
			dmu_tx_hold_zap(tx, MASTER_NODE_OBJ, FALSE, NULL);
		} else {
			dmu_tx_hold_bonus(tx, zfsvfs->z_fuid_obj);
			dmu_tx_hold_write(tx, zfsvfs->z_fuid_obj, 0,
			    FUID_SIZE_ESTIMATE(zfsvfs));
		}
	}
	if ((dzp->z_phys->zp_flags & ZFS_INHERIT_ACE) || aclp)
		dmu_tx_hold_write(tx, DMU_NEW_OBJECT,
		    0, SPA_MAXBLOCKSIZE);
	error = dmu_tx_assign(tx, zfsvfs->z_assign);
	if (error) {
		zfs_dirent_unlock(dl);
		if (error == ERESTART && zfsvfs->z_assign == TXG_NOWAIT) {
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		dmu_tx_abort(tx);
		ZFS_EXIT(zfsvfs);
		if (aclp)
			zfs_acl_free(aclp);
		return (error);
	}

	/*
	 * Create new node.
	 */
	zfs_mknode(dzp, vap, tx, cr, 0, &zp, 0, aclp, &fuidp);

	if (aclp)
		zfs_acl_free(aclp);

	/*
	 * Now put new name in parent dir.
	 */
	(void) zfs_link_create(dl, zp, tx, ZNEW);

	txtype = TX_MKDIR;
	if (ZFS_IGNORECASE(zfsvfs))
		txtype |= TX_CI;
	zfs_log_create(zilog, tx, txtype, dzp, zp, dirname, NULL, NULL, vap);

	if (fuidp)
		zfs_fuid_info_free(fuidp);
	dmu_tx_commit(tx);

	/*
	 * OS X - attach the vnode _after_ committing the transaction
	 */
	if ((error = zfs_attach_vnode(zp)) != 0) {
		zfs_zinactive(zp);
		zp = NULL;
	}

	*vpp = zp ? ZTOV(zp) : NULL;

	zfs_dirent_unlock(dl);

	ZFS_EXIT(zfsvfs);
	return (error);
}

/*
 * Remove a directory subdir entry.
 */
static int
zfs_vnop_rmdir(struct vnop_rmdir_args *ap)
{
	vnode_t		*dvp = ap->a_dvp;
	struct componentname *cnp = ap->a_cnp;
	char * name = (char *)cnp->cn_nameptr;
	cred_t		*cr = (cred_t *)vfs_context_ucred(ap->a_context);

	znode_t		*dzp = VTOZ(dvp);
	znode_t		*zp;
	vnode_t		*vp;
	zfsvfs_t	*zfsvfs = dzp->z_zfsvfs;
	zilog_t		*zilog;
	zfs_dirlock_t	*dl;
	dmu_tx_t	*tx;
	int		error;
	int		zflg = ZEXISTS;

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(dzp);
	zilog = zfsvfs->z_log;

	if (ZFS_IGNORECASE(zfsvfs))
		zflg |= ZCILOOK;
top:
	zp = NULL;

	/*
	 * Attempt to lock directory; fail if entry doesn't exist.
	 */
	if ((error = zfs_dirent_lock(&dl, dzp, name, &zp, zflg, cnp))) {
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	vp = ZTOV(zp);

	if (!vnode_isdir(vp)) {
		error = ENOTDIR;
		goto out;
	}

	/* OS X - Remove our entry from the namei cache. */
	cache_purge(vp);

	/*
	 * Grab a lock on the directory to make sure that no one is
	 * trying to add (or lookup) entries while we are removing it.
	 */
	rw_enter(&zp->z_name_lock, RW_WRITER);

	/*
	 * Grab a lock on the parent pointer to make sure we play well
	 * with the treewalk and directory rename code.
	 */
	rw_enter(&zp->z_parent_lock, RW_WRITER);

	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_zap(tx, dzp->z_id, FALSE, name);
	dmu_tx_hold_bonus(tx, zp->z_id);
	dmu_tx_hold_zap(tx, zfsvfs->z_unlinkedobj, FALSE, NULL);
	error = dmu_tx_assign(tx, zfsvfs->z_assign);
	if (error) {
		rw_exit(&zp->z_parent_lock);
		rw_exit(&zp->z_name_lock);
		zfs_dirent_unlock(dl);
		vnode_put(vp);
		if (error == ERESTART && zfsvfs->z_assign == TXG_NOWAIT) {
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		dmu_tx_abort(tx);
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	error = zfs_link_destroy(dl, zp, tx, zflg, NULL);

	if (error == 0) {
		uint64_t txtype = TX_RMDIR;
		if (ZFS_IGNORECASE(zfsvfs))
			txtype |= TX_CI;
		zfs_log_remove(zilog, tx, txtype, dzp, name);
	}

	dmu_tx_commit(tx);

	rw_exit(&zp->z_parent_lock);
	rw_exit(&zp->z_name_lock);
out:
	zfs_dirent_unlock(dl);

	vnode_put(vp);

	ZFS_EXIT(zfsvfs);
	return (error);
}

/*
 * Read as many directory entries as will fit into the provided
 * buffer from the given directory cursor position (specified in
 * the uio structure.
 *
 *	IN:
 *		a_vp		- vnode of directory to read.
 *		a_uio		- structure supplying read location,
 *			  		and return buffer.
 *		a_context	- caller context
 *
 *	OUT:	a_uio		- updated offset, buffer filled.
 *		a_numdirent	- updated number of directory entries.
 *		a_eofflag	- set to true if end-of-file detected.
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 * Timestamps:
 *	zp - atime updated
 *
 */

static int
zfs_vnop_readdir(struct vnop_readdir_args *ap)
{
	vnode_t		*vp = ap->a_vp;
	uio_t		uio = ap->a_uio;
	cred_t		*cr = (cred_t *)vfs_context_ucred(ap->a_context);
	int		*eofp =  ap->a_eofflag;

	znode_t		*zp = VTOZ(vp);
	char		*bufptr;
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	objset_t	*os;
	caddr_t		outbuf = NULL;
	size_t		bufsize;
	zap_cursor_t	zc;
	zap_attribute_t	zap;
	uint_t		bytes_wanted;
	uint64_t	offset; /* must be unsigned; checks for < 1 */
	int		local_eof;
	int		outcount;
	int		error;
	uint8_t		prefetch;
	int		extended;
	int		numdirent;

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(zp);

	/*
	 * If we are not given an eof variable,
	 * use a local one.
	 */
	if (eofp == NULL)
		eofp = &local_eof;

	/*
	 * Quit if directory has been removed (posix)
	 */
	if ((*eofp = zp->z_unlinked) != 0) {
		ZFS_EXIT(zfsvfs);
		return (0);
	}

	error = 0;
	os = zfsvfs->z_os;
	offset = uio_offset(uio);
	prefetch = zp->z_zn_prefetch;
	extended = (ap->a_flags & VNODE_READDIR_EXTENDED);
	numdirent = 0;

	/*
	 * Initialize the iterator cursor.
	 */
	if (offset <= 3) {
		/*
		 * Start iteration from the beginning of the directory.
		 */
		zap_cursor_init(&zc, os, zp->z_id);
	} else {
		/*
		 * The offset is a serialized cursor.
		 */
		zap_cursor_init_serialized(&zc, os, zp->z_id, offset);
	}

	/*
	 * Get space to change directory entries into fs independent format.
	 */
	bytes_wanted = uio_curriovlen(uio);
	bufsize = (size_t)bytes_wanted;
	outbuf = kmem_alloc(bufsize, KM_SLEEP);
	bufptr = (char *)outbuf;


	/*
	 * Transform to file-system independent format
	 */
	outcount = 0;
	while (outcount < bytes_wanted) {
		ino64_t objnum;
		ushort_t reclen;
		uint64_t *next;
		uint8_t dtype;
		size_t namelen;
		int ascii;

		/*
		 * Special case `.', `..', and `.zfs'.
		 *
		 * Note that the low 4 bits of the cookie returned by zap is 
		 * alsways zero. This allows us to use the low nibble for 
		 * "special" entries:
		 * We use 0 for '.', and 1 for '..'.
		 * If this is the root of the filesystem, we use the offset 2 
		 * for the *'.zfs' directory.
		 */
		if (offset == 0) {
			(void) strcpy(zap.za_name, ".");
			zap.za_normalization_conflict = 0;
			objnum = zp->z_id;
			dtype = DT_DIR;
		} else if (offset == 1) {
			(void) strcpy(zap.za_name, "..");
			zap.za_normalization_conflict = 0;
			objnum = zp->z_phys->zp_parent;
			dtype = DT_DIR;
		} else if (offset == 2 && zfs_show_ctldir(zp)) {
			(void) strcpy(zap.za_name, ZFS_CTLDIR_NAME);
			zap.za_normalization_conflict = 0;
			objnum = ZFSCTL_INO_ROOT;
			dtype = DT_DIR;
		} else {
			/*
			 * Grab next entry.
			 */
			if (error = zap_cursor_retrieve(&zc, &zap)) {
				if ((*eofp = (error == ENOENT)) != 0)
					break;
				else
					goto update;
			}

			if (zap.za_integer_length != 8 ||
			    zap.za_num_integers != 1) {
				cmn_err(CE_WARN, "zap_readdir: bad directory "
				    "entry, obj = %lld, offset = %lld\n",
				    (u_longlong_t)zp->z_id,
				    (u_longlong_t)offset);
				error = ENXIO;
				goto update;
			}

			objnum = ZFS_DIRENT_OBJ(zap.za_first_integer);
			dtype = ZFS_DIRENT_TYPE(zap.za_first_integer);
		}

		/*
		 * Check if name will fit.
		 *
		 * Note: non-ascii names may expand (up to 3x) when converted to NFD
		 */
		namelen = strlen(zap.za_name);
		ascii = is_ascii_str(zap.za_name);
		if (!ascii)
			namelen = MIN(extended ? MAXPATHLEN-1 : MAXNAMLEN, namelen * 3);
		reclen = DIRENT_RECLEN(namelen, extended);

		/*
		 * Will this entry fit in the buffer?
		 */
		if (outcount + reclen > bufsize) {
			/*
			 * Did we manage to fit anything in the buffer?
			 */
			if (!outcount) {
				error = EINVAL;
				goto update;
			}
			break;
		}
		/*
		 * Add this entry:
		 */
		if (extended) {
			dirent64_t  *odp;
			size_t  nfdlen;

			odp = (dirent64_t  *)bufptr;
			/* NOTE: d_seekoff is the offset for the *next* entry */
			next = &(odp->d_seekoff);
			odp->d_ino = objnum;
			odp->d_type = dtype;

			/*
			 * Mac OS X: non-ascii names are UTF-8 NFC on disk 
			 * so convert to NFD before exporting them.
			 */
			namelen = strlen(zap.za_name);
			if (ascii ||
			    utf8_normalizestr((const u_int8_t *)zap.za_name, namelen,
			                      (u_int8_t *)odp->d_name, &nfdlen,
			                      MAXPATHLEN-1, UTF_DECOMPOSED) != 0) {
				/* ASCII or normalization failed, just copy zap name. */
				(void) bcopy(zap.za_name, odp->d_name, namelen + 1);
			} else {
				/* Normalization succeeded (already in buffer). */
				namelen = nfdlen;
			}
			odp->d_namlen = namelen;
			odp->d_reclen = reclen = DIRENT_RECLEN(namelen, extended);
		} else {
			dirent_t  *odp;
			size_t  nfdlen;

			odp = (dirent_t  *)bufptr;
			odp->d_ino = objnum;
			odp->d_type = dtype;

			/*
			 * Mac OS X: non-ascii names are UTF-8 NFC on disk 
			 * so convert to NFD before exporting them.
			 */
			namelen = strlen(zap.za_name);
			if (ascii ||
			    utf8_normalizestr((const u_int8_t *)zap.za_name, namelen,
			                      (u_int8_t *)odp->d_name, &nfdlen,
			                      MAXNAMLEN, UTF_DECOMPOSED) != 0) {
				/* ASCII or normalization failed, just copy zap name. */
				(void) bcopy(zap.za_name, odp->d_name, namelen + 1);
			} else {
				/* Normalization succeeded (already in buffer). */
				namelen = nfdlen;
			}
			odp->d_namlen = namelen;
			odp->d_reclen = reclen = DIRENT_RECLEN(namelen, extended);
		}
		outcount += reclen;
		bufptr += reclen;
		numdirent++;
		ASSERT(outcount <= bufsize);

		/* Prefetch znode */
		if (prefetch)
			dmu_prefetch(os, objnum, 0, 0);

		/*
		 * Move to the next entry, fill in the previous offset.
		 */
		if (offset > 2 || (offset == 2 && !zfs_show_ctldir(zp))) {
			zap_cursor_advance(&zc);
			offset = zap_cursor_serialize(&zc);
		} else {
			offset += 1;
		}
		if (extended) {
			*next = offset;
		}
	}
	zp->z_zn_prefetch = B_FALSE; /* a lookup will re-enable pre-fetching */

	if (error = uio_move(outbuf, (long)outcount, UIO_READ, uio)) {
		/*
		 * Reset the pointer.
		 */
		offset = uio_offset(uio);
	}

update:
	zap_cursor_fini(&zc);
	if (outbuf) {
		kmem_free(outbuf, bufsize);
	}
	if (error == ENOENT) {
		error = 0;
	}
	ZFS_ACCESSTIME_STAMP(zfsvfs, zp);

	uio_setoffset(uio, offset);
	if (ap->a_numdirent) {
		*ap->a_numdirent = numdirent;
	}
	ZFS_EXIT(zfsvfs);
	return (error);
}

ulong_t zfs_fsync_sync_cnt = 4;

/* copied from udf.kext.  Should use qsort after <rdar://4707352> is fixed. */
errno_t
zfs_shellsort(void *data, size_t numItems, size_t itemSize, int (*comp)(const void *, const void *), char *tmpBuf);
errno_t
zfs_shellsort(void *data, size_t numItems, size_t itemSize, int (*comp)(const void *, const void *), char *tmpBuf)
{
	static size_t incs[16] = { 1391376, 463792, 198768, 86961, 33936, 13776, 4592, 1968, 861, 336, 
							   112, 48, 21, 7, 3, 1 };
	size_t i, j, k, h;
	char buf[16];
	char *tmp;

	if (itemSize <= 16) {
		tmp = buf;
	} else {
		if (tmpBuf != NULL) {
			tmp = tmpBuf;
		} else {
			tmp = kmem_alloc(sizeof(char) * itemSize, KM_SLEEP);
			if (tmp == NULL) {
				return ENOMEM;
			}
		}
	}

	for ( k = 0; k < 16; k++) {
		for (h = incs[k], i = h; i < numItems; i++) { 
			memcpy(tmp, (uint8_t*)data + i * itemSize, itemSize);
			j = i;
			while (j >= h && comp((uint8_t*)data + (j-h) * itemSize, tmp) > 0) { 
				memcpy((uint8_t*)data + j * itemSize, (uint8_t*)data + (j-h) * itemSize, itemSize);
				j -= h;
			}
			memcpy((uint8_t*)data + j * itemSize, tmp, itemSize);
		}
	}
	if (tmp != buf && tmp != tmpBuf)
		kmem_free(tmp, sizeof(char) * itemSize);
	return 0;
}

int
zfs_vnop_fsync(struct vnop_fsync_args *ap)
{
	vnode_t  *vp = ap->a_vp;
	int waitfor = (ap->a_waitfor == MNT_WAIT);

	znode_t		*zp = VTOZ(vp);
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;

#ifndef __APPLE__
	/*
	 * Regardless of whether this is required for standards conformance,
	 * this is the logical behavior when fsync() is called on a file with
	 * dirty pages.  We use B_ASYNC since the ZIL transactions are already
	 * going to be pushed out as part of the zil_commit().
	 */
	if (vn_has_cached_data(vp) && !(syncflag & FNODSYNC) &&
	    vnode_isreg(vp) && !(vnode_isswap(vp)))
		(void) VOP_PUTPAGE(vp, (offset_t)0, (size_t)0, B_ASYNC, cr);

	(void) tsd_set(zfs_fsyncer_key, (void *)zfs_fsync_sync_cnt);
#endif /*!__APPLE__*/

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(zp);

#ifdef ZFS_DEBUG
	znode_stalker(zp, N_vnop_fsync_zil);
#endif
	zil_commit(zfsvfs->z_log, zp->z_last_itx, zp->z_id);
	ZFS_EXIT(zfsvfs);
	return (0);
}

/*
 * Get file attributes.
 */
static int
zfs_vnop_getattr(struct vnop_getattr_args *ap)
{
	vnode_t  *vp = ap->a_vp;
	struct vnode_attr  *vap = ap->a_vap;
	kauth_cred_t crp = vfs_context_ucred(ap->a_context);

	znode_t		*zp = VTOZ(vp);
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	znode_phys_t	*pzp;
	uint64_t	links;

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(zp);
	pzp = zp->z_phys;

	mutex_enter(&zp->z_lock);

	/*
	 * Return all attributes.  It's cheaper to provide the answer
	 * than to determine whether we were asked the question.
	 */

	vap->va_mode = pzp->zp_mode & MODEMASK;
	vap->va_uid = pzp->zp_uid;
	vap->va_gid = pzp->zp_gid;
//	vap->va_fsid = zp->z_zfsvfs->z_vfs->vfs_dev;
	/*
	 * On Mac OS X we always export the root directory id as 2
	 */
	vap->va_fileid = (zp->z_id == zfsvfs->z_root) ? 2 : zp->z_id;
	if (vnode_isvroot(vp) && zfs_show_ctldir(zp))
		links = pzp->zp_links + 1;
	else
		links = pzp->zp_links;
	vap->va_nlink = links;
	vap->va_data_size = pzp->zp_size;
	vap->va_total_size = pzp->zp_size;
	vap->va_rdev = pzp->zp_rdev;
	vap->va_gen = pzp->zp_gen;

	ZFS_TIME_DECODE(&vap->va_create_time, pzp->zp_crtime);
	ZFS_TIME_DECODE(&vap->va_access_time, pzp->zp_atime);
	ZFS_TIME_DECODE(&vap->va_modify_time, pzp->zp_mtime);
	ZFS_TIME_DECODE(&vap->va_change_time, pzp->zp_ctime);
	/*
	 * For Carbon compatibility, pretend to support this legacy/unused attribute
	 */
	if (VATTR_IS_ACTIVE(vap, va_backup_time)) {
		vap->va_backup_time.tv_sec = 0;
		vap->va_backup_time.tv_nsec = 0;
		VATTR_SET_SUPPORTED(vap, va_backup_time);
	}
	vap->va_flags = zfs_getbsdflags(zp);
	/*
	 * On Mac OS X we always export the root directory id as 2 and its parent as 1
	 */
	if (zp->z_id == zfsvfs->z_root)
		vap->va_parentid = 1;
	else if (pzp->zp_parent == zfsvfs->z_root)
		vap->va_parentid = 2;
	else
		vap->va_parentid = pzp->zp_parent;

	vap->va_iosize = zp->z_blksz ? zp->z_blksz : zfsvfs->z_max_blksz;

	vap->va_supported |=
		VNODE_ATTR_va_mode |
		VNODE_ATTR_va_uid |
		VNODE_ATTR_va_gid |
//		VNODE_ATTR_va_fsid |
		VNODE_ATTR_va_fileid |
		VNODE_ATTR_va_nlink |
		VNODE_ATTR_va_data_size |
		VNODE_ATTR_va_total_size |
		VNODE_ATTR_va_rdev |
		VNODE_ATTR_va_gen |
		VNODE_ATTR_va_create_time |
		VNODE_ATTR_va_access_time |
		VNODE_ATTR_va_modify_time |
		VNODE_ATTR_va_change_time |
		VNODE_ATTR_va_flags |
		VNODE_ATTR_va_parentid |
		VNODE_ATTR_va_iosize;

	/* Don't include '.' and '..' in the number of entries */
	if (VATTR_IS_ACTIVE(vap, va_nchildren) && vnode_isdir(vp))
		VATTR_RETURN(vap, va_nchildren, pzp->zp_size - 2);

	if (VATTR_IS_ACTIVE(vap, va_acl)) {
		if (zp->z_phys->zp_acl.z_acl_count == 0) {
			vap->va_acl = (kauth_acl_t) KAUTH_FILESEC_NONE;
		} else {
			int error;

			if ((error = zfs_getacl_kauth(zp, &vap->va_acl, crp))) {
				ZFS_EXIT(zfsvfs);
				return (error);
			}
		}
		VATTR_SET_SUPPORTED(vap, va_acl);
		/* va_acl implies that va_uuuid and va_guuid are also supported. */
		VATTR_RETURN(vap, va_uuuid, kauth_null_guid);
		VATTR_RETURN(vap, va_guuid, kauth_null_guid);
	}
	mutex_exit(&zp->z_lock);

	if (VATTR_IS_ACTIVE(vap, va_data_alloc) || VATTR_IS_ACTIVE(vap, va_total_alloc)) {
		uint32_t  blksize;
		u_longlong_t  nblks;

		dmu_object_size_from_db(zp->z_dbuf, &blksize, &nblks);

		vap->va_data_alloc = (uint64_t)512LL * (uint64_t)nblks;
		vap->va_total_alloc = vap->va_data_alloc;
		vap->va_supported |= VNODE_ATTR_va_data_alloc | 
					VNODE_ATTR_va_total_alloc;
	}

	if (VATTR_IS_ACTIVE(vap, va_name)) {
		if (vnode_isvroot(vp)) {
			zfs_get_fsname(zfsvfs, vap->va_name);
			VATTR_SET_SUPPORTED(vap, va_name);
		} else if (zap_value_search(zfsvfs->z_os, pzp->zp_parent,
		           zp->z_id, ZFS_DIRENT_OBJ(-1ULL), vap->va_name) == 0) {
			VATTR_SET_SUPPORTED(vap, va_name);
		}
	}

	ZFS_EXIT(zfsvfs);
	return (0);
}

/*
 * Set file attributes.
 */
static int
zfs_vnop_setattr(struct vnop_setattr_args *ap)
{
	vnode_t  *vp = ap->a_vp;
	struct vnode_attr  *vap = ap->a_vap;
	kauth_cred_t  crp = vfs_context_ucred(ap->a_context);

	znode_t		*zp = VTOZ(vp);
	znode_phys_t	*pzp;
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	zilog_t		*zilog;
	dmu_tx_t	*tx;
	uint64_t	mask = vap->va_active;
	znode_t		*attrzp;
	int		error;

	if (mask == 0)
		return (0);

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(zp);

	pzp = zp->z_phys;
	zilog = zfsvfs->z_log;

top:
	attrzp = NULL;

	if (vfs_isrdonly(zfsvfs->z_vfs)) {
		ZFS_EXIT(zfsvfs);
		return (EROFS);
	}

	/*
	 * First validate permissions
	 */

	if (VATTR_IS_ACTIVE(vap, va_data_size)) {
		/*
		 * XXX - Note, we are not providing any open
		 * mode flags here (like FNDELAY), so we may
		 * block if there are locks present... this
		 * should be addressed in openat().
		 */
		/* XXX - would it be OK to generate a log record here? */
		error = zfs_freesp(zp, vap->va_size, 0, 0, FALSE);
		if (error) {
			ZFS_EXIT(zfsvfs);
			return (error);
		}
		/* Mac OS X: pageout requires that the UBC file size to be current. */
		ubc_setsize(vp, vap->va_data_size);

		VATTR_SET_SUPPORTED(vap, va_data_size);
	}

	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_bonus(tx, zp->z_id);

	if ((mask & (VNODE_ATTR_va_uid | VNODE_ATTR_va_gid)) &&
	    zp->z_phys->zp_xattr != 0) {
		error = zfs_zget(zp->z_zfsvfs, zp->z_phys->zp_xattr, &attrzp);
		if (error) {
			dmu_tx_abort(tx);
			ZFS_EXIT(zfsvfs);
			return (error);
		}
		dmu_tx_hold_bonus(tx, attrzp->z_id);
	}

	error = dmu_tx_assign(tx, zfsvfs->z_assign);
	if (error) {
		if (attrzp)
			vnode_put(ZTOV(attrzp));
		if (error == ERESTART && zfsvfs->z_assign == TXG_NOWAIT) {
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		dmu_tx_abort(tx);
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	dmu_buf_will_dirty(zp->z_dbuf, tx);

	/*
	 * Set each attribute requested.
	 * We group settings according to the locks they need to acquire.
	 *
	 * Note: you cannot set ctime directly, although it will be
	 * updated as a side-effect of calling this function.
	 */

	mutex_enter(&zp->z_lock);

	if (VATTR_IS_ACTIVE(vap, va_mode)) {
		zp->z_phys->zp_mode = (pzp->zp_mode & S_IFMT) |
		                      (vap->va_mode & ~S_IFMT);
		/* Note: OS X doesn't synchronize mode with ACL here */
		VATTR_SET_SUPPORTED(vap, va_mode);
	}

	if (attrzp)
		mutex_enter(&attrzp->z_lock);

	if (VATTR_IS_ACTIVE(vap, va_uid)) {
		zp->z_phys->zp_uid = (uint64_t)vap->va_uid;
		if (attrzp) {
			attrzp->z_phys->zp_uid = (uint64_t)vap->va_uid;
		}
		VATTR_SET_SUPPORTED(vap, va_uid);
	}

	if (VATTR_IS_ACTIVE(vap, va_gid)) {
		zp->z_phys->zp_gid = (uint64_t)vap->va_gid;
		if (attrzp)
			attrzp->z_phys->zp_gid = (uint64_t)vap->va_gid;
		VATTR_SET_SUPPORTED(vap, va_gid);
	}

	if (attrzp)
		mutex_exit(&attrzp->z_lock);

	if (VATTR_IS_ACTIVE(vap, va_access_time)) {
		ZFS_TIME_ENCODE(&vap->va_access_time, pzp->zp_atime);
		VATTR_SET_SUPPORTED(vap, va_access_time);
	}
	if (VATTR_IS_ACTIVE(vap, va_modify_time)) {
		ZFS_TIME_ENCODE(&vap->va_modify_time, pzp->zp_mtime);
		VATTR_SET_SUPPORTED(vap, va_modify_time);
	}
	if (VATTR_IS_ACTIVE(vap, va_create_time)) {
		ZFS_TIME_ENCODE(&vap->va_create_time, pzp->zp_crtime);
		VATTR_SET_SUPPORTED(vap, va_create_time);
	}
	/*
	 * For Carbon compatibility, pretend to support this legacy/unused attribute
	 */
	if (VATTR_IS_ACTIVE(vap, va_backup_time)) {
		VATTR_SET_SUPPORTED(vap, va_backup_time);
	}

	if (VATTR_IS_ACTIVE(vap, va_flags)) {
		zfs_setbsdflags(zp, vap->va_flags);
		VATTR_SET_SUPPORTED(vap, va_flags);
	}

	if (VATTR_IS_ACTIVE(vap, va_data_size))
		zfs_time_stamper_locked(zp, CONTENT_MODIFIED, tx);
	else if (mask != 0)
		zfs_time_stamper_locked(zp, STATE_CHANGED, tx);

	if (mask != 0) {
		struct vnode_attr va;

		/* zfs_log_setattr() peeks at all the following: */
		va.va_active = mask;
		va.va_mode = pzp->zp_mode;
		va.va_uid = pzp->zp_uid;
		va.va_gid = pzp->zp_gid;
		va.va_size = pzp->zp_size;
		ZFS_TIME_DECODE(&va.va_atime, pzp->zp_atime);
		ZFS_TIME_DECODE(&va.va_mtime, pzp->zp_mtime);

		zfs_log_setattr(zilog, tx, TX_SETATTR, zp, &va, mask, NULL);
	}

	mutex_exit(&zp->z_lock);

	if (attrzp) {
		vnode_put(ZTOV(attrzp));
	}
	dmu_tx_commit(tx);

	/*
	 * zfs_setacl() will utilize its own separate transaction
	 */
	if (VATTR_IS_ACTIVE(vap, va_acl)) {
		struct kauth_acl *aclp;

		if ((vap->va_acl != (kauth_acl_t) KAUTH_FILESEC_NONE) &&
		    (vap->va_acl->acl_entrycount != KAUTH_FILESEC_NOACL)) {
			aclp = vap->va_acl;
		} else {
			aclp = kauth_acl_alloc(0);
			if (aclp == NULL) {
				error = ENOMEM;
				goto out;
			}
		}
		error = zfs_setacl_kauth(zp, aclp, crp);
		if (aclp != vap->va_acl)
			kauth_acl_free(aclp);
		if (error)
			goto out;
		VATTR_SET_SUPPORTED(vap, va_acl);
	}
out:
	ZFS_EXIT(zfsvfs);
	return (error);
}

typedef struct zfs_zlock {
	krwlock_t	*zl_rwlock;	/* lock we acquired */
	znode_t		*zl_znode;	/* znode we held */
	struct zfs_zlock *zl_next;	/* next in list */
} zfs_zlock_t;

/*
 * Drop locks and release vnodes that were held by zfs_rename_lock().
 */
static void
zfs_rename_unlock(zfs_zlock_t **zlpp)
{
	zfs_zlock_t *zl;

	while ((zl = *zlpp) != NULL) {
		if (zl->zl_znode != NULL)
			vnode_put(ZTOV(zl->zl_znode));
		rw_exit(zl->zl_rwlock);
		*zlpp = zl->zl_next;
		kmem_free(zl, sizeof (*zl));
	}
}

/*
 * Search back through the directory tree, using the ".." entries.
 * Lock each directory in the chain to prevent concurrent renames.
 * Fail any attempt to move a directory into one of its own descendants.
 * XXX - z_parent_lock can overlap with map or grow locks
 */
static int
zfs_rename_lock(znode_t *szp, znode_t *tdzp, znode_t *sdzp, zfs_zlock_t **zlpp)
{
	zfs_zlock_t	*zl;
	znode_t		*zp = tdzp;
	uint64_t	rootid = zp->z_zfsvfs->z_root;
	uint64_t	*oidp = &zp->z_id;
	krwlock_t	*rwlp = &szp->z_parent_lock;
	krw_t		rw = RW_WRITER;

	/*
	 * First pass write-locks szp and compares to zp->z_id.
	 * Later passes read-lock zp and compare to zp->z_parent.
	 */
	do {
		if (!rw_tryenter(rwlp, rw)) {
			/*
			 * Another thread is renaming in this path.
			 * Note that if we are a WRITER, we don't have any
			 * parent_locks held yet.
			 */
			if (rw == RW_READER && zp->z_id > szp->z_id) {
				/*
				 * Drop our locks and restart
				 */
				zfs_rename_unlock(&zl);
				*zlpp = NULL;
				zp = tdzp;
				oidp = &zp->z_id;
				rwlp = &szp->z_parent_lock;
				rw = RW_WRITER;
				continue;
			} else {
				/*
				 * Wait for other thread to drop its locks
				 */
				rw_enter(rwlp, rw);
			}
		}

		zl = kmem_alloc(sizeof (*zl), KM_SLEEP);
		zl->zl_rwlock = rwlp;
		zl->zl_znode = NULL;
		zl->zl_next = *zlpp;
		*zlpp = zl;

		if (*oidp == szp->z_id)		/* We're a descendant of szp */
			return (EINVAL);

		if (*oidp == rootid)		/* We've hit the top */
			return (0);

		if (rw == RW_READER) {		/* i.e. not the first pass */
			int error = zfs_zget(zp->z_zfsvfs, *oidp, &zp);
			if (error)
				return (error);
			zl->zl_znode = zp;
		}
		oidp = &zp->z_phys->zp_parent;
		rwlp = &zp->z_parent_lock;
		rw = RW_READER;

	} while (zp->z_id != sdzp->z_id);

	return (0);
}

static int
zfs_vnop_rename(struct vnop_rename_args *ap)
{
	vnode_t		*sdvp = ap->a_fdvp;
	vnode_t		*tdvp = ap->a_tdvp;
	struct componentname  *scnp = ap->a_fcnp;
	struct componentname  *tcnp = ap->a_tcnp;
	char *snm = (char *)scnp->cn_nameptr;
	char *tnm = (char *)tcnp->cn_nameptr;

	znode_t		*tdzp, *szp, *tzp;
	znode_t		*sdzp = VTOZ(sdvp);
	zfsvfs_t	*zfsvfs = sdzp->z_zfsvfs;
	zilog_t		*zilog;
	zfs_dirlock_t	*sdl, *tdl;
	dmu_tx_t	*tx;
	zfs_zlock_t	*zl;
	int		cmp, serr, terr;
	int		error = 0;
	int		zflg = 0;

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(sdzp);
	zilog = zfsvfs->z_log;

	if (vnode_mount(tdvp) != vnode_mount(sdvp)) {
		ZFS_EXIT(zfsvfs);
		return (EXDEV);
	}

	tdzp = VTOZ(tdvp);
	ZFS_VERIFY_ZP(tdzp);

	if (ap->a_tcnp->cn_namelen >= ZAP_MAXNAMELEN) {
		ZFS_EXIT(zfsvfs);
		return (ENAMETOOLONG);
	}
	if (zfsvfs->z_utf8 && u8_validate(tnm,
	    strlen(tnm), NULL, U8_VALIDATE_ENTIRE, &error) < 0) {
		ZFS_EXIT(zfsvfs);
		return (EILSEQ);
	}

	if (ZFS_IGNORECASE(zfsvfs))
		zflg |= ZCILOOK;

top:
	szp = NULL;
	tzp = NULL;
	zl = NULL;

	/*
	 * This is to prevent the creation of links into attribute space
	 * by renaming a linked file into/outof an attribute directory.
	 * See the comment in zfs_link() for why this is considered bad.
	 */
	if ((tdzp->z_phys->zp_flags & ZFS_XATTR) !=
	    (sdzp->z_phys->zp_flags & ZFS_XATTR)) {
		ZFS_EXIT(zfsvfs);
		return (EINVAL);
	}

	/*
	 * Lock source and target directory entries.  To prevent deadlock,
	 * a lock ordering must be defined.  We lock the directory with
	 * the smallest object id first, or if it's a tie, the one with
	 * the lexically first name.
	 */
	if (sdzp->z_id < tdzp->z_id) {
		cmp = -1;
	} else if (sdzp->z_id > tdzp->z_id) {
		cmp = 1;
	} else {
		/*
		 * First compare the two name arguments without
		 * considering any case folding.
		 */
		int nofold = (zfsvfs->z_norm & ~U8_TEXTPREP_TOUPPER);

		cmp = u8_strcmp(snm, tnm, 0, nofold, U8_UNICODE_LATEST, &error);
		ASSERT(error == 0 || !zfsvfs->z_utf8);
		if (cmp == 0) {
			/*
			 * POSIX: "If the old argument and the new argument
			 * both refer to links to the same existing file,
			 * the rename() function shall return successfully
			 * and perform no other action."
			 */
			ZFS_EXIT(zfsvfs);
			return (0);
		}
		/*
		 * If the file system is case-insensitive, then we may
		 * have some more checking to do.  Note that the file
		 * system is always case preserving.
		 *
		 * If the source and target names provided differ only
		 * by case (e.g. rename "jared" to "Jared"), we will
		 * treat this as a special case. As long as the source
		 * name is an exact match, we will allow this rename
		 * to proceed as a name-change request.
		 */
		if ((zfsvfs->z_case == ZFS_CASE_INSENSITIVE) &&
		    u8_strcmp(snm, tnm, 0, zfsvfs->z_norm, U8_UNICODE_LATEST,
		    &error) == 0) {
			/*
			 * case preserving rename request, require exact
			 * name matches
			 */
			zflg |= ZCIEXACT;
			zflg &= ~ZCILOOK;
		}
	}

	if (cmp < 0) {
		serr = zfs_dirent_lock(&sdl, sdzp, snm, &szp,
		                       ZEXISTS | zflg, scnp);
		terr = zfs_dirent_lock(&tdl, tdzp, tnm, &tzp,
		                       ZRENAMING | zflg, tcnp);
	} else {
		terr = zfs_dirent_lock(&tdl, tdzp, tnm, &tzp,
		                       zflg, tcnp);
		serr = zfs_dirent_lock(&sdl, sdzp, snm, &szp,
		                       ZEXISTS | ZRENAMING | zflg, scnp);
	}

	if (serr) {
		/*
		 * Source entry invalid or not there.
		 */
		if (!terr) {
			zfs_dirent_unlock(tdl);
			if (tzp)
				vnode_put(ZTOV(tzp));
		}
		if (strcmp(snm, "..") == 0)
			serr = EINVAL;
		ZFS_EXIT(zfsvfs);
		return (serr);
	}
	if (terr) {
		zfs_dirent_unlock(sdl);
		vnode_put(ZTOV(szp));
		if (strcmp(tnm, "..") == 0)
			terr = EINVAL;
		ZFS_EXIT(zfsvfs);
		return (terr);
	}

	if (vnode_isdir(ZTOV(szp))) {
		/*
		 * Check to make sure rename is valid.
		 * Can't do a move like this: /usr/a/b to /usr/a/b/c/d
		 */
		if (error = zfs_rename_lock(szp, tdzp, sdzp, &zl))
			goto out;
	}

	/*
	 * Does target exist?
	 */
	if (tzp) {
		/*
		 * Source and target must be the same type.
		 */
		if (vnode_isdir(ZTOV(szp))) {
			if (!vnode_isdir(ZTOV(tzp))) {
				error = ENOTDIR;
				goto out;
			}
		} else {
			if (vnode_isdir(ZTOV(tzp))) {
				error = EISDIR;
				goto out;
			}
		}
		/*
		 * POSIX dictates that when the source and target
		 * entries refer to the same file object, rename
		 * must do nothing and exit without error.
		 */
		if (szp->z_id == tzp->z_id) {
			error = 0;
			goto out;
		}
	}

	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_bonus(tx, szp->z_id);	/* nlink changes */
	dmu_tx_hold_bonus(tx, sdzp->z_id);	/* nlink changes */
	dmu_tx_hold_zap(tx, sdzp->z_id, FALSE, snm);
	dmu_tx_hold_zap(tx, tdzp->z_id, TRUE, tnm);
	if (sdzp != tdzp)
		dmu_tx_hold_bonus(tx, tdzp->z_id);	/* nlink changes */
	if (tzp)
		dmu_tx_hold_bonus(tx, tzp->z_id);	/* parent changes */
	dmu_tx_hold_zap(tx, zfsvfs->z_unlinkedobj, FALSE, NULL);
	error = dmu_tx_assign(tx, zfsvfs->z_assign);
	if (error) {
		if (zl != NULL)
			zfs_rename_unlock(&zl);
		zfs_dirent_unlock(sdl);
		zfs_dirent_unlock(tdl);
		vnode_put(ZTOV(szp));
		if (tzp)
			vnode_put(ZTOV(tzp));
		if (error == ERESTART && zfsvfs->z_assign == TXG_NOWAIT) {
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		dmu_tx_abort(tx);
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	if (tzp)	/* Attempt to remove the existing target */
		error = zfs_link_destroy(tdl, tzp, tx, zflg, NULL);

	if (error == 0) {
		error = zfs_link_create(tdl, szp, tx, ZRENAMING);
		if (error == 0) {
			error = zfs_link_destroy(sdl, szp, tx, ZRENAMING, NULL);
			ASSERT(error == 0);

			zfs_log_rename(zilog, tx,
			    TX_RENAME | (ZFS_IGNORECASE(zfsvfs) ? TX_CI : 0),
			    sdzp, sdl->dl_name, tdzp, tdl->dl_name, szp);

			/* Update path information for the target vnode */
			/* XXX OS X update identity here ? */
		}
	}

	/* Remove entries from the namei cache. */
	cache_purge(ZTOV(szp));
	if (tzp)
		cache_purge(ZTOV(tzp));

	dmu_tx_commit(tx);
out:
	if (zl != NULL)
		zfs_rename_unlock(&zl);

	zfs_dirent_unlock(sdl);
	zfs_dirent_unlock(tdl);

	vnode_put(ZTOV(szp));
	if (tzp)
		vnode_put(ZTOV(tzp));

	ZFS_EXIT(zfsvfs);
	return (error);
}

static int
zfs_vnop_symlink(struct vnop_symlink_args *ap)
{
	vnode_t  *dvp = ap->a_dvp;
	struct componentname  *cnp = ap->a_cnp;
	char * name = (char *)cnp->cn_nameptr;
	struct vnode_attr  *vap = ap->a_vap;
	char  *link = ap->a_target;
	cred_t  *cr = (cred_t *)vfs_context_ucred(ap->a_context);

	znode_t		*zp, *dzp = VTOZ(dvp);
	zfs_dirlock_t	*dl;
	dmu_tx_t	*tx;
	zfsvfs_t	*zfsvfs = dzp->z_zfsvfs;
	zilog_t		*zilog;
	int		len = strlen(link);
	int		error;
	int		zflg = ZNEW;
	zfs_fuid_info_t *fuidp = NULL;
	uint64_t	zoid;

	ASSERT(vap->va_type == VLNK);

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(dzp);
	zilog = zfsvfs->z_log;

	if (cnp->cn_namelen >= ZAP_MAXNAMELEN) {
		ZFS_EXIT(zfsvfs);
		return (ENAMETOOLONG);
	}
	if (zfsvfs->z_utf8 && u8_validate(name, strlen(name),
	    NULL, U8_VALIDATE_ENTIRE, &error) < 0) {
		ZFS_EXIT(zfsvfs);
		return (EILSEQ);
	}
	if (ZFS_IGNORECASE(zfsvfs))
		zflg |= ZCILOOK;
top:
	if (len > MAXPATHLEN) {
		ZFS_EXIT(zfsvfs);
		return (ENAMETOOLONG);
	}

	/*
	 * Attempt to lock directory; fail if entry already exists.
	 */
	error = zfs_dirent_lock(&dl, dzp, name, &zp, zflg, cnp);
	if (error) {
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_write(tx, DMU_NEW_OBJECT, 0, MAX(1, len));
	dmu_tx_hold_bonus(tx, dzp->z_id);
	dmu_tx_hold_zap(tx, dzp->z_id, TRUE, name);
	if (dzp->z_phys->zp_flags & ZFS_INHERIT_ACE)
		dmu_tx_hold_write(tx, DMU_NEW_OBJECT, 0, SPA_MAXBLOCKSIZE);
	if (IS_EPHEMERAL(crgetuid(cr)) || IS_EPHEMERAL(crgetgid(cr))) {
		if (zfsvfs->z_fuid_obj == 0) {
			dmu_tx_hold_bonus(tx, DMU_NEW_OBJECT);
			dmu_tx_hold_write(tx, DMU_NEW_OBJECT, 0,
			    FUID_SIZE_ESTIMATE(zfsvfs));
			dmu_tx_hold_zap(tx, MASTER_NODE_OBJ, FALSE, NULL);
		} else {
			dmu_tx_hold_bonus(tx, zfsvfs->z_fuid_obj);
			dmu_tx_hold_write(tx, zfsvfs->z_fuid_obj, 0,
			    FUID_SIZE_ESTIMATE(zfsvfs));
		}
	}
	error = dmu_tx_assign(tx, zfsvfs->z_assign);
	if (error) {
		zfs_dirent_unlock(dl);
		if (error == ERESTART && zfsvfs->z_assign == TXG_NOWAIT) {
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		dmu_tx_abort(tx);
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	dmu_buf_will_dirty(dzp->z_dbuf, tx);

	/*
	 * Create a new object for the symlink.
	 * Put the link content into bonus buffer if it will fit;
	 * otherwise, store it just like any other file data.
	 */
	if (sizeof (znode_phys_t) + len <= dmu_bonus_max()) {
		zfs_mknode(dzp, vap, tx, cr, 0, &zp, len, NULL, &fuidp);
		if (len != 0)
			bcopy(link, zp->z_phys + 1, len);
	} else {
		dmu_buf_t *dbp;

		zfs_mknode(dzp, vap, tx, cr, 0, &zp, 0, NULL, &fuidp);

		/*
		 * Nothing can access the znode yet so no locking needed
		 * for growing the znode's blocksize.
		 */
		zfs_grow_blocksize(zp, len, tx);

		VERIFY(0 == dmu_buf_hold(zfsvfs->z_os,
		    zp->z_id, 0, FTAG, &dbp));
		dmu_buf_will_dirty(dbp, tx);

		ASSERT3U(len, <=, dbp->db_size);
		bcopy(link, dbp->db_data, len);
		dmu_buf_rele(dbp, FTAG);
	}
	zp->z_phys->zp_size = len;

	/*
	 * Insert the new object into the directory.
	 */
	(void) zfs_link_create(dl, zp, tx, ZNEW);

	if (error == 0) {
		uint64_t txtype = TX_SYMLINK;
		if (ZFS_IGNORECASE(zfsvfs))
			txtype |= TX_CI;
		zfs_log_symlink(zilog, tx, txtype, dzp, zp, name, link);
	}

	if (fuidp)
		zfs_fuid_info_free(fuidp);

	dmu_tx_commit(tx);

	/*
	 * OS X - attach the vnode _after_ committing the transaction
	 */
	if ((error = zfs_attach_vnode(zp)) != 0) {
		zfs_zinactive(zp);
		zp = NULL;
	}

	zfs_dirent_unlock(dl);

	if (ap->a_vpp)
		*ap->a_vpp = zp ? ZTOV(zp) : NULL;

	ZFS_EXIT(zfsvfs);
	return (error);
}

static int
zfs_vnop_readlink(struct vnop_readlink_args *ap)
{
	vnode_t  *vp = ap->a_vp;
	struct uio  *uio = ap->a_uio;

	znode_t		*zp = VTOZ(vp);
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	size_t		bufsz;
	int		error;

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(zp);

	bufsz = (size_t)zp->z_phys->zp_size;
	if (bufsz + sizeof (znode_phys_t) <= zp->z_dbuf->db_size) {
		error = uio_move((caddr_t)(zp->z_phys + 1),
		    MIN((size_t)bufsz, uio_resid(uio)), UIO_READ, uio);
	} else {
		dmu_buf_t *dbp;
		error = dmu_buf_hold(zfsvfs->z_os, zp->z_id, 0, FTAG, &dbp);
		if (error) {
			ZFS_EXIT(zfsvfs);
			return (error);
		}
		error = uio_move(dbp->db_data,
		    MIN((size_t)bufsz, uio_resid(uio)), UIO_READ, uio);
		dmu_buf_rele(dbp, FTAG);
	}

	ZFS_ACCESSTIME_STAMP(zfsvfs, zp);
	ZFS_EXIT(zfsvfs);
	return (error);
}

static int
zfs_vnop_link(struct vnop_link_args *ap)
{
	vnode_t  *tdvp = ap->a_tdvp;
	vnode_t  *svp = ap->a_vp;
	struct componentname  *cnp = ap->a_cnp;
	char * name = (char *)cnp->cn_nameptr;

	znode_t		*dzp = VTOZ(tdvp);
	znode_t		*tzp, *szp;
	zfsvfs_t	*zfsvfs = dzp->z_zfsvfs;
	zilog_t		*zilog;
	zfs_dirlock_t	*dl;
	dmu_tx_t	*tx;
	int		error;
	int		zf = ZNEW;

	ASSERT(vnode_isdir(tdvp));

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(dzp);
	zilog = zfsvfs->z_log;

	if (vnode_mount(svp) != vnode_mount(tdvp)) {
		ZFS_EXIT(zfsvfs);
		return (EXDEV);
	}
	szp = VTOZ(svp);
	ZFS_VERIFY_ZP(szp);

	if (cnp->cn_namelen >= ZAP_MAXNAMELEN) {
		ZFS_EXIT(zfsvfs);
		return (ENAMETOOLONG);
	}
	if (zfsvfs->z_utf8 && u8_validate(name,
	    strlen(name), NULL, U8_VALIDATE_ENTIRE, &error) < 0) {
		ZFS_EXIT(zfsvfs);
		return (EILSEQ);
	}
	if (ZFS_IGNORECASE(zfsvfs))
		zf |= ZCILOOK;

top:
	/*
	 * We do not support links between attributes and non-attributes
	 * because of the potential security risk of creating links
	 * into "normal" file space in order to circumvent restrictions
	 * imposed in attribute space.
	 */
	if ((szp->z_phys->zp_flags & ZFS_XATTR) !=
	    (dzp->z_phys->zp_flags & ZFS_XATTR)) {
		ZFS_EXIT(zfsvfs);
		return (EINVAL);
	}

	/*
	 * POSIX dictates that we return EPERM here.
	 * Better choices include ENOTSUP or EISDIR.
	 */
	if (vnode_isdir(svp)) {
		ZFS_EXIT(zfsvfs);
		return (EPERM);
	}

	/*
	 * Attempt to lock directory; fail if entry already exists.
	 */
	error = zfs_dirent_lock(&dl, dzp, name, &tzp, zf, cnp);
	if (error) {
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_bonus(tx, szp->z_id);
	dmu_tx_hold_zap(tx, dzp->z_id, TRUE, name);
	error = dmu_tx_assign(tx, zfsvfs->z_assign);
	if (error) {
		zfs_dirent_unlock(dl);
		if (error == ERESTART && zfsvfs->z_assign == TXG_NOWAIT) {
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		dmu_tx_abort(tx);
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	error = zfs_link_create(dl, szp, tx, 0);

	if (error == 0) {
		uint64_t txtype = TX_LINK;
		if (ZFS_IGNORECASE(zfsvfs))
			txtype |= TX_CI;
		zfs_log_link(zilog, tx, txtype, dzp, szp, name);
	}

	dmu_tx_commit(tx);

	zfs_dirent_unlock(dl);

	ZFS_EXIT(zfsvfs);
	return (error);
}

static int
zfs_vnop_pagein(struct vnop_pagein_args *ap)
{
	vnode_t	*vp = ap->a_vp;
	offset_t	off = ap->a_f_offset;
	size_t		len = ap->a_size;
	upl_t		upl = ap->a_pl;
	vm_offset_t	upl_offset = ap->a_pl_offset;

	znode_t		*zp = VTOZ(vp);
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	vm_offset_t	vaddr;
	int		flags = ap->a_flags;
	int		need_unlock = 0;
	int		error = 0;

	if (upl == (upl_t)NULL)
		panic("zfs_vnop_pagein: no upl!");

	if (len <= 0) {
		printf("zfs_vnop_pagein: invalid size %ld", len);
		if (!(flags & UPL_NOCOMMIT))
			(void) ubc_upl_abort(upl, UPL_ABORT_FREE_ON_EMPTY);
		return (EINVAL);
	}

	ASSERT(zp->z_phys);

	/* can't fault past EOF */
	if ((off < 0) || (off >= zp->z_phys->zp_size) ||
	    (len & PAGE_MASK) || (upl_offset & PAGE_MASK)) {
		if (!(flags & UPL_NOCOMMIT))
			ubc_upl_abort_range(upl, upl_offset, len,
				UPL_ABORT_ERROR | UPL_ABORT_FREE_ON_EMPTY);
		return (EFAULT);
	}

	/*
	 * If we already own the lock, then we must be page faulting
	 * in the middle of a write to this file (i.e., we are writing
	 * to this file using data from a mapped region of the file).
	 */
	if (!rw_write_held(&zp->z_map_lock)) {
		rw_enter(&zp->z_map_lock, RW_WRITER);
		need_unlock = TRUE;
	}

	error = dmu_pagein(vp, zp->z_zfsvfs->z_os, zp->z_id, off, len, upl, upl_offset);

	if (!(flags & UPL_NOCOMMIT)) {
		if (error) {
			ubc_upl_abort_range(upl, upl_offset, ap->a_size,
					    UPL_ABORT_ERROR |
					    UPL_ABORT_FREE_ON_EMPTY);
		} else {
			ubc_upl_commit_range(upl, upl_offset, ap->a_size,
					     UPL_COMMIT_CLEAR_DIRTY |
					     UPL_COMMIT_FREE_ON_EMPTY);
		}
	}
	ZFS_ACCESSTIME_STAMP(zfsvfs, zp);

	/*
	 * We can't grab the range lock for the page as reader which would
	 * stop truncation as this leads to deadlock. So we need to recheck
	 * the file size.
	 */
	if (ap->a_f_offset >= zp->z_phys->zp_size) {
		error = EFAULT;
	}
	if (need_unlock) {
		rw_exit(&zp->z_map_lock);
	}

	return (error);
}

static int
zfs_vnop_pageout(struct vnop_pageout_args *ap)
{
	vnode_t		*vp = ap->a_vp;
	offset_t	off = ap->a_f_offset;
	offset_t	newoff;
	size_t		len = ap->a_size;
	int		flags = ap->a_flags;
	int		uplflags;

	znode_t		*zp = VTOZ(vp);
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	zilog_t		*zilog = zfsvfs->z_log;
	upl_t		upl = ap->a_pl;
	upl_page_info_t *pl;
	vm_offset_t	upl_offset = ap->a_pl_offset;
	rl_t		*rl;
	uint64_t	filesz;
	int		error = 0;
	size_t		fsblksz;

	if (ISSET(flags, UPL_MSYNC))
		uplflags = UPL_UBC_MSYNC;
	else
		uplflags = UPL_UBC_PAGEOUT;

	ASSERT(!(flags & UPL_NOCOMMIT)); /* this is for swap files only, not yet supported on ZFS */
	ASSERT(upl == NULL); 	/* zfs is responsible to create the upl */

	if (zfsvfs == NULL) {
		error = ENXIO;
		goto exit_abort;
	}

	/* OS X - can't use ZFS_ENTER macro since we may have to cleanup UPL */
	rrw_enter(&(zfsvfs)->z_teardown_lock, RW_READER, FTAG);
	if (zfsvfs->z_unmounted) {
		error = EIO;
		goto exit_abort;
	}

	ASSERT(zp->z_phys);

	if (len <= 0) {
		printf("zfs_vnop_pageout: invalid size %ld", len);
		error = EINVAL;
		goto exit_abort;
	}
	if (vnode_vfsisrdonly(vp)) {
		error = EROFS;
		goto exit_abort;
	}

	fsblksz = zp->z_blksz ? zp->z_blksz : PAGE_SIZE;

	/* expand the range so it starts and ends on file block boundary */
	newoff = off / fsblksz * fsblksz;
	len += (off - newoff);
	off = newoff;

	if (off + len < zp->z_phys->zp_size) {
		len = roundup(len, fsblksz);
		if (len & ~PAGE_MASK) { /* fsblksz is NOT a multiple of PAGE_SIZE */
			len = roundup(len, PAGE_SIZE);
		}
	}

	zilog = zfsvfs->z_log;
	rl = zfs_range_lock(zp, off, len, RL_WRITER);
	/*
	 * Can't push pages past end-of-file.  File size may have changed before we grab the range lock, so we must check
	 * after we have the range lock
	 */
	filesz = zp->z_phys->zp_size; /* get consistent copy of zp_size */
	if ((off < 0) || (off >= filesz) ||
	    (off & PAGE_MASK_64) || (len & PAGE_MASK)) { /* totally out of file range, abort the whole range */
		error = EINVAL;
		zfs_range_unlock(rl);
		goto exit_abort;
	}
	off_t rounded_filesz = roundup(filesz, PAGE_SIZE);
	if (off + len > rounded_filesz) {
		/* abort the range out of EOF */
		VERIFY(ubc_create_upl(vp, rounded_filesz, off + len - rounded_filesz, &upl, &pl, uplflags) == 0);
		ubc_upl_abort(upl, UPL_ABORT_FREE_ON_EMPTY);
		len = rounded_filesz - off;
	}

	/* split into smaller chunks if necessary */
	int max_blksz = zfsvfs->z_max_blksz;

	/* now we have all the locks, create the upl, insert it into the avl tree, so it can be found by sharedupl_get
	 * before they do I/Os */
	size_t upl_size = roundup(len, PAGE_SIZE);
	uint64_t size = roundup(zp->z_phys->zp_size, PAGE_SIZE_64);
	if (off + upl_size > size)
		upl_size = size - off;
	error = ubc_create_upl(vp, off, upl_size, &upl, &pl, uplflags);
	if (error) {
		goto out;
	}
	sharedupl_t supl;
	bzero(&supl, sizeof(sharedupl_t));
	supl.su_upl_f_off = off;
	supl.su_upl_size = upl_size;
	supl.su_upl_off = 0;
	supl.su_upl = upl;
	supl.su_pl = pl;
	supl.su_vaddr = 0;
	supl.su_refcount = 1;		/* prevent it from being freed in sharedupl_put */
	supl.su_err = 0;
	mutex_init(&supl.su_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_enter(&zp->z_upltree_lock);
	avl_add(&zp->z_upltree, &supl);
	mutex_exit(&zp->z_upltree_lock);

	error = zfs_cluster_push_now(vp, zfsvfs->z_os, zp->z_id, upl, pl, off, 0/*upl_offset*/, len, flags, max_blksz, NULL/*tx*/);

out:
	debug_msg("%s:%d upl=%p", __func__, __LINE__, upl);
	zfs_range_unlock(rl);

	/* we want to push the dirty pages out since VM wants free pages when calling vnop_pageout */
	zil_commit(zfsvfs->z_log, UINT64_MAX, zp->z_id);

	SInt32 old_ref_count = OSDecrementAtomic(&supl.su_refcount);
	ASSERT(old_ref_count == 1);	/* I must be the only owner */
	mutex_enter(&zp->z_upltree_lock);
	avl_remove(&zp->z_upltree, &supl);
	mutex_exit(&zp->z_upltree_lock);

	if (supl.su_vaddr) {
		ubc_upl_unmap(supl.su_upl);
	}
	mutex_destroy(&supl.su_lock);
	debug_msg("%s:%d upl=%p", __func__, __LINE__, upl);
	ubc_upl_commit_range(upl, 0, upl_size, UPL_COMMIT_FREE_ON_EMPTY);

	ZFS_EXIT(zfsvfs);
	return (error);

exit_abort:
	VERIFY(ubc_create_upl(vp, off, len, &upl, &pl, uplflags) == 0);
	ubc_upl_abort(upl, UPL_ABORT_FREE_ON_EMPTY);
	if (zfsvfs)
		ZFS_EXIT(zfsvfs);
	return (error);
}

static int
zfs_vnop_inactive(struct vnop_inactive_args *ap)
{
	vnode_t  *vp = ap->a_vp;

	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	znode_phys_t  *pzp = zp->z_phys;

	rw_enter(&zfsvfs->z_teardown_inactive_lock, RW_READER);

#ifdef ZFS_DEBUG
	znode_stalker(zp, N_vnop_inactive);
#endif
	/* If we're force unmounting, go to reclaim */
	if (zfsvfs->z_unmounted) {
		rw_exit(&zfsvfs->z_teardown_inactive_lock);
		return (0);
	}

	/*
	 * Destroy the on-disk znode and flag the vnode to be recycled. 
	 * If this was a directory then zfs_link_destroy will have set 
	 * zp_links = 0
	 */
	if (pzp->zp_links == 0) {
		vnode_recycle(vp);
	}

	rw_exit(&zfsvfs->z_teardown_inactive_lock);
	return (0);
}

static int
zfs_vnop_reclaim(struct vnop_reclaim_args *ap)
{
	vnode_t  *vp = ap->a_vp;

	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;

	rw_enter(&zfsvfs->z_teardown_inactive_lock, RW_READER);

#ifdef ZFS_DEBUG
	znode_stalker(zp, N_vnop_reclaim);
#endif

     	mutex_enter(&zp->z_lock);
	if (zp->z_dbuf && vfs_isforce(zfsvfs->z_vfs)) {
		/*
		 * A forced unmount relclaim prior to zfs_unmount().
		 * Relinquish the vnode back to VFS and let
		 * zfsvfs_teardown() deal with the znode.
		 */
		zp->z_vnode = NULL;
		zp->z_vid = 0;
		mutex_exit(&zp->z_lock);
	} else {
		mutex_exit(&zp->z_lock);
		zfs_zinactive(zp);
	}

	/* Mark the vnode as not used and NULL out the vp's data*/
	vnode_removefsref(vp);
	vnode_clearfsnode(vp);
	rw_exit(&zfsvfs->z_teardown_inactive_lock);
	return (0);
}

static int
zfs_vnop_mmap(struct vnop_mmap_args *ap)
{
	vnode_t *vp = ap->a_vp;

	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(zp);

	if ( !vnode_isreg(vp) ) {
		ZFS_EXIT(zfsvfs);
		return (ENODEV);
	}

	rw_enter(&zp->z_map_lock, RW_WRITER);
	if (ISSET(ap->a_fflags, VM_PROT_WRITE))
		zp->z_mmapped_for_write = TRUE;
	rw_exit(&zp->z_map_lock);

	ZFS_EXIT(zfsvfs);
	return (0);
}

static int
zfs_vnop_mknod(struct vnop_mknod_args *ap)
{
	struct vnode_attr  *vap = ap->a_vap;
	int error;

	switch(vap->va_type) {
	case VSOCK:
	case VFIFO:
	case VBLK:
	case VCHR:
		error = zfs_vnop_create((struct vnop_create_args *)ap);
		break;
	default:
		error = EINVAL;
	}
	return (error);
}

static int
zfs_vnop_allocate(struct vnop_allocate_args *ap)
{
	vnode_t *vp = ap->a_vp;
	off_t length = ap->a_length;
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	int err;

        ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(zp);

	/* Sanity checks */
	if (!vnode_isreg(vp)) {
		ZFS_EXIT(zfsvfs);
		return (EISDIR);
	}
	if (length < (off_t)0) {
		ZFS_EXIT(zfsvfs);
		return (EINVAL);
	}

	err = dmu_allocate_check(zfsvfs->z_os, length);

	/*
	 * XXX If space is available, set bytesallocated to size requested.
	 * This is place holder code for when we do a more complete 
	 * preallocate solution later.
	 */
	if(!err)
		*(ap->a_bytesallocated) += length;
	ZFS_EXIT(zfsvfs);
	return (err);
}


static int 
zfs_vnop_whiteout(struct vnop_whiteout_args *ap)
{
	vnode_t *vp = NULLVP;
	int error = 0;

	switch (ap->a_flags) {
		case LOOKUP: {
			error = 0;
			break;
		}
		case CREATE: {
			struct vnop_mknod_args mknod_args;
			struct vnode_attr va;

			VATTR_INIT(&va);
			VATTR_SET(&va, va_type, VREG);
			VATTR_SET(&va, va_mode, S_IFWHT);
			VATTR_SET(&va, va_uid, 0);
			VATTR_SET(&va, va_gid, 0);

			mknod_args.a_desc = &vnop_mknod_desc;
			mknod_args.a_dvp = ap->a_dvp;
			mknod_args.a_vpp = &vp;
			mknod_args.a_cnp = ap->a_cnp;
			mknod_args.a_vap = &va;
			mknod_args.a_context = ap->a_context;

			error = zfs_vnop_mknod(&mknod_args);
			/*
			 * No need to release the vnode since
			 * a vnode isn't created for whiteouts.
			 */
			break;
		}
		case DELETE: {
			struct vnop_remove_args remove_args;
			struct vnop_lookup_args lookup_args;

			lookup_args.a_dvp = ap->a_dvp;
			lookup_args.a_vpp = &vp;
			lookup_args.a_cnp = ap->a_cnp;
			lookup_args.a_context = ap->a_context;

			error = zfs_vnop_lookup(&lookup_args);
			if (error) {
				break;
			}

			remove_args.a_dvp = ap->a_dvp;
			remove_args.a_vp = vp;
			remove_args.a_cnp = ap->a_cnp;
			remove_args.a_flags = 0;
			remove_args.a_context = ap->a_context;

			error = zfs_vnop_remove(&remove_args);
			vnode_put(vp);
			break;
		}

		default:
			error = EINVAL;
	}

	return (error);
}

static int
zfs_vnop_pathconf(struct vnop_pathconf_args *ap)
{
	int32_t  *valp = ap->a_retval;

	switch (ap->a_name) {
	case _PC_LINK_MAX:
		*valp = INT_MAX;
		break;

	case _PC_PIPE_BUF:
		*valp = PIPE_BUF;
		break;

	case _PC_CHOWN_RESTRICTED:
		*valp = 200112;  /* POSIX */
		break;

	case _PC_NO_TRUNC:
		*valp = 200112;  /* POSIX */
		break;

	case _PC_NAME_MAX:
	case _PC_NAME_CHARS_MAX:
		*valp = ZAP_MAXNAMELEN - 1;  /* 255 */
		break;

	case _PC_PATH_MAX:
	case _PC_SYMLINK_MAX:
		*valp = PATH_MAX;  /* 1024 */
		break;

	case _PC_CASE_SENSITIVE: {
		znode_t  *zp = VTOZ(ap->a_vp);
		zfsvfs_t  *zfsvfs = zp->z_zfsvfs;

		*valp = (zfsvfs->z_case == ZFS_CASE_INSENSITIVE) ? 0 : 1;
		break;
	}
	case _PC_CASE_PRESERVING:
		*valp = 1;
		break;

	case _PC_FILESIZEBITS:
		*valp = 64;
		break;

	default:
		return (EINVAL);
	}
	return (0);
}

/*
 * Retrieve the data of an extended attribute.
 */
static int
zfs_vnop_getxattr(struct vnop_getxattr_args *ap)
{
	vnode_t  *vp = ap->a_vp;
	vnode_t  *xdvp = NULLVP;
	vnode_t  *xvp = NULLVP;
	znode_t  *zp = VTOZ(vp);
	znode_phys_t *pzp;
	zfsvfs_t  *zfsvfs = zp->z_zfsvfs;
	uio_t  uio = ap->a_uio;
	cred_t  *cr = (cred_t *)vfs_context_ucred(ap->a_context);
	char * name = (char *)ap->a_name;
	boolean_t locked;
	int flags;
	int  error;

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(zp);
	pzp = zp->z_phys;

	mutex_enter(&zp->z_lock);
	locked = B_TRUE;

	/*
	 * Recursive attributes are not allowed.
	 */
	if (pzp->zp_flags & ZFS_XATTR) {
		error = EINVAL;
		goto out;
	}

	/*
	 * First check if we have embedded Finder Info.
	 */
	if ((strcmp(name, XATTR_FINDERINFO_NAME) == 0) &&
	    (vnode_isdir(vp) || vnode_isreg(vp)) &&
	    (pzp->zp_flags & ZFS_BONUS_FINDERINFO)) {
		size_t len;
		dmu_object_info_t doi;

		if (uio == NULL) {
			*ap->a_size = sizeof (finderinfo_t);
			error = 0;
			goto out;
		} else if ((user_size_t)uio_resid(uio) < sizeof (finderinfo_t)) {
			error = ERANGE;
			goto out;
		}

		/*
		 * Only VREG/VDIR objects have embedded Finder Info, so
		 * we won't conflict with symlinks in the bonus buffer.
		 */
		dmu_object_info_from_db(zp->z_dbuf, &doi);
		len = sizeof (finderinfo_t) + sizeof (znode_phys_t);
		if (len <= doi.doi_bonus_size) {
			/*
			 * pzp points to the start of the
			 * znode_phys_t. pzp + 1 points to the
			 * first byte after the znode_phys_t.
			 */
			error = uio_move((caddr_t)(pzp + 1),
			                 sizeof (finderinfo_t), UIO_READ, uio);
			goto out;
		}
	}

	if (pzp->zp_xattr == 0) {
		error = ENOATTR;
		goto out;
	}
	mutex_exit(&zp->z_lock);
	locked = B_FALSE;

	/* Grab the hidden attribute directory vnode. */
	if ( (error = zfs_get_xattrdir(zp, &xdvp, cr, 0)) ) {
		goto out;
	}

	flags = ZFS_IGNORECASE(zfsvfs) ? FIGNORECASE : 0;

	/* Lookup the attribute name. */
	error = zfs_dirlook(VTOZ(xdvp), name, &xvp, flags, NULL);
	if (error) {
		if (error == ENOENT)
			error = ENOATTR;
		goto out;
	}

	/* Read the attribute data. */
	if (uio == NULL) {
		znode_t  *xzp = VTOZ(xvp);

		mutex_enter(&xzp->z_lock);
		*ap->a_size = (size_t)xzp->z_phys->zp_size;
		mutex_exit(&xzp->z_lock);
	} else {
		error = VNOP_READ(xvp, uio, 0, ap->a_context);
	}
out:
	if (locked)
		mutex_exit(&zp->z_lock);

	if (xvp) {
		vnode_put(xvp);
	}
	if (xdvp) {
		vnode_put(xdvp);
	}
	ZFS_EXIT(zfsvfs);

	return (error);
}

/*
 * Lookup/Create an extended attribute entry.
 *
 * Input arguments:
 *	dzp	- znode for hidden attribute directory
 *	name	- name of attribute
 *	flag	- ZNEW: if the entry already exists, fail with EEXIST.
 *		  ZEXISTS: if the entry does not exist, fail with ENOENT.
 *
 * Output arguments:
 *	vpp	- pointer to the vnode for the entry (NULL if there isn't one)
 *
 * Return value: 0 on success or errno value on failure.
 */
int
zfs_obtain_xattr(znode_t *dzp, const char *name, mode_t mode, cred_t *cr,
                 vnode_t **vpp, int flag)
{
	znode_t  *xzp = NULL;
	zfsvfs_t  *zfsvfs = dzp->z_zfsvfs;
	zilog_t  *zilog = zfsvfs->z_log;
	zfs_dirlock_t  *dl;
	dmu_tx_t  *tx;
	uint64_t txtype;
	struct vnode_attr  vattr;
	int error;

	if (ZFS_IGNORECASE(zfsvfs))
		flag |= ZCILOOK;
top:
	/* Lock the attribute entry name. */
	error = zfs_dirent_lock(&dl, dzp, (char *)name, &xzp, flag, NULL);
	if (error) {
		goto out;
	}
	/* If the name already exists, we're done. */
	if (xzp != NULL) {
		zfs_dirent_unlock(dl);
		goto out;
	}
	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_bonus(tx, DMU_NEW_OBJECT);
	dmu_tx_hold_bonus(tx, dzp->z_id);
	dmu_tx_hold_zap(tx, dzp->z_id, TRUE, (char *)name);
	if (dzp->z_phys->zp_flags & ZFS_INHERIT_ACE) {
		dmu_tx_hold_write(tx, DMU_NEW_OBJECT, 0, SPA_MAXBLOCKSIZE);
	}
	error = dmu_tx_assign(tx, zfsvfs->z_assign);
	if (error) {
		zfs_dirent_unlock(dl);
		if ((error == ERESTART) && (zfsvfs->z_assign == TXG_NOWAIT)) {
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		dmu_tx_abort(tx);
		goto out;
	}

	VATTR_INIT(&vattr);
	VATTR_SET(&vattr, va_type, VREG);
	VATTR_SET(&vattr, va_mode, mode & ~S_IFMT);
	zfs_mknode(dzp, &vattr, tx, cr, 0, &xzp, 0, NULL, NULL);

	(void) zfs_link_create(dl, xzp, tx, ZNEW);

	txtype = TX_CREATE;
	if (ZFS_IGNORECASE(zfsvfs))
		txtype |= TX_CI;
	zfs_log_create(zilog, tx, txtype, dzp, xzp, (char *)name, NULL, NULL, &vattr);

	dmu_tx_commit(tx);

	/*
	 * OS X - attach the vnode _after_ committing the transaction
	 */
	if ((error = zfs_attach_vnode(xzp)) != 0) {
		zfs_zinactive(xzp);
		xzp = NULL;
	}

	zfs_dirent_unlock(dl);
out:
	if (error == EEXIST)
		error = ENOATTR;
		
	*vpp = xzp ? ZTOV(xzp) : NULL;

	return (error);
}

/*
 * Set the data of an extended attribute.
 */
static int
zfs_vnop_setxattr(struct vnop_setxattr_args *ap)
{
	vnode_t  *vp = ap->a_vp;
	vnode_t  *xdvp = NULLVP;
	vnode_t  *xvp = NULLVP;
	znode_t  *zp = VTOZ(vp);
	znode_phys_t *pzp;
	zfsvfs_t  *zfsvfs = zp->z_zfsvfs;
	char * name = (char *)ap->a_name;
	uio_t  uio = ap->a_uio;
	cred_t  *cr = (cred_t *)vfs_context_ucred(ap->a_context);
	int  flag;
	int  error;

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(zp);
	pzp = zp->z_phys;

	/*
	 * Recursive attributes are not allowed.
	 */
	if (pzp->zp_flags & ZFS_XATTR) {
		error = EINVAL;
		goto out;
	}

	if (strlen(ap->a_name) >= ZAP_MAXNAMELEN) {
		error = ENAMETOOLONG;
		goto out;
	}

	if (zfsvfs->z_utf8 && u8_validate((char *)ap->a_name, strlen(ap->a_name),
	    NULL, U8_VALIDATE_ENTIRE, &error) < 0) {
		error = EILSEQ;
		goto out;
	}
top:
	/*
	 * Set embedded Finder Info if our ZPL version allows it
	 * and znode is a regular file or directory.
	 */
	if ((strcmp(name, XATTR_FINDERINFO_NAME) == 0) &&
	    (zfsvfs->z_version >= ZPL_VERSION_BONUS_FINDERINFO) &&
	    (pzp->zp_xattr == 0) &&
	    (vnode_isdir(vp) || vnode_isreg(vp))) {
		size_t len;
		dmu_object_info_t doi;
		dmu_tx_t *tx;

		/* Enforce setxattr option semantics */
		if (pzp->zp_flags & ZFS_BONUS_FINDERINFO) {
			/* attr exists and "create" was specified. */
			if (ap->a_options & XATTR_CREATE) {
				error = EEXIST;
				goto out;
			}
		} else /* empty */ {
			/* attr doesn't exists and "replace" was specified. */
			if (ap->a_options & XATTR_REPLACE) {
				error = ENOATTR;
				goto out;
			}
		}
		tx = dmu_tx_create(zfsvfs->z_os);
		dmu_tx_hold_bonus(tx, zp->z_id);

		if ((error = dmu_tx_assign(tx, zfsvfs->z_assign))) {
			if ((error == ERESTART) &&
			    (zfsvfs->z_assign == TXG_NOWAIT)) {
				dmu_tx_wait(tx);
				dmu_tx_abort(tx);
				goto top;
			}
			dmu_tx_abort(tx);
			ZFS_EXIT(zfsvfs);
			return (error);
		}
		dmu_buf_will_dirty(zp->z_dbuf, tx);

		mutex_enter(&zp->z_lock);

		/* Grow the bonus buffer if necessary. */
		dmu_object_info_from_db(zp->z_dbuf, &doi);
		len = sizeof (finderinfo_t) + sizeof (znode_phys_t);
		if ((len <= doi.doi_bonus_size) ||
		    (dmu_set_bonus(zp->z_dbuf, len, tx) == 0)) {

			error = uio_move((caddr_t)(pzp + 1),
			                 sizeof (finderinfo_t), UIO_WRITE, uio);

			pzp->zp_flags |= ZFS_BONUS_FINDERINFO;

			mutex_exit(&zp->z_lock);
			dmu_tx_commit(tx);

			ZFS_EXIT(zfsvfs);
			return (error);
		}
		/* Fall back to using an extended atribute */
		mutex_exit(&zp->z_lock);
		dmu_tx_commit(tx);
	}

	/* Grab the hidden attribute directory vnode. */
	if ( (error = zfs_get_xattrdir(zp, &xdvp, cr, CREATE_XATTR_DIR)) ) {
		goto out;
	}

	/* Enforce setxattr option semantics */
	if (ap->a_options & XATTR_CREATE)
		flag = ZNEW;     /* expect no pre-existing entry */
	else if (ap->a_options & XATTR_REPLACE)
		flag = ZEXISTS;  /* expect an existing entry */
	else
		flag = 0;

	/* Lookup or create the named attribute. */
	error = zfs_obtain_xattr(VTOZ(xdvp), ap->a_name,
	                         VTOZ(vp)->z_phys->zp_mode, cr, &xvp, flag);
	if (error)
		goto out;

	/* Write the attribute data. */
	ASSERT(uio != NULL);
	error = VNOP_WRITE(xvp, uio, 0, ap->a_context);

out:
	if (xdvp) {
		vnode_put(xdvp);
	}
	if (xvp) {
		vnode_put(xvp);
	}

	ZFS_EXIT(zfsvfs);
	return (error);
}

/*
 * Remove an extended attribute.
 */
static int
zfs_vnop_removexattr(struct vnop_removexattr_args *ap)
{
	vnode_t  *vp = ap->a_vp;
	vnode_t  *xdvp = NULLVP;
	vnode_t  *xvp = NULLVP;
	znode_t  *zp = VTOZ(vp);
	znode_phys_t *pzp;
	zfsvfs_t  *zfsvfs = zp->z_zfsvfs;
	char * name = (char *)ap->a_name;
	cred_t  *cr = (cred_t *)vfs_context_ucred(ap->a_context);
	struct vnop_remove_args  args;
	struct componentname  cn;
	int flags;
	int  error;

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(zp);
	pzp = zp->z_phys;

	/*
	 * Recursive attributes are not allowed.
	 */
	if (pzp->zp_flags & ZFS_XATTR) {
		error = EINVAL;
		goto out;
	}

	/*
	 * First check if we have embedded Finder Info.
	 */
top:
	if ((strcmp(name, XATTR_FINDERINFO_NAME) == 0) &&
	    (vnode_isdir(vp) || vnode_isreg(vp)) &&
	    (pzp->zp_flags & ZFS_BONUS_FINDERINFO)) {
		size_t len;
		dmu_object_info_t doi;
		dmu_tx_t *tx;

		tx = dmu_tx_create(zfsvfs->z_os);
		dmu_tx_hold_bonus(tx, zp->z_id);

		if ((error = dmu_tx_assign(tx, zfsvfs->z_assign))) {
			if ((error == ERESTART) &&
			    (zfsvfs->z_assign == TXG_NOWAIT)) {
				dmu_tx_wait(tx);
				dmu_tx_abort(tx);
				goto top;
			}
			dmu_tx_abort(tx);
			ZFS_EXIT(zfsvfs);
			return (error);
		}
		dmu_buf_will_dirty(zp->z_dbuf, tx);

		mutex_enter(&zp->z_lock);

		/* Shrink the bonus buffer size */
		dmu_object_info_from_db(zp->z_dbuf, &doi);
		len = doi.doi_bonus_size - sizeof (finderinfo_t);
		(void) dmu_set_bonus(zp->z_dbuf, len, tx);

		pzp->zp_flags &= ~ZFS_BONUS_FINDERINFO;

		mutex_exit(&zp->z_lock);
		dmu_tx_commit(tx);

		ZFS_EXIT(zfsvfs);
		return (error);
	}

	if (pzp->zp_xattr == 0) {
		error = ENOATTR;
		goto out;
	}

	/* Grab the hidden attribute directory vnode. */
	if ( (error = zfs_get_xattrdir(zp, &xdvp, cr, 0)) ) {
		goto out;
	}

	flags = ZFS_IGNORECASE(zfsvfs) ? FIGNORECASE : 0;

	/* Lookup the attribute name. */
	error = zfs_dirlook(VTOZ(xdvp), name, &xvp, flags, NULL);
	if (error) {
		if (error == ENOENT)
			error = ENOATTR;
		goto out;
	}

	bzero(&cn, sizeof (cn));
	cn.cn_nameiop = DELETE;
	cn.cn_flags = ISLASTCN;
	cn.cn_nameptr = name;
	cn.cn_namelen = strlen(cn.cn_nameptr);

	args.a_desc = &vnop_remove_desc;
	args.a_dvp = xdvp;
	args.a_vp = xvp;
	args.a_cnp = &cn;
	args.a_flags = 0;
	args.a_context = ap->a_context;

	error = zfs_vnop_remove(&args);

out:
	if (xvp) {
		vnode_put(xvp);
	}
	if (xdvp) {
		vnode_put(xdvp);
	}
	ZFS_EXIT(zfsvfs);

	return (error);
}

/*
 * Generate a list of extended attribute names.
 */
static int
zfs_vnop_listxattr(struct vnop_listxattr_args *ap)
{
	vnode_t  *vp = ap->a_vp;
	vnode_t  *xdvp = NULLVP;
	znode_t  *zp = VTOZ(vp);
	znode_phys_t *pzp;
	zfsvfs_t  *zfsvfs = zp->z_zfsvfs;
	uio_t  uio = ap->a_uio;
	cred_t  *cr = (cred_t *)vfs_context_ucred(ap->a_context);
	zap_cursor_t  zc;
	zap_attribute_t  za;
	objset_t  *os;
	size_t size = 0;
	char  *nameptr;
	char  nfd_name[ZAP_MAXNAMELEN];
	size_t  namelen;
	int  error = 0;

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(zp);
	pzp = zp->z_phys;

	/*
	 * Recursive attributes are not allowed.
	 */
	if (pzp->zp_flags & ZFS_XATTR) {
		error = EINVAL;
		goto out;
	}

	/* If we have embedded Finder Info then export it's name. */
	if ((vnode_isdir(vp) || vnode_isreg(vp)) &&
	    (pzp->zp_flags & ZFS_BONUS_FINDERINFO)) {
		if (uio == NULL) {
			size += sizeof(XATTR_FINDERINFO_NAME);
		} else if ((user_size_t)uio_resid(uio) <
		           sizeof(XATTR_FINDERINFO_NAME)) {
			error = ERANGE;
			goto out;
		} else {
			error = uiomove(XATTR_FINDERINFO_NAME,
			                  sizeof(XATTR_FINDERINFO_NAME), uio);
			if (error)
				goto out;
		}
	}

	/* Do we even have any attributes? */
	if (pzp->zp_xattr == 0) {
		goto out;  /* all done */
	}
	/* Grab the hidden attribute directory vnode. */
	if (zfs_get_xattrdir(zp, &xdvp, cr, 0) != 0) {
		goto out;
	}
	os = zfsvfs->z_os;

	for (zap_cursor_init(&zc, os, VTOZ(xdvp)->z_id);
	     zap_cursor_retrieve(&zc, &za) == 0;
	     zap_cursor_advance(&zc)) {

		if (xattr_protected(za.za_name))
			continue;     /* skip */

		/*
		 * Mac OS X: non-ascii names are UTF-8 NFC on disk 
		 * so convert to NFD before exporting them.
		 */
		namelen = strlen(za.za_name);
		if (!is_ascii_str(za.za_name) &&
		    utf8_normalizestr((const u_int8_t *)za.za_name, namelen,
				      (u_int8_t *)nfd_name, &namelen,
				      sizeof (nfd_name), UTF_DECOMPOSED) == 0) {
			nameptr = nfd_name;
		} else {
			nameptr = &za.za_name[0];
		}

		++namelen;  /* account for NULL termination byte */
		if (uio == NULL) {
			size += namelen;
		} else {
			if (namelen > uio_resid(uio)) {
				error = ERANGE;
				break;
			}
			error = uiomove((caddr_t)nameptr, namelen, uio);
			if (error) {
				break;
			}
		}
	}
	zap_cursor_fini(&zc);
out:
	if (uio == NULL) {
		*ap->a_size = size;
	}
	if (xdvp) {
		vnode_put(xdvp);
	}
	ZFS_EXIT(zfsvfs);

	return (error);
}

/*
 * Obtain the vnode for a stream.
 */
static int
zfs_vnop_getnamedstream(struct vnop_getnamedstream_args* ap)
{
	vnode_t  *vp = ap->a_vp;
	vnode_t  **svpp = ap->a_svpp;
	vnode_t  *xdvp = NULLVP;
	znode_t  *zp = VTOZ(vp);
	zfsvfs_t  *zfsvfs = zp->z_zfsvfs;
	cred_t  *cr = (cred_t *)vfs_context_ucred(ap->a_context);
	int flags;
	int  error = ENOATTR;

	*svpp = NULLVP;
	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(zp);

	/*
	 * Mac OS X only supports the "com.apple.ResourceFork" stream.
	 */
	if (bcmp(ap->a_name, XATTR_RESOURCEFORK_NAME, sizeof(XATTR_RESOURCEFORK_NAME)) != 0 ||
	    zp->z_phys->zp_xattr == 0) {
		goto out;
	}

	/* Grab the hidden attribute directory vnode. */
	if (zfs_get_xattrdir(zp, &xdvp, cr, 0) != 0) {
		goto out;
	}

	flags = ZFS_IGNORECASE(zfsvfs) ? FIGNORECASE : 0;

	/* Lookup the attribute name. */
	error = zfs_dirlook(VTOZ(xdvp), (char *)ap->a_name, svpp, flags, NULL);
	if (error) {
		if (error == ENOENT)
			error = ENOATTR;
	}
out:
	if (xdvp) {
		vnode_put(xdvp);
	}
	ZFS_EXIT(zfsvfs);

	return (error);
}

/*
 * Create a stream.
 */
static int
zfs_vnop_makenamedstream(struct vnop_makenamedstream_args* ap)
{
	vnode_t  *vp = ap->a_vp;
	vnode_t  *xdvp = NULLVP;
	znode_t  *zp = VTOZ(vp);
	zfsvfs_t  *zfsvfs = zp->z_zfsvfs;
	cred_t  *cr = (cred_t *)vfs_context_ucred(ap->a_context);
	struct componentname  cn;
	struct vnode_attr  vattr;
	struct vnop_create_args  args;
	int  error = 0;

	*ap->a_svpp = NULLVP;
	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(zp);

	/* Only regular files can have a resource fork stream. */
	if ( !vnode_isreg(vp) ) {
		error = EPERM;
		goto out;
	}

	/*
	 * Mac OS X only supports the "com.apple.ResourceFork" stream.
	 */
	if (bcmp(ap->a_name, XATTR_RESOURCEFORK_NAME, sizeof(XATTR_RESOURCEFORK_NAME)) != 0) {
		error = ENOATTR;
		goto out;
	}

	/* Grab the hidden attribute directory vnode. */
	if ( (error = zfs_get_xattrdir(zp, &xdvp, cr, CREATE_XATTR_DIR)) ) {
		goto out;
	}

	bzero(&cn, sizeof (cn));
	cn.cn_nameiop = CREATE;
	cn.cn_flags = ISLASTCN;
	cn.cn_nameptr = (char *)ap->a_name;
	cn.cn_namelen = strlen(cn.cn_nameptr);

	VATTR_INIT(&vattr);
	VATTR_SET(&vattr, va_type, VREG);
	VATTR_SET(&vattr, va_mode, VTOZ(vp)->z_phys->zp_mode & ~S_IFMT);

	args.a_desc = &vnop_create_desc;
	args.a_dvp = xdvp;
	args.a_vpp = ap->a_svpp;
	args.a_cnp = &cn;
	args.a_vap = &vattr;
	args.a_context = ap->a_context;

	error = zfs_vnop_create(&args);
out:
	if (xdvp) {
		vnode_put(xdvp);
	}
	ZFS_EXIT(zfsvfs);

	return (error);
}

/*
 * Remove a stream.
 */
static int
zfs_vnop_removenamedstream(struct vnop_removenamedstream_args* ap)
{
	vnode_t *svp = ap->a_svp;
	znode_t  *zp = VTOZ(svp);
	zfsvfs_t  *zfsvfs = zp->z_zfsvfs;
	int error = 0;

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(zp);

	/*
	 * Mac OS X only supports the "com.apple.ResourceFork" stream.
	 */
	if (bcmp(ap->a_name, XATTR_RESOURCEFORK_NAME, sizeof(XATTR_RESOURCEFORK_NAME)) != 0) {
		error = ENOATTR;
		goto out;
	}

	/* ### MISING CODE ### */
	printf("zfs_vnop_removenamedstream\n");
	error = EPERM;
out:
	ZFS_EXIT(zfsvfs);

	return (error);
}

static int
zfs_vnop_revoke(struct vnop_revoke_args *ap)
{
	return vn_revoke(ap->a_vp, ap->a_flags, ap->a_context);
}

static int
zfs_vnop_blktooff(__unused struct vnop_blktooff_args *ap)
{
	return (ENOTSUP);
}

static int
zfs_vnop_offtoblk(__unused struct vnop_offtoblk_args *ap)
{
	return (ENOTSUP);
}

static int
zfs_vnop_blockmap(__unused struct vnop_blockmap_args *ap)
{
	return (ENOTSUP);
}

static int
zfs_vnop_strategy(__unused struct vnop_strategy_args *ap)
{
	return (ENOTSUP);
}

static int
zfs_vnop_select(__unused struct vnop_select_args *ap)
{
	return (1);
}

static int
zfs_inval(__unused void *ap)
{
	return (EINVAL);
}

static int
zfs_isdir(__unused void *ap)
{
	return (EISDIR);
}

#define VOPFUNC int (*)(void *)

extern int zfs_vnop_readdirattr(struct vnop_readdirattr_args *ap);
extern int zfs_vnop_exchange(struct vnop_exchange_args *ap);

/*
 * Directory vnode operations template
 */
int (**zfs_dvnodeops) (void *);
struct vnodeopv_entry_desc zfs_dvnodeops_template[] = {
	{&vnop_default_desc, 	(VOPFUNC)vn_default_error },
	{&vnop_lookup_desc,	(VOPFUNC)zfs_vnop_lookup},
	{&vnop_create_desc,	(VOPFUNC)zfs_vnop_create},
	{&vnop_whiteout_desc,	(VOPFUNC)zfs_vnop_whiteout},
	{&vnop_mknod_desc,	(VOPFUNC)zfs_vnop_mknod},
	{&vnop_open_desc,	(VOPFUNC)zfs_vnop_open},
	{&vnop_close_desc,	(VOPFUNC)zfs_vnop_close},
	{&vnop_access_desc,	(VOPFUNC)zfs_vnop_access},
	{&vnop_getattr_desc,	(VOPFUNC)zfs_vnop_getattr},
	{&vnop_setattr_desc,	(VOPFUNC)zfs_vnop_setattr},
	{&vnop_read_desc,	(VOPFUNC)zfs_isdir},
	{&vnop_write_desc,	(VOPFUNC)zfs_isdir},
	{&vnop_ioctl_desc,	(VOPFUNC)zfs_vnop_ioctl},
	{&vnop_select_desc,	(VOPFUNC)zfs_isdir},
	{&vnop_fsync_desc,	(VOPFUNC)zfs_vnop_fsync},
	{&vnop_remove_desc,	(VOPFUNC)zfs_vnop_remove},
	{&vnop_link_desc,	(VOPFUNC)zfs_vnop_link},
	{&vnop_rename_desc,	(VOPFUNC)zfs_vnop_rename},
	{&vnop_mkdir_desc,	(VOPFUNC)zfs_vnop_mkdir},
	{&vnop_rmdir_desc,	(VOPFUNC)zfs_vnop_rmdir},
	{&vnop_symlink_desc,	(VOPFUNC)zfs_vnop_symlink},
	{&vnop_readdir_desc,	(VOPFUNC)zfs_vnop_readdir},
	{&vnop_inactive_desc,	(VOPFUNC)zfs_vnop_inactive},
	{&vnop_reclaim_desc,	(VOPFUNC)zfs_vnop_reclaim},
	{&vnop_pathconf_desc,	(VOPFUNC)zfs_vnop_pathconf},
	{&vnop_revoke_desc,	(VOPFUNC)zfs_vnop_revoke},
	{&vnop_getxattr_desc,	(VOPFUNC)zfs_vnop_getxattr},
	{&vnop_setxattr_desc,	(VOPFUNC)zfs_vnop_setxattr},
	{&vnop_removexattr_desc,(VOPFUNC)zfs_vnop_removexattr},
	{&vnop_listxattr_desc,	(VOPFUNC)zfs_vnop_listxattr},
	{&vnop_readdirattr_desc, (VOPFUNC)zfs_vnop_readdirattr},
	{NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc zfs_dvnodeop_opv_desc =
{ &zfs_dvnodeops, zfs_dvnodeops_template };


/*
 * Regular file vnode operations template
 */
int (**zfs_fvnodeops) (void *);
struct vnodeopv_entry_desc zfs_fvnodeops_template[] = {
	{&vnop_default_desc, 	(VOPFUNC)vn_default_error },
	{&vnop_whiteout_desc,	(VOPFUNC)zfs_vnop_whiteout},
	{&vnop_open_desc,	(VOPFUNC)zfs_vnop_open},
	{&vnop_close_desc,	(VOPFUNC)zfs_vnop_close},
	{&vnop_access_desc,	(VOPFUNC)zfs_vnop_access},
	{&vnop_getattr_desc,	(VOPFUNC)zfs_vnop_getattr},
	{&vnop_setattr_desc,	(VOPFUNC)zfs_vnop_setattr},
	{&vnop_read_desc,	(VOPFUNC)zfs_vnop_read},
	{&vnop_write_desc,	(VOPFUNC)zfs_vnop_write},
	{&vnop_ioctl_desc,	(VOPFUNC)zfs_vnop_ioctl},
	{&vnop_select_desc,	(VOPFUNC)zfs_vnop_select},
	{&vnop_fsync_desc,	(VOPFUNC)zfs_vnop_fsync},
	{&vnop_inactive_desc,	(VOPFUNC)zfs_vnop_inactive},
	{&vnop_reclaim_desc,	(VOPFUNC)zfs_vnop_reclaim},
	{&vnop_pathconf_desc,	(VOPFUNC)zfs_vnop_pathconf},
	{&vnop_pagein_desc,	(VOPFUNC)zfs_vnop_pagein},
	{&vnop_pageout_desc,	(VOPFUNC)zfs_vnop_pageout},
	{&vnop_mmap_desc,	(VOPFUNC)zfs_vnop_mmap},
	{&vnop_blktooff_desc,	(VOPFUNC)zfs_vnop_blktooff},
	{&vnop_offtoblk_desc,	(VOPFUNC)zfs_vnop_offtoblk},
	{&vnop_blockmap_desc,	(VOPFUNC)zfs_vnop_blockmap},
	{&vnop_strategy_desc,	(VOPFUNC)zfs_vnop_strategy},
	{&vnop_allocate_desc,   (VOPFUNC)zfs_vnop_allocate},
	{&vnop_revoke_desc,	(VOPFUNC)zfs_vnop_revoke},
	{&vnop_exchange_desc,	(VOPFUNC)zfs_vnop_exchange},
	{&vnop_getxattr_desc,	(VOPFUNC)zfs_vnop_getxattr},
	{&vnop_setxattr_desc,	(VOPFUNC)zfs_vnop_setxattr},
	{&vnop_removexattr_desc,(VOPFUNC)zfs_vnop_removexattr},
	{&vnop_listxattr_desc,	(VOPFUNC)zfs_vnop_listxattr},
	{&vnop_getnamedstream_desc,	(VOPFUNC)zfs_vnop_getnamedstream},
	{&vnop_makenamedstream_desc,	(VOPFUNC)zfs_vnop_makenamedstream},
	{&vnop_removenamedstream_desc,	(VOPFUNC)zfs_vnop_removenamedstream},
	{NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc zfs_fvnodeop_opv_desc =
{ &zfs_fvnodeops, zfs_fvnodeops_template };


/*
 * Symbolic link vnode operations template
 */
int (**zfs_symvnodeops) (void *);
struct vnodeopv_entry_desc zfs_symvnodeops_template[] = {
	{&vnop_default_desc, 	(VOPFUNC)vn_default_error },
	{&vnop_open_desc,	(VOPFUNC)zfs_vnop_open},
	{&vnop_close_desc,	(VOPFUNC)zfs_vnop_close},
	{&vnop_access_desc,	(VOPFUNC)zfs_vnop_access},
	{&vnop_getattr_desc,	(VOPFUNC)zfs_vnop_getattr},
	{&vnop_setattr_desc,	(VOPFUNC)zfs_vnop_setattr},
	{&vnop_ioctl_desc,	(VOPFUNC)zfs_vnop_ioctl},
	{&vnop_readlink_desc,	(VOPFUNC)zfs_vnop_readlink},
	{&vnop_inactive_desc,	(VOPFUNC)zfs_vnop_inactive},
	{&vnop_reclaim_desc,	(VOPFUNC)zfs_vnop_reclaim},
	{&vnop_pathconf_desc,	(VOPFUNC)zfs_vnop_pathconf},
	{&vnop_revoke_desc,	(VOPFUNC)zfs_vnop_revoke},
	{&vnop_getxattr_desc,	(VOPFUNC)zfs_vnop_getxattr},
	{&vnop_setxattr_desc,	(VOPFUNC)zfs_vnop_setxattr},
	{&vnop_removexattr_desc,(VOPFUNC)zfs_vnop_removexattr},
	{&vnop_listxattr_desc,	(VOPFUNC)zfs_vnop_listxattr},
	{NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc zfs_symvnodeop_opv_desc =
{ &zfs_symvnodeops, zfs_symvnodeops_template };


/*
 * Extended attribute directory vnode operations template
 *	This template is similar to the directory vnodes
 *	operation template except for restricted operations:
 *		VNOP_MKDIR()
 *		VNOP_SYMLINK()
 *		VNOP_MKNOD()
 * Note that there are other restrictions embedded in:
 *	zfs_vnop_create() - restrict type to VREG
 *	zfs_vnop_link()   - no links into/out of attribute space
 *	zfs_vnop_rename() - no moves into/out of attribute space
 */
int (**zfs_xdvnodeops) (void *);
struct vnodeopv_entry_desc zfs_xdvnodeops_template[] = {
	{&vnop_default_desc, 	(VOPFUNC)vn_default_error },
	{&vnop_lookup_desc,	(VOPFUNC)zfs_vnop_lookup},
	{&vnop_create_desc,	(VOPFUNC)zfs_vnop_create},
	{&vnop_whiteout_desc,	(VOPFUNC)zfs_vnop_whiteout},
	{&vnop_mknod_desc,	(VOPFUNC)zfs_inval},
	{&vnop_open_desc,	(VOPFUNC)zfs_vnop_open},
	{&vnop_close_desc,	(VOPFUNC)zfs_vnop_close},
	{&vnop_access_desc,	(VOPFUNC)zfs_vnop_access},
	{&vnop_getattr_desc,	(VOPFUNC)zfs_vnop_getattr},
	{&vnop_setattr_desc,	(VOPFUNC)zfs_vnop_setattr},
	{&vnop_read_desc,	(VOPFUNC)zfs_vnop_read},
	{&vnop_write_desc,	(VOPFUNC)zfs_vnop_write},
	{&vnop_ioctl_desc,	(VOPFUNC)zfs_vnop_ioctl},
	{&vnop_select_desc,	(VOPFUNC)zfs_vnop_select},
	{&vnop_fsync_desc,	(VOPFUNC)zfs_vnop_fsync},
	{&vnop_remove_desc,	(VOPFUNC)zfs_vnop_remove},
	{&vnop_link_desc,	(VOPFUNC)zfs_vnop_link},
	{&vnop_rename_desc,	(VOPFUNC)zfs_vnop_rename},
	{&vnop_mkdir_desc,	(VOPFUNC)zfs_inval},
	{&vnop_rmdir_desc,	(VOPFUNC)zfs_vnop_rmdir},
	{&vnop_symlink_desc,	(VOPFUNC)zfs_inval},
	{&vnop_readdir_desc,	(VOPFUNC)zfs_vnop_readdir},
	{&vnop_inactive_desc,	(VOPFUNC)zfs_vnop_inactive},
	{&vnop_reclaim_desc,	(VOPFUNC)zfs_vnop_reclaim},
	{&vnop_pathconf_desc,	(VOPFUNC)zfs_vnop_pathconf},
	{NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc zfs_xdvnodeop_opv_desc =
{ &zfs_xdvnodeops, zfs_xdvnodeops_template };

/*
 * Error vnode operations template
 */
int (**zfs_evnodeops) (void *);
struct vnodeopv_entry_desc zfs_evnodeops_template[] = {
	{&vnop_default_desc, 	(VOPFUNC)vn_default_error },
	{&vnop_inactive_desc,	(VOPFUNC)zfs_vnop_inactive},
	{&vnop_reclaim_desc,	(VOPFUNC)zfs_vnop_reclaim},
	{&vnop_pathconf_desc,	(VOPFUNC)zfs_vnop_pathconf},
	{NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc zfs_evnodeop_opv_desc =
{ &zfs_evnodeops, zfs_evnodeops_template };

/* 
 * FIFO vnode operations template
 */
int (**zfs_fifoops) (void *);
struct vnodeopv_entry_desc zfs_fifoops_template[] = {
	{&vnop_default_desc, 	(VOPFUNC)vn_default_error},
	{&vnop_lookup_desc,	(VOPFUNC)fifo_lookup},
	{&vnop_open_desc,	(VOPFUNC)fifo_open},
	{&vnop_close_desc,	(VOPFUNC)fifo_close},
	{&vnop_read_desc,	(VOPFUNC)fifo_read},
	{&vnop_write_desc,	(VOPFUNC)fifo_write},
	{&vnop_ioctl_desc,	(VOPFUNC)fifo_ioctl},
	{&vnop_select_desc,	(VOPFUNC)fifo_select},
	{&vnop_revoke_desc,	(VOPFUNC)fifo_revoke},
	{&vnop_pathconf_desc,	(VOPFUNC)fifo_pathconf},
	{&vnop_fsync_desc,	(VOPFUNC)zfs_vnop_fsync},
	{&vnop_getattr_desc,	(VOPFUNC)zfs_vnop_getattr},
	{&vnop_setattr_desc,	(VOPFUNC)zfs_vnop_setattr},
	{&vnop_inactive_desc,	(VOPFUNC)zfs_vnop_inactive},
	{&vnop_reclaim_desc,	(VOPFUNC)zfs_vnop_reclaim},
	{&vnop_pagein_desc,	(VOPFUNC)zfs_vnop_pagein},
	{&vnop_pageout_desc,	(VOPFUNC)zfs_vnop_pageout},
	{NULL, 			(VOPFUNC)NULL}
};
struct vnodeopv_desc zfs_fifoop_opv_desc = 
{ &zfs_fifoops, zfs_fifoops_template };


/*
 * zfs VNOP glue (utilized during a zil replay)
 */

int 
ZFS_VNOP_CREATE(vnode_t *dvp, vnode_t **vpp, struct componentname *cnp,
    struct vnode_attr *vap, vfs_context_t ctx)
{
	struct vnop_create_args args;

	args.a_desc = &vnop_create_desc;
	args.a_dvp = dvp;
	args.a_vpp = vpp;
	args.a_cnp = cnp;
	args.a_vap = vap;
	args.a_context = ctx;

	return zfs_vnop_create(&args);
}

int 
ZFS_VNOP_REMOVE(vnode_t *dvp, vnode_t *vp, struct componentname *cnp,
    int flags, vfs_context_t ctx)
{
	struct vnop_remove_args args;

	args.a_desc = &vnop_remove_desc;
	args.a_dvp = dvp;
	args.a_vp = vp;
	args.a_cnp = cnp;
	args.a_flags = flags;
	args.a_context = ctx;

	return zfs_vnop_remove(&args);
}

int 
ZFS_VNOP_LINK(vnode_t *vp, vnode_t *tdvp, struct componentname *cnp,
    vfs_context_t ctx)
{
	struct vnop_link_args args;

	args.a_desc = &vnop_link_desc;
	args.a_vp = vp;
	args.a_tdvp = tdvp;
	args.a_cnp = cnp;
	args.a_context = ctx;

	return zfs_vnop_link(&args);
}

int
ZFS_VNOP_RENAME(vnode_t *fdvp, vnode_t *fvp, struct componentname *fcnp,
    vnode_t *tdvp, vnode_t *tvp, struct componentname *tcnp, vfs_context_t ctx)
{
	struct vnop_rename_args args;

	args.a_desc = &vnop_rename_desc;
	args.a_fdvp = fdvp;
	args.a_fvp = fvp;
	args.a_fcnp = fcnp;
	args.a_tdvp = tdvp;
	args.a_tvp = tvp;
	args.a_tcnp = tcnp;
	args.a_context = ctx;

	return zfs_vnop_rename(&args);
}

int
ZFS_VNOP_MKDIR(vnode_t *dvp, vnode_t **vpp, struct componentname *cnp,
    struct vnode_attr *vap, vfs_context_t ctx)
{
	struct vnop_mkdir_args args;

	args.a_desc = &vnop_mkdir_desc;
	args.a_dvp = dvp;
	args.a_vpp = vpp;
	args.a_cnp = cnp;
	args.a_vap = vap;
	args.a_context = ctx;

	return zfs_vnop_mkdir(&args);
}

int
ZFS_VNOP_RMDIR(vnode_t *dvp, vnode_t *vp, struct componentname *cnp,
    vfs_context_t ctx)
{
	struct vnop_rmdir_args args;

	args.a_desc = &vnop_rmdir_desc;
	args.a_dvp = dvp;
	args.a_vp = vp;
	args.a_cnp = cnp;
	args.a_context = ctx;

	return zfs_vnop_rmdir(&args);
}

int
ZFS_VNOP_SYMLINK(vnode_t *dvp, vnode_t **vpp, struct componentname *cnp,
    struct vnode_attr *vap, char *target, vfs_context_t ctx)
{
	struct vnop_symlink_args args;

	args.a_desc = &vnop_symlink_desc;
	args.a_dvp = dvp;
	args.a_vpp = vpp;
	args.a_cnp = cnp;
	args.a_vap = vap;
	args.a_target = target;
	args.a_context = ctx;

	return zfs_vnop_symlink(&args);
}

