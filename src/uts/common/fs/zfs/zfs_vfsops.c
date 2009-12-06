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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/kmem.h>
#include <sys/pathname.h>
#include <sys/zfs_vnode.h>
#include <sys/vfs.h>
#include <sys/zfs_context.h>
#include <sys/zfs_mount.h>
#include <sys/cmn_err.h>
#include <sys/zfs_vfsops.h>
#include <sys/zfs_znode.h>
#include <sys/zfs_dir.h>
#include <sys/zil.h>
#include <sys/fs/zfs.h>
//#include <sys/refcount.h>
#include <sys/dmu.h>
#include <sys/dsl_prop.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_deleg.h>
#include <sys/spa.h>
#include <sys/zap.h>
#include <sys/atomic.h>
#include <sys/zfs_ioctl.h>
#include <sys/zfs_ctldir.h>
#include <sys/sunddi.h>
#include <sys/dnlc.h>
#include <sys/dmu_objset.h>
#include <coverage.h>

#include "zfs_namecheck.h"
#include "zfs_iomedia.h"
#include <libkern/crypto/sha1.h>

/* These should come from <sys/sysctl.h> but they are hidden in our context */
extern int sysctl_int(user_addr_t, size_t *, user_addr_t, size_t, int *);
extern int sysctl_rdint(user_addr_t, size_t *, user_addr_t, int);

static int  zfs_vfs_init (struct vfsconf *vfsp);
static int  zfs_vfs_start (struct mount *mp, int flags, vfs_context_t context);
static int  zfs_vfs_mount (struct mount *mp, vnode_t *devvp, user_addr_t data, vfs_context_t context);
static int  zfs_vfs_unmount (struct mount *mp, int mntflags, vfs_context_t context);
static int  zfs_vfs_root (struct mount *mp, vnode_t **vpp, vfs_context_t context);
static int  zfs_vfs_vget (struct mount *mp, ino64_t ino, vnode_t **vpp, vfs_context_t context);
static int  zfs_vfs_getattr (struct mount *mp, struct vfs_attr *fsap, vfs_context_t context);
static int  zfs_vfs_setattr (struct mount *mp, struct vfs_attr *fsap, vfs_context_t context);
int  zfs_vfs_sync (struct mount *mp, int waitfor, vfs_context_t context);
static int  zfs_vfs_fhtovp (struct mount *mp, int fhlen, unsigned char *fhp, vnode_t **vpp, vfs_context_t context);
static int  zfs_vfs_vptofh (vnode_t *vp, int *fhlenp, unsigned char *fhp, vfs_context_t context);
static int  zfs_vfs_sysctl (int *name, u_int namelen, user_addr_t oldp, size_t *oldlenp,  user_addr_t newp, size_t newlen, vfs_context_t context);
static int  zfs_vfs_quotactl ( struct mount *mp, int cmds, uid_t uid, caddr_t datap, vfs_context_t context);
static void zfs_freevfs(struct mount *mp);

int  zfs_module_start(void);
int  zfs_module_stop(void);


/* cleanup and teardown of pending search queries */
extern void zfs_search_teardown(zfsvfs_t* zfsvfs);


/*
 * We need to keep a count of active fs's.
 * This is necessary to prevent our kext
 * from being unloaded after a umount -f
 */
static SInt32	zfs_active_fs_count = 0;

/*
 * OS X expects a file system modify time
 *
 * We use the mtime of the "com.apple.system.mtime" 
 * extended attribute, which is associated with the
 * file system root directory.  This attribute has
 * no associated data.
 */
#define ZFS_MTIME_XATTR		"com.apple.system.mtime"

extern int zfs_obtain_xattr(znode_t *, const char *, mode_t, cred_t *,
                            vnode_t **, int);

/*
 * zfs vfs operations.
 */
static struct vfsops zfs_vfsops_template = {
	zfs_vfs_mount,
	zfs_vfs_start,
	zfs_vfs_unmount,
	zfs_vfs_root,
	zfs_vfs_quotactl,
	zfs_vfs_getattr,
	zfs_vfs_sync,
	zfs_vfs_vget,
	zfs_vfs_fhtovp,
	zfs_vfs_vptofh,
	zfs_vfs_init,
	zfs_vfs_sysctl,
	zfs_vfs_setattr,
	{NULL}
};


extern struct vnodeopv_desc zfs_dvnodeop_opv_desc;
extern struct vnodeopv_desc zfs_fvnodeop_opv_desc;
extern struct vnodeopv_desc zfs_symvnodeop_opv_desc;
extern struct vnodeopv_desc zfs_xdvnodeop_opv_desc;
extern struct vnodeopv_desc zfs_evnodeop_opv_desc;
extern struct vnodeopv_desc zfs_fifoop_opv_desc;

#define ZFS_VNOP_TBL_CNT	6

static struct vnodeopv_desc *zfs_vnodeop_opv_desc_list[ZFS_VNOP_TBL_CNT] =
{
	&zfs_dvnodeop_opv_desc,
	&zfs_fvnodeop_opv_desc,
	&zfs_symvnodeop_opv_desc,
	&zfs_xdvnodeop_opv_desc,
	&zfs_evnodeop_opv_desc,
	&zfs_fifoop_opv_desc,
};

static vfstable_t zfs_vfsconf;

extern void zfs_ioctl_init(void);
extern void zfs_ioctl_fini(void);

#ifdef __APPLE__
extern int zfs_vnop_fsync(struct vnop_fsync_args *ap);

struct zfs_vfs_sync_callback_args {
	vfs_context_t context;
	int waitfor;
	int err;
};

static int
zfs_vfs_sync_callback(vnode_t *vp, void *cargs)
{
	struct zfs_vfs_sync_callback_args *args = (struct zfs_vfs_sync_callback_args*)cargs;
	struct vnop_fsync_args fsync_args;
	int err;
	fsync_args.a_desc = NULL;
	fsync_args.a_vp = vp;
	fsync_args.a_waitfor = args->waitfor;
	fsync_args.a_context = args->context;
	err = zfs_vnop_fsync(&fsync_args);
	if (err != 0)
		args->err = err;
	return VNODE_RETURNED;
}
#endif

int
zfs_vfs_sync(struct mount *mp, __unused int waitfor, __unused vfs_context_t context)
{
	zfsvfs_t *zfsvfs = vfs_fsprivate(mp);

	ZFS_ENTER(zfsvfs);

	/*
	 * OS X expects a file system modify time
	 *
	 * We use the mtime of the "com.apple.system.mtime" 
	 * extended attribute, which is associated with the
	 * file system root directory.
	 *
	 * Here we sync any mtime changes to this attribute.
	 */
	if (zfsvfs->z_mtime_vp != NULL) {
		timestruc_t  mtime;
		znode_t  *zp;
top:
		zp = VTOZ(zfsvfs->z_mtime_vp);
		ZFS_TIME_DECODE(&mtime, zp->z_phys->zp_mtime);
		if (zfsvfs->z_last_mtime_synced < mtime.tv_sec) {
			dmu_tx_t  *tx;
			int  error;

			tx = dmu_tx_create(zfsvfs->z_os);
			dmu_tx_hold_bonus(tx, zp->z_id);
			error = dmu_tx_assign(tx, zfsvfs->z_assign);
			if (error) {
				if (error == ERESTART && zfsvfs->z_assign == TXG_NOWAIT) {
					dmu_tx_wait(tx);
					dmu_tx_abort(tx);
					goto top;
				}
				dmu_tx_abort(tx);
			} else {
				dmu_buf_will_dirty(zp->z_dbuf, tx);
				dmu_tx_commit(tx);
				zfsvfs->z_last_mtime_synced = mtime.tv_sec;
			}
		}
	}

#ifdef __APPLE__
	/* to avoid deadlock, we cannot call zil_commit here, since zil_commit will call vnode_get after grabbing ZFS locks.  We need to use vnode_iterate to call fsync on each vnode so that vnode reference is taken before any ZFS resource is taken. */
	struct zfs_vfs_sync_callback_args args;
	args.waitfor = waitfor;
	args.context = context;
	vnode_iterate(mp, VNODE_ITERATE_ACTIVE, zfs_vfs_sync_callback, (void *)&args);
#else
	if (zfsvfs->z_log != NULL)
		zil_commit(zfsvfs->z_log, UINT64_MAX, 0);
	else
		txg_wait_synced(dmu_objset_pool(zfsvfs->z_os), 0);
#endif

	ZFS_EXIT(zfsvfs);

	return (0);
}

static int
zfsvfs_setup(zfsvfs_t *zfsvfs, boolean_t mounting)
{
	uint_t readonly;
	int error;

	/*
	 * Set the objset user_ptr to track its zfsvfs.
	 */
	mutex_enter(&zfsvfs->z_os->os->os_user_ptr_lock);
	dmu_objset_set_user(zfsvfs->z_os, zfsvfs);
	mutex_exit(&zfsvfs->z_os->os->os_user_ptr_lock);

	/*
	 * If we are not mounting (ie: online recv), then we don't
	 * have to worry about replaying the log as we blocked all
	 * operations out since we closed the ZIL.
	 */
	if (mounting) {
		/*
		 * During replay we remove the read only flag to
		 * allow replays to succeed.
		 */

		readonly = vfs_isrdonly(zfsvfs->z_vfs);
		if (readonly != 0)
			vfs_clearflags(zfsvfs->z_vfs, MNT_RDONLY);
		else
			zfs_unlinked_drain(zfsvfs);

		/*
		 * Parse and replay the intent log.
		 *
		 * Because of ziltest, this must be done after
		 * zfs_unlinked_drain().  (Further note: ziltest doesn't
		 * use readonly mounts, where zfs_unlinked_drain() isn't
		 * called.)  This is because ziltest causes spa_sync()
		 * to think it's committed, but actually it is not, so
		 * the intent log contains many txg's worth of changes.
		 *
		 * In particular, if object N is in the unlinked set in
		 * the last txg to actually sync, then it could be
		 * actually freed in a later txg and then reallocated in
		 * a yet later txg.  This would write a "create object
		 * N" record to the intent log.  Normally, this would be
		 * fine because the spa_sync() would have written out
		 * the fact that object N is free, before we could write
		 * the "create object N" intent log record.
		 *
		 * But when we are in ziltest mode, we advance the "open
		 * txg" without actually spa_sync()-ing the changes to
		 * disk.  So we would see that object N is still
		 * allocated and in the unlinked set, and there is an
		 * intent log record saying to allocate it.
		 */
		zil_replay(zfsvfs->z_os, zfsvfs, &zfsvfs->z_assign,
		    zfs_replay_vector);

		if (readonly)
			vfs_setflags(zfsvfs->z_vfs, MNT_RDONLY);
	}

	if (!zil_disable)
		zfsvfs->z_log = zil_open(zfsvfs->z_os, zfs_get_data);

	return (0);
}

static void
zfs_freezfsvfs(zfsvfs_t *zfsvfs)
{
	/* OS X - cleanup any remaining search queries */
	mutex_destroy(&zfsvfs->z_search_mtx);
	list_destroy(&zfsvfs->z_search_pending);
	mutex_destroy(&zfsvfs->z_rename_lock);

	mutex_destroy(&zfsvfs->z_znodes_lock);
	mutex_destroy(&zfsvfs->z_online_recv_lock);
	list_destroy(&zfsvfs->z_all_znodes);
	rrw_destroy(&zfsvfs->z_teardown_lock);
	rw_destroy(&zfsvfs->z_teardown_inactive_lock);
	rw_destroy(&zfsvfs->z_fuid_lock);
	kmem_free(zfsvfs, sizeof (zfsvfs_t));
}

static int
zfs_domount(struct mount *mp, dev_t mount_dev, char *osname, vfs_context_t ctx)
{
	uint64_t readonly;
	int error = 0;
	int mode;
	zfsvfs_t *zfsvfs;
	znode_t *zp = NULL;
	struct timeval tv;
	/* for cleaning up search snaps */
	uint64_t offp = 0;
	int snaperr;

	ASSERT(mp);
	ASSERT(osname);

	/*
	 * Initialize the zfs-specific filesystem structure.
	 * Should probably make this a kmem cache, shuffle fields,
	 * and just bzero up to z_hold_mtx[].
	 */
	zfsvfs = kmem_zalloc(sizeof (zfsvfs_t), KM_SLEEP);
	zfsvfs->z_vfs = mp;
	zfsvfs->z_parent = zfsvfs;
	zfsvfs->z_assign = TXG_NOWAIT;
	zfsvfs->z_max_blksz = SPA_MAXBLOCKSIZE;
	zfsvfs->z_show_ctldir = ZFS_SNAPDIR_VISIBLE;

	mutex_init(&zfsvfs->z_znodes_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&zfsvfs->z_online_recv_lock, NULL, MUTEX_DEFAULT, NULL);
	list_create(&zfsvfs->z_all_znodes, sizeof (znode_t),
	    offsetof(znode_t, z_link_node));
	rrw_init(&zfsvfs->z_teardown_lock);
	rw_init(&zfsvfs->z_teardown_inactive_lock, NULL, RW_DEFAULT, NULL);
	rw_init(&zfsvfs->z_fuid_lock, NULL, RW_DEFAULT, NULL);
	mutex_init(&zfsvfs->z_rename_lock, NULL, MUTEX_DEFAULT, NULL);

	/* Initialize search data structures in zfsvfs */
	mutex_init(&zfsvfs->z_search_mtx, NULL, MUTEX_DEFAULT, NULL);
	list_create(&zfsvfs->z_search_pending, sizeof(zfssearch_t), 
		offsetof(zfssearch_t, z_search_link));
	zfsvfs->z_search_cleanup = NULL;
	cv_init(&zfsvfs->z_search_cv, NULL, 0, NULL);
	zfsvfs->z_search_seq = 0;

	/* Initialize the generic filesystem structure. */
	vfs_setfsprivate(mp, zfsvfs);

	if (error = dsl_prop_get_integer(osname, "readonly", &readonly, NULL))
		goto out;

	if (readonly) {
		mode = DS_MODE_OWNER | DS_MODE_READONLY;
		vfs_setflags(mp, (u_int64_t)((unsigned int)MNT_RDONLY));
	} else {
		mode = DS_MODE_OWNER;
	}

	error = dmu_objset_open(osname, DMU_OST_ZFS, mode, &zfsvfs->z_os);
	if (error == EROFS) {
		mode = DS_MODE_OWNER | DS_MODE_READONLY;
		error = dmu_objset_open(osname, DMU_OST_ZFS, mode,
		    &zfsvfs->z_os);
	}

	if (error)
		goto out;

	if ((error = zfs_init_fs(zfsvfs, &zp)))
		goto out;

	/* The call to zfs_init_fs leaves the vnode held, release it here. */
	vnode_put(ZTOV(zp));

	if (dmu_objset_is_snapshot(zfsvfs->z_os)) {
		ASSERT(mode & DS_MODE_READONLY);
		zfsvfs->z_atime = B_FALSE;
		vfs_setflags(mp, MNT_RDONLY);
		zfsvfs->z_issnap = B_TRUE;
	} else {
		error = zfsvfs_setup(zfsvfs, B_TRUE);
	}

#if 0
	if (!zfsvfs->z_issnap)
		zfsctl_create(zfsvfs);
#endif

	/*
	 * Record the mount time (for Spotlight)
	 */
	microtime(&tv);
	zfsvfs->z_mount_time = tv.tv_sec;

out:
	if (error) {
		if (zfsvfs->z_os)
			dmu_objset_close(zfsvfs->z_os);
		zfs_freezfsvfs(zfsvfs);
	} else {
		OSIncrementAtomic(&zfs_active_fs_count);
		/*
		 * If we don't yet have a f_mntfromname, provide one.
		 * This will typically occur for sub-filesystems.
		 */
		if (vfs_statfs(mp)->f_mntfromname[0] == '\0') {
			(void) copystr(osname, vfs_statfs(mp)->f_mntfromname,
			               MNAMELEN - 1, 0);
			/*
			 * XXX Experiment for sub-filesystems
			 * (to suppress Finder treating it as a volume)
			 */
			vfs_setflags(mp, (u_int64_t)((unsigned int)MNT_AUTOMOUNTED));
		}
		vfs_getnewfsid(mp);
	}

	return (error);
}

static int
zfs_vfs_mount(struct mount *mp, vnode_t *devvp, user_addr_t data, vfs_context_t context)
{
	char	*osname = NULL;
	size_t	osnamelen = 0;
	int	error = 0;
	int	canwrite;

	/*
	 * Get the objset name (the "special" mount argument).
	 */
	if (data) {
		user_addr_t datasetpath = USER_ADDR_NULL;
		osname = kmem_alloc(MAXPATHLEN, KM_SLEEP);

		if (vfs_context_is64bit(context)) {
			if ((error = copyin(data, (caddr_t)&datasetpath,
			                     sizeof(datasetpath)))) {
				goto out;
			}
		} else {
			user32_addr_t tmp;

			if ((error = copyin(data, (caddr_t)&tmp, sizeof(tmp))))
				goto out;
			/* munge into LP64 addr */
			datasetpath = CAST_USER_ADDR_T(tmp);
		}
		if ((error = copyinstr(datasetpath, osname, MAXPATHLEN,
		     &osnamelen))) {
			goto out;
		}
	}

	error = zfs_domount(mp, 0, osname, context);
	if (error)
		printf("zfs_vfs_mount: error %d\n", error);
	if (error == 0) {
		zfsvfs_t *zfsvfs = NULL;

		/* Indicate to VFS that we support ACLs. */
		vfs_setextendedsecurity(mp);

		/* Advisory locking should be handled at the VFS layer */
		vfs_setlocklocal(mp);

		/*
		 * OS X expects a file system modify time
		 *
		 * We use the mtime of the "com.apple.system.mtime" 
		 * extended attribute, which is associated with the
		 * file system root directory.
		 *
		 * Here we need to take a ref on z_mtime_vp to keep it around.
		 * If the attribute isn't there, attempt to create it.
		 */
		zfsvfs = vfs_fsprivate(mp);
		if (zfsvfs->z_mtime_vp == NULL) {
			vnode_t * rvp;
			vnode_t *xdvp = NULLVP;
			vnode_t *xvp = NULLVP;
			znode_t *rootzp;
			timestruc_t modify_time;
			cred_t  *cr;
			timestruc_t  now;
			int flag;
			int result;

			if (zfs_zget(zfsvfs, zfsvfs->z_root, &rootzp) != 0) {
				goto out;
			}
			rvp = ZTOV(rootzp);
			cr = (cred_t *)vfs_context_ucred(context);

			/* Grab the hidden attribute directory vnode. */
			result = zfs_get_xattrdir(rootzp, &xdvp, cr, CREATE_XATTR_DIR);
			vnode_put(rvp);	/* all done with root vnode */
			rvp = NULL;
			if (result) {
				goto out;
			}

			/*
			 * HACK - workaround missing vnode_setnoflush() KPI...
			 *
			 * We tag zfsvfs so that zfs_attach_vnode() can then set
			 * vnfs_marksystem when the vnode gets created.
			 */
			zfsvfs->z_last_unmount_time = 0xBADC0DE;
			zfsvfs->z_last_mtime_synced = VTOZ(xdvp)->z_id;
			flag = vfs_isrdonly(mp) ? 0 : ZEXISTS;
			/* Lookup or create the named attribute. */
			if ( zfs_obtain_xattr(VTOZ(xdvp), ZFS_MTIME_XATTR,
			                          S_IRUSR | S_IWUSR, cr, &xvp,
			                          flag) ) {
					zfsvfs->z_last_unmount_time = 0;
					zfsvfs->z_last_mtime_synced = 0;
					vnode_put(xdvp);
					goto out;
				}
				gethrestime(&now);
			ZFS_TIME_ENCODE(&now, VTOZ(xvp)->z_phys->zp_mtime);

			vnode_put(xdvp);
			vnode_ref(xvp);

			zfsvfs->z_mtime_vp = xvp;
			ZFS_TIME_DECODE(&modify_time, VTOZ(xvp)->z_phys->zp_mtime);
			zfsvfs->z_last_unmount_time = modify_time.tv_sec;
			zfsvfs->z_last_mtime_synced = modify_time.tv_sec;

			/*
			 * Keep this referenced vnode from impeding an unmount.
			 *
			 * XXX vnode_setnoflush() is MIA from KPI (see workaround above).
			 */
#if 0
			vnode_setnoflush(xvp);
#endif
			vnode_put(xvp);
		}
	}
out:
	if (osname) {
		kmem_free(osname, MAXPATHLEN);
	}
	return (error);
}

/*
 * ZFS file system features.
 */
const vol_capabilities_attr_t zfs_capabilities = {
	{
		/* Format capabilities we support: */
		VOL_CAP_FMT_PERSISTENTOBJECTIDS |
		VOL_CAP_FMT_SYMBOLICLINKS |
		VOL_CAP_FMT_HARDLINKS |
		VOL_CAP_FMT_SPARSE_FILES |
		VOL_CAP_FMT_CASE_SENSITIVE |
		VOL_CAP_FMT_CASE_PRESERVING |
		VOL_CAP_FMT_FAST_STATFS | 
		VOL_CAP_FMT_2TB_FILESIZE |
		VOL_CAP_FMT_HIDDEN_FILES |
		VOL_CAP_FMT_PATH_FROM_ID,

		/* Interface capabilities we support: */
		VOL_CAP_INT_SEARCHFS |
		VOL_CAP_INT_ATTRLIST |
		VOL_CAP_INT_NFSEXPORT |
		VOL_CAP_INT_READDIRATTR |
		VOL_CAP_INT_VOL_RENAME |
		VOL_CAP_INT_ADVLOCK |
		VOL_CAP_INT_FLOCK |
		VOL_CAP_INT_EXTENDED_SECURITY |
		VOL_CAP_INT_NAMEDSTREAMS |
		VOL_CAP_INT_EXTENDED_ATTR ,

		0 , 0
	},
	{
		/* Format capabilities we know about: */
		VOL_CAP_FMT_PERSISTENTOBJECTIDS |
		VOL_CAP_FMT_SYMBOLICLINKS |
		VOL_CAP_FMT_HARDLINKS |
		VOL_CAP_FMT_JOURNAL |
		VOL_CAP_FMT_JOURNAL_ACTIVE |
		VOL_CAP_FMT_NO_ROOT_TIMES |
		VOL_CAP_FMT_SPARSE_FILES |
		VOL_CAP_FMT_ZERO_RUNS |
		VOL_CAP_FMT_CASE_SENSITIVE |
		VOL_CAP_FMT_CASE_PRESERVING |
		VOL_CAP_FMT_FAST_STATFS | 
		VOL_CAP_FMT_2TB_FILESIZE |
		VOL_CAP_FMT_OPENDENYMODES |
		VOL_CAP_FMT_HIDDEN_FILES |
		VOL_CAP_FMT_PATH_FROM_ID ,

		/* Interface capabilities we know about: */
		VOL_CAP_INT_SEARCHFS |
		VOL_CAP_INT_ATTRLIST |
		VOL_CAP_INT_NFSEXPORT |
		VOL_CAP_INT_READDIRATTR |
		VOL_CAP_INT_EXCHANGEDATA |
		VOL_CAP_INT_COPYFILE |
		VOL_CAP_INT_ALLOCATE |
		VOL_CAP_INT_VOL_RENAME |
		VOL_CAP_INT_ADVLOCK |
		VOL_CAP_INT_FLOCK |
		VOL_CAP_INT_EXTENDED_SECURITY |
		VOL_CAP_INT_USERACCESS |
		VOL_CAP_INT_MANLOCK |
		VOL_CAP_INT_NAMEDSTREAMS |
		VOL_CAP_INT_EXTENDED_ATTR ,

		0, 0
	}
};

/*
 * ZFS file system attributes (for getattrlist).
 */
const attribute_set_t zfs_attributes = {
		ATTR_CMN_NAME	|
		ATTR_CMN_DEVID	|
		ATTR_CMN_FSID	|
		ATTR_CMN_OBJTYPE |
		ATTR_CMN_OBJTAG	|
		ATTR_CMN_OBJID	|
		ATTR_CMN_OBJPERMANENTID |
		ATTR_CMN_PAROBJID |
		ATTR_CMN_CRTIME |
		ATTR_CMN_MODTIME |
		ATTR_CMN_CHGTIME |
		ATTR_CMN_ACCTIME |
		ATTR_CMN_BKUPTIME |
		ATTR_CMN_FNDRINFO |
		ATTR_CMN_OWNERID |
		ATTR_CMN_GRPID	|
		ATTR_CMN_ACCESSMASK |
		ATTR_CMN_FLAGS	|
		ATTR_CMN_USERACCESS |
		ATTR_CMN_EXTENDED_SECURITY |
		ATTR_CMN_UUID |
		ATTR_CMN_GRPUUID ,

		ATTR_VOL_FSTYPE	|
		ATTR_VOL_SIGNATURE |
		ATTR_VOL_SIZE	|
		ATTR_VOL_SPACEFREE |
		ATTR_VOL_SPACEAVAIL |
		ATTR_VOL_MINALLOCATION |
		ATTR_VOL_ALLOCATIONCLUMP |
		ATTR_VOL_IOBLOCKSIZE |
		ATTR_VOL_OBJCOUNT |
		ATTR_VOL_FILECOUNT |
		ATTR_VOL_DIRCOUNT |
		ATTR_VOL_MAXOBJCOUNT |
		ATTR_VOL_MOUNTPOINT |
		ATTR_VOL_NAME	|
		ATTR_VOL_MOUNTFLAGS |
		ATTR_VOL_MOUNTEDDEVICE |
		ATTR_VOL_CAPABILITIES |
		ATTR_VOL_UUID |
		ATTR_VOL_ATTRIBUTES ,

		ATTR_DIR_LINKCOUNT |
		ATTR_DIR_ENTRYCOUNT |
		ATTR_DIR_MOUNTSTATUS ,

		ATTR_FILE_LINKCOUNT |
		ATTR_FILE_TOTALSIZE |
		ATTR_FILE_ALLOCSIZE |
		/* ATTR_FILE_IOBLOCKSIZE */
		ATTR_FILE_DEVTYPE |
		ATTR_FILE_DATALENGTH |
		ATTR_FILE_DATAALLOCSIZE |
		ATTR_FILE_RSRCLENGTH |
		ATTR_FILE_RSRCALLOCSIZE ,

		0
};

/* 6A898CC3-1DD2-11B2-99A6-080020736631 */
UUID_DEFINE( ZFS_UUID_NAMESPACE, 0x6A,0x89,0x8C,0xC3,0x1D,0xD2,0x11,0xB2,0x99,0xA6,0x08,0x00,0x20,0x73,0x66,0x31);

static void
zfs_generate_uuid(uint64_t pool_guid, uint64_t fs_guid, uuid_t zfs_uuid)
{
    SHA1_CTX c;
    uint8_t md[SHA_DIGEST_LENGTH];
    uint8_t name[16];

    *(uint64_t *)&name[0] = pool_guid;
    *(uint64_t *)&name[8] = fs_guid;

    SHA1Init(&c);
    SHA1Update(&c, ZFS_UUID_NAMESPACE, sizeof(uuid_t));
    SHA1Update(&c, &name, sizeof (name));
    SHA1Final(md, &c);

    uuid_copy(zfs_uuid, md);

    zfs_uuid[6] = (zfs_uuid[6] & 0x0F) | 0x50;
    zfs_uuid[8] = (zfs_uuid[8] & 0x3F) | 0x80;
}

static int
zfs_vfs_getattr(struct mount *mp, struct vfs_attr *fsap, __unused vfs_context_t context)
{
	zfsvfs_t *zfsvfs = vfs_fsprivate(mp);
	uint64_t refdbytes, availbytes, usedobjs, availobjs;

	ZFS_ENTER(zfsvfs);

	dmu_objset_space(zfsvfs->z_os,
	    &refdbytes, &availbytes, &usedobjs, &availobjs);

	VFSATTR_RETURN(fsap, f_objcount, usedobjs);
	VFSATTR_RETURN(fsap, f_maxobjcount, 0x7fffffffffffffff);
	/*
	 * Carbon depends on f_filecount and f_dircount so
	 * make up some values based on total objects.
	 */
	VFSATTR_RETURN(fsap, f_filecount, usedobjs - (usedobjs / 4));
	VFSATTR_RETURN(fsap, f_dircount, usedobjs / 4);

	/*
	 * The underlying storage pool actually uses multiple block sizes.
	 * We report our blocksize as the filesystem's minimum blocksize.
	 */
	VFSATTR_RETURN(fsap, f_bsize, SPA_MINBLOCKSIZE);
	VFSATTR_RETURN(fsap, f_iosize, zfsvfs->z_max_blksz);

	/*
	 * The following report "total" blocks of various kinds in the
	 * file system in terms of f_bsize (above).
	 */
	VFSATTR_RETURN(fsap, f_blocks,
	    (u_int64_t)((refdbytes + availbytes) >> SPA_MINBLOCKSHIFT));
	VFSATTR_RETURN(fsap, f_bfree, (u_int64_t)(availbytes >> SPA_MINBLOCKSHIFT));
	VFSATTR_RETURN(fsap, f_bavail, fsap->f_bfree);  /* no root reservation */
	VFSATTR_RETURN(fsap, f_bused, fsap->f_blocks - fsap->f_bfree);

	/*
	 * ZFS doesn't preallocate files, so the best we can do is
	 * report the max that could possibly fit in f_files, and
	 * that minus the number actually used in f_ffree.
	 * For f_ffree, report the smaller of the number of object
	 * available and the number of blocks (each object takes at
	 * least a block).
	 */
	VFSATTR_RETURN(fsap, f_ffree, (u_int64_t)MIN(availobjs, fsap->f_bfree));
	VFSATTR_RETURN(fsap, f_files,  fsap->f_ffree + usedobjs);

	if (VFSATTR_IS_ACTIVE(fsap, f_fsid)) {
		/* use value obtained during vfs_getnewfsid() */
		VFSATTR_RETURN(fsap, f_fsid, vfs_statfs(mp)->f_fsid);
	}
	if (VFSATTR_IS_ACTIVE(fsap, f_capabilities)) {
		bcopy(&zfs_capabilities, &fsap->f_capabilities, sizeof (zfs_capabilities));
		/* Fix up any dynamic capabilities */
		if (zfsvfs->z_case == ZFS_CASE_INSENSITIVE) {
			fsap->f_capabilities.capabilities[VOL_CAPABILITIES_FORMAT] &=
			    ~VOL_CAP_FMT_CASE_SENSITIVE;
		}
		VFSATTR_SET_SUPPORTED(fsap, f_capabilities);
	}
	if (VFSATTR_IS_ACTIVE(fsap, f_attributes)) {
		bcopy(&zfs_attributes, &fsap->f_attributes.validattr, sizeof (zfs_attributes));
		bcopy(&zfs_attributes, &fsap->f_attributes.nativeattr, sizeof (zfs_attributes));
		VFSATTR_SET_SUPPORTED(fsap, f_attributes);
	}
	if (VFSATTR_IS_ACTIVE(fsap, f_create_time)) {
		dmu_objset_stats_t dmu_stat;

		dmu_objset_fast_stat(zfsvfs->z_os, &dmu_stat);
		fsap->f_create_time.tv_sec = dmu_stat.dds_creation_time;
		fsap->f_create_time.tv_nsec = 0;
		VFSATTR_SET_SUPPORTED(fsap, f_create_time);
	}
	if (VFSATTR_IS_ACTIVE(fsap, f_modify_time)) {
		if (zfsvfs->z_mtime_vp != NULL) {
			znode_t *mzp;

			mzp = VTOZ(zfsvfs->z_mtime_vp);
			ZFS_TIME_DECODE(&fsap->f_modify_time, mzp->z_phys->zp_mtime);
		} else {
			fsap->f_modify_time.tv_sec = 0;
			fsap->f_modify_time.tv_nsec = 0;
		}
		VFSATTR_SET_SUPPORTED(fsap, f_modify_time);
	}
	/*
	 * For Carbon compatibility, pretend to support this legacy/unused 
	 * attribute
	 */
	if (VFSATTR_IS_ACTIVE(fsap, f_backup_time)) {
		fsap->f_backup_time.tv_sec = 0;
		fsap->f_backup_time.tv_nsec = 0;
		VFSATTR_SET_SUPPORTED(fsap, f_backup_time);
	}
	if (VFSATTR_IS_ACTIVE(fsap, f_vol_name)) {
		zfs_get_fsname(zfsvfs, fsap->f_vol_name);
		VFSATTR_SET_SUPPORTED(fsap, f_vol_name);
	}
	if (VFSATTR_IS_ACTIVE(fsap, f_fssubtype)) {
		uint64_t guid;

		/* Ask IOKit layer for our pool type. */ 
		guid = spa_guid(dmu_objset_spa(zfsvfs->z_os));
		fsap->f_fssubtype = zfs_iomedia_subtype(guid);
		VFSATTR_SET_SUPPORTED(fsap, f_fssubtype);
	}
	VFSATTR_RETURN(fsap, f_signature, 0x5a21);  /* 'Z!' */
	VFSATTR_RETURN(fsap, f_carbon_fsid, 0);

	if (VFSATTR_IS_ACTIVE(fsap, f_uuid)) {
		uint64_t pool_guid, fs_guid;

		pool_guid = spa_guid(dmu_objset_spa(zfsvfs->z_os));
		fs_guid = dsl_dataset_fsid_guid(dmu_objset_ds(zfsvfs->z_os));
		zfs_generate_uuid(pool_guid, fs_guid, fsap->f_uuid);
		VFSATTR_SET_SUPPORTED(fsap, f_uuid);
	}

	ZFS_EXIT(zfsvfs);

	return (0);
}

/*
 * Obtain the current file system name
 *
 * Assumes buffer size is at least MAXPATHLEN
 */
void
zfs_get_fsname(zfsvfs_t *zfsvfs, char *fsname)
{
	char *leafname;

	dmu_objset_name(zfsvfs->z_os, fsname);

	/* Strip any mount hierarchy components from name. */
	if ((leafname = strrchr(fsname, '/')))
		strlcpy(fsname, leafname + 1, MAXPATHLEN);
}

static int
zfs_vfs_root(struct mount *mp, vnode_t **vpp, __unused vfs_context_t context)
{
	zfsvfs_t *zfsvfs = vfs_fsprivate(mp);
	znode_t *rootzp;
	int error;

	ZFS_ENTER(zfsvfs);

	error = zfs_zget(zfsvfs, zfsvfs->z_root, &rootzp);
	if (error == 0)
		*vpp = ZTOV(rootzp);

	ZFS_EXIT(zfsvfs);
	return (error);
}

int
VFS_ROOT(struct mount *mp, vnode_t **vpp)
{
	struct vfsstatfs *vfsstatfsp = vfs_statfs(mp);

	if (strncmp(vfsstatfsp->f_fstypename, "zfs", MFSTYPENAMELEN) != 0) 
		return (EINVAL);

	return zfs_vfs_root(mp, vpp, NULL);
}

/*
 * Teardown the zfsvfs::z_os.
 *
 * Note, if 'unmounting' if FALSE, we return with the 'z_teardown_lock'
 * and 'z_teardown_inactive_lock' held.
 */
static int
zfsvfs_teardown(zfsvfs_t *zfsvfs, boolean_t unmounting)
{
	znode_t	*zp;
	znode_t	*nextzp;

	rrw_enter(&zfsvfs->z_teardown_lock, RW_WRITER, FTAG);

	/*
	 * Close the zil. NB: Can't close the zil while zfs_inactive
	 * threads are blocked as zil_close can call zfs_inactive.
	 */
	if (zfsvfs->z_log) {
		zil_close(zfsvfs->z_log);
		zfsvfs->z_log = NULL;
	}

	rw_enter(&zfsvfs->z_teardown_inactive_lock, RW_WRITER);

	/*
	 * If we are not unmounting (ie: online recv) and someone already
	 * unmounted this file system while we were doing the switcheroo,
	 * or a reopen of z_os failed then just bail out now.
	 */
	if (!unmounting && (zfsvfs->z_unmounted || zfsvfs->z_os == NULL)) {
		rw_exit(&zfsvfs->z_teardown_inactive_lock);
		rrw_exit(&zfsvfs->z_teardown_lock, FTAG);
		return (EIO);
	}

	/*
	 * At this point there are no vops active, and any new vops will
	 * fail with EIO since we have z_teardown_lock for writer (only
	 * relavent for forced unmount).
	 *
	 * Release all holds on dbufs.
	 */
	mutex_enter(&zfsvfs->z_znodes_lock);
	for (zp = list_head(&zfsvfs->z_all_znodes); zp != NULL; zp = nextzp) {
		nextzp= list_next(&zfsvfs->z_all_znodes, zp);
		if (zp->z_dbuf) {
			zfs_znode_dmu_fini(zp);
			/*
			 * OS X - zfs_znode_dmu_fini() will cause a znode_free()
			 * during forced unmounts. So we need to start over here
			 * since the list may have changed underneath us.
			 */
			nextzp = list_head(&zfsvfs->z_all_znodes);
		}
	}
	mutex_exit(&zfsvfs->z_znodes_lock);

	/*
	 * If we are unmounting, set the unmounted flag and let new vops
	 * unblock.  zfs_inactive will have the unmounted behavior, and all
	 * other vops will fail with EIO.
	 */
	if (unmounting) {
		zfsvfs->z_unmounted = B_TRUE;
		rrw_exit(&zfsvfs->z_teardown_lock, FTAG);
		rw_exit(&zfsvfs->z_teardown_inactive_lock);
	}

	/*
	 * z_os will be NULL if there was an error in attempting to reopen
	 * zfsvfs, so just return as the properties had already been
	 * unregistered and cached data had been evicted before.
	 */
	if (zfsvfs->z_os == NULL)
		return (0);

	/*
	 * Evict cached data
	 */
	if (dmu_objset_evict_dbufs(zfsvfs->z_os)) {
		txg_wait_synced(dmu_objset_pool(zfsvfs->z_os), 0);
		(void) dmu_objset_evict_dbufs(zfsvfs->z_os);
	}

	return (0);
}

/*ARGSUSED*/
static int
zfs_vfs_unmount(struct mount *mp, int mntflags, vfs_context_t context)
{
	zfsvfs_t	*zfsvfs = vfs_fsprivate(mp);
	objset_t	*os = zfsvfs->z_os;
	int		ret;
	int		flags;

	/* 
	 * we may need to cleanup pending search queries before
	 * we can proceed.
	 */
	zfs_search_teardown(zfsvfs);

	/*
	 * Unmount any snapshots mounted under .zfs before unmounting the
	 * dataset itself.
	 */
#if 0
	if (zfsvfs->z_ctldir != NULL &&
	    (ret = zfsctl_umount_snapshots(vfsp, fflag, cr)) != 0) {
		return (ret);
#endif
	flags = SKIPSYSTEM;
	if (mntflags & MNT_FORCE)
		flags |= FORCECLOSE;

	ret = vflush(mp, NULLVP, flags);

	/*
	 * OS X expects a file system modify time
	 *
	 * We use the mtime of the "com.apple.system.mtime" 
	 * extended attribute, which is associated with the
	 * file system root directory.
	 *
	 * Here we need to release the ref we took on z_mtime_vp during mount.
	 */
	if ((ret == 0) || (mntflags & MNT_FORCE)) {
		if (zfsvfs->z_mtime_vp != NULL) {
			vnode_t *mvp;

			mvp = zfsvfs->z_mtime_vp;
			zfsvfs->z_mtime_vp = NULL;

			if (vnode_get(mvp) == 0) {
				vnode_rele(mvp);
				vnode_recycle(mvp);
				vnode_put(mvp);
			}
		}
	}

	if (ret && !(mntflags & MNT_FORCE)) {
		return (EBUSY);
	}

	VERIFY(zfsvfs_teardown(zfsvfs, B_TRUE) == 0);
	os = zfsvfs->z_os;

	/*
	 * z_os will be NULL if there was an error in
	 * attempting to reopen zfsvfs.
	 */
	if (os != NULL) {
		/*
		 * Unset the objset user_ptr.
		 */
		mutex_enter(&os->os->os_user_ptr_lock);
		dmu_objset_set_user(os, NULL);
		mutex_exit(&os->os->os_user_ptr_lock);

		/*
		 * Finally release the objset
		 */
		dmu_objset_close(os);
	}

	/*
	 * We can now safely destroy the '.zfs' directory node.
	 */
#if 0
	if (zfsvfs->z_ctldir != NULL)
		zfsctl_destroy(zfsvfs);
#endif

	/*
	 * OS X - invoke zfs_freevfs here since our VFS doesn't have this op
	 */
	zfs_freevfs(mp);

	return (0);
}

 
vnode_t* vnode_getparent(vnode_t *vp);  /* sys/vnode_internal.h */

static int
zfs_vget_internal(zfsvfs_t *zfsvfs, ino64_t ino, vnode_t **vpp)
{
	vnode_t		*vp;
	vnode_t		*dvp = NULL;
	znode_t		*zp;
	int		error;

	*vpp = NULL;

	/*
	 * OS X always exports the root directory id as 2
	 * and its parent as 1
	 */
	if (ino == 2 || ino == 1)
		ino = zfsvfs->z_root;

	if ((error = zfs_zget(zfsvfs, ino, &zp)))
		goto out;

	/* Don't expose EA objects! */
	if (zp->z_phys->zp_flags & ZFS_XATTR) {
		vnode_put(ZTOV(zp));
		error = ENOENT;
		goto out;
	}

	*vpp = vp = ZTOV(zp);

	if (vnode_isvroot(vp))
		goto out;

	/*
	 * If this znode didn't just come from the cache then
	 * it won't have a valid identity (parent and name).
	 *
	 * Manually fix its identity here (normally done by namei lookup).
	 */
	if ((dvp = vnode_getparent(vp)) == NULL) {
		if (zp->z_phys->zp_parent != 0 &&
		    zfs_vget_internal(zfsvfs, zp->z_phys->zp_parent, &dvp)) {
			goto out;
		}
		if ( vnode_isdir(dvp) ) {
			char objname[ZAP_MAXNAMELEN];  /* 256 bytes */
			int flags = VNODE_UPDATE_PARENT;

			/* Look for znode's name in its parent's zap */
			if ( zap_value_search(zfsvfs->z_os,
			                      zp->z_phys->zp_parent, 
			                      zp->z_id,
			                      ZFS_DIRENT_OBJ(-1ULL),
			                      objname) == 0 ) {
				flags |= VNODE_UPDATE_NAME;
			}

			/* Update the znode's parent and name */
			vnode_update_identity(vp, dvp, objname, 0, 0, flags);
		}
	}
	/* All done with znode's parent */
	vnode_put(dvp);
out:
	return (error);
}

/*
 * Get a vnode from a file id (ignoring the generation)
 *
 * Use by NFS Server (readdirplus) and VFS (build_path)
 */
static int
zfs_vfs_vget(struct mount *mp, ino64_t ino, vnode_t **vpp,
    __unused vfs_context_t context)
{
	zfsvfs_t *zfsvfs = vfs_fsprivate(mp);
	int error;

	ZFS_ENTER(zfsvfs);

	/*
	 * OS X always exports the root directory id as 2.
	 * So we don't expect to see the real root directory id
	 * from zfs_vfs_vget KPI (unless of course the real id was
	 * already 2).
	 */
	if ((ino == zfsvfs->z_root) && (zfsvfs->z_root != 2)) {
		ZFS_EXIT(zfsvfs);
		return (ENOENT);
	}
	error = zfs_vget_internal(zfsvfs, ino, vpp);

	ZFS_EXIT(zfsvfs);
	return (error);
}

/*
 * Block out VOPs and close zfsvfs_t::z_os
 *
 * Note, if successful, then we return with the 'z_teardown_lock' and
 * 'z_teardown_inactive_lock' write held.
 */
int
zfs_suspend_fs(zfsvfs_t *zfsvfs, char *name, int *mode)
{
	int error;

	if ((error = zfsvfs_teardown(zfsvfs, B_FALSE)) != 0)
		return (error);

	*mode = zfsvfs->z_os->os_mode;
	dmu_objset_name(zfsvfs->z_os, name);
	dmu_objset_close(zfsvfs->z_os);

	return (0);
}

/*
 * Reopen zfsvfs_t::z_os and release VOPs.
 */
int
zfs_resume_fs(zfsvfs_t *zfsvfs, const char *osname, int mode)
{
	int err;

	ASSERT(RRW_WRITE_HELD(&zfsvfs->z_teardown_lock));
	ASSERT(RW_WRITE_HELD(&zfsvfs->z_teardown_inactive_lock));

	err = dmu_objset_open(osname, DMU_OST_ZFS, mode, &zfsvfs->z_os);
	if (err) {
		zfsvfs->z_os = NULL;
	} else {
		znode_t *zp;

		VERIFY(zfsvfs_setup(zfsvfs, B_FALSE) == 0);

		/*
		 * Attempt to re-establish all the active znodes with
		 * their dbufs.  If a zfs_rezget() fails, then we'll let
		 * any potential callers discover that via ZFS_ENTER_VERIFY_VP
		 * when they try to use their znode.
		 */
		mutex_enter(&zfsvfs->z_znodes_lock);
		for (zp = list_head(&zfsvfs->z_all_znodes); zp;
		    zp = list_next(&zfsvfs->z_all_znodes, zp)) {
			(void) zfs_rezget(zp);
		}
		mutex_exit(&zfsvfs->z_znodes_lock);

	}

	/* release the VOPs */
	rw_exit(&zfsvfs->z_teardown_inactive_lock);
	rrw_exit(&zfsvfs->z_teardown_lock, FTAG);
#if 0
	if (err) {
		/*
		 * Since we couldn't reopen zfsvfs::z_os, force
		 * unmount this file system.
		 */
		if (vn_vfswlock(zfsvfs->z_vfs->vfs_vnodecovered) == 0)
			(void) dounmount(zfsvfs->z_vfs, MS_FORCE, CRED());
	}
#endif
	return (err);
}

static void
zfs_freevfs(struct mount *mp)
{
	zfsvfs_t *zfsvfs = vfs_fsprivate(mp);
	int i;

	for (i = 0; i != ZFS_OBJ_MTX_SZ; i++)
		mutex_destroy(&zfsvfs->z_hold_mtx[i]);

	zfs_fuid_destroy(zfsvfs);
	zfs_freezfsvfs(zfsvfs);

	OSDecrementAtomic((SInt32 *)&zfs_active_fs_count);
}

static int
zfs_vfs_init(__unused struct vfsconf *vfsp)
{
	return (0);
}

static void
zfs_init(void)
{
	/*
	 * Initialize our context globals
	 */
	zfs_context_init();

	/*
	 * Initialize slab allocator and taskq layers
	 */
	kmem_init();

	/*
	 * Initialize .zfs directory structures
	 */
#if 0
	zfsctl_init();
#endif
	/*
	 * Initialize znode cache, vnode ops, etc...
	 */
	zfs_znode_init();

	/*
	 * Initialize /dev/zfs
	 */
	zfs_ioctl_init();
}

static void
zfs_fini(void)
{
	zfs_ioctl_fini();
#if 0
	zfsctl_fini();
#endif
	zfs_znode_fini();

	kmem_fini();

	zfs_context_fini();
}

int
zfs_busy(void)
{
	return (zfs_active_fs_count != 0);
}

int
zfs_set_version(const char *name, uint64_t newvers)
{
	int error;
	objset_t *os;
	dmu_tx_t *tx;
	uint64_t curvers;

	/*
	 * XXX for now, require that the filesystem be unmounted.  Would
	 * be nice to find the zfsvfs_t and just update that if
	 * possible.
	 */

	if (newvers < ZPL_VERSION_INITIAL || newvers > ZPL_VERSION)
		return (EINVAL);

	error = dmu_objset_open(name, DMU_OST_ZFS, DS_MODE_OWNER, &os);
	if (error)
		return (error);

	error = zap_lookup(os, MASTER_NODE_OBJ, ZPL_VERSION_STR,
	    8, 1, &curvers);
	if (error)
		goto out;
	if (newvers < curvers) {
		error = EINVAL;
		goto out;
	}

	tx = dmu_tx_create(os);
	dmu_tx_hold_zap(tx, MASTER_NODE_OBJ, 0, ZPL_VERSION_STR);
	error = dmu_tx_assign(tx, TXG_WAIT);
	if (error) {
		dmu_tx_abort(tx);
		goto out;
	}
	error = zap_update(os, MASTER_NODE_OBJ, ZPL_VERSION_STR, 8, 1,
	    &newvers, tx);

	spa_history_internal_log(LOG_DS_UPGRADE,
	    dmu_objset_spa(os), tx, CRED(),
	    "oldver=%llu newver=%llu dataset = %llu", curvers, newvers,
	    dmu_objset_id(os));
	dmu_tx_commit(tx);

out:
	dmu_objset_close(os);
	return (error);
}

/*
 * Read a property stored within the master node.
 */
int
zfs_get_zplprop(objset_t *os, zfs_prop_t prop, uint64_t *value)
{
	const char *pname;
	int error;

	/*
	 * Look up the file system's value for the property.  For the
	 * version property, we look up a slightly different string.
	 */
	if (prop == ZFS_PROP_VERSION)
		pname = ZPL_VERSION_STR;
	else
		pname = zfs_prop_to_name(prop);

	error = zap_lookup(os, MASTER_NODE_OBJ, pname, 8, 1, value);

	if (error == ENOENT) {
		/* No value set, use the default value */
		switch (prop) {
		case ZFS_PROP_VERSION:
			*value = ZPL_VERSION;
			break;
		case ZFS_PROP_NORMALIZE:
		case ZFS_PROP_UTF8ONLY:
			*value = 0;
			break;
		case ZFS_PROP_CASE:
			*value = ZFS_CASE_SENSITIVE;
			break;
		default:
			return (error);
		}
		error = 0;
	}
	return (error);
}

static int
zfs_vfs_setattr(struct mount *mp, struct vfs_attr *fsap, vfs_context_t context)
{
	if (VFSATTR_IS_ACTIVE(fsap, f_vol_name)) {
		zfsvfs_t *zfsvfs = vfs_fsprivate(mp);
		char *oldname, *newname, *leaf;

		/* Does new name conform to rules? */
		if (dataset_namecheck(fsap->f_vol_name, NULL, NULL) != 0) {
			return (EINVAL);
		}
		oldname = kmem_alloc(MAXPATHLEN, KM_SLEEP);
		newname = kmem_alloc(MAXPATHLEN, KM_SLEEP);
		mutex_enter(&zfsvfs->z_rename_lock);

		/* Grab full dataset name */
		dmu_objset_name(zfsvfs->z_os, oldname);
		strlcpy(newname, oldname, MAXPATHLEN);

		/* A hierarchy is expected here, find leaf component name */
		if ((leaf = strrchr(newname, '/'))) {
			strlcpy(leaf + 1, fsap->f_vol_name, MAXPATHLEN);

			if (dsl_dataset_rename(oldname, newname, 0, 1) == 0) {
				VFSATTR_SET_SUPPORTED(fsap, f_vol_name);

				/*
				 * When renaming a sub-filesystem, keep
				 * f_mntfromname in sync so that zfs(8)
				 * unmount still functions after a rename.
				 */
				if (vfs_statfs(mp)->f_mntfromname[0] != '/') {
					strlcpy(vfs_statfs(mp)->f_mntfromname,
					        newname, MNAMELEN);
				}
			}

		}

		mutex_exit(&zfsvfs->z_rename_lock);
		kmem_free(newname, MAXPATHLEN);
		kmem_free(oldname, MAXPATHLEN);

		if (VFSATTR_IS_SUPPORTED(fsap, f_vol_name)) {
			vnode_t *rvp;

			/* Keep vnode identity in sync as well */
			if (zfs_vget_internal(zfsvfs, 2, &rvp) == 0) {
				vnode_update_identity(rvp, NULLVP,
				    fsap->f_vol_name, 0, 0, VNODE_UPDATE_NAME);
				vnode_put(rvp);
			}
			return (0);
		}
	}

	return (EINVAL);
}


/*
 * NFS Server File Handle File ID
 */
typedef struct zfs_zfid {
	uint8_t   zf_object[8];		/* obj[i] = obj >> (8 * i) */
	uint8_t   zf_gen[8];		/* gen[i] = gen >> (8 * i) */
} zfs_zfid_t;

/*
 * File handle to vnode pointer
 */
static int
zfs_vfs_fhtovp(struct mount *mp, int fhlen, unsigned char *fhp, vnode_t **vpp,
    __unused vfs_context_t context)
{
	zfsvfs_t *zfsvfs = vfs_fsprivate(mp);
	zfs_zfid_t	*zfid = (zfs_zfid_t *)fhp;
	znode_t		*zp;
	uint64_t	obj_num = 0;
	uint64_t	fid_gen = 0;
	uint64_t	zp_gen;
	int 		i;
	int		error;

	*vpp = NULL;

	ZFS_ENTER(zfsvfs);

	if (fhlen < sizeof (zfs_zfid_t)) {
		error = EINVAL;
		goto out;
	}

	/*
	 * Grab the object and gen numbers in an endian neutral manner
	 */
	for (i = 0; i < sizeof (zfid->zf_object); i++)
		obj_num |= ((uint64_t)zfid->zf_object[i]) << (8 * i);

	for (i = 0; i < sizeof (zfid->zf_gen); i++)
		fid_gen |= ((uint64_t)zfid->zf_gen[i]) << (8 * i);

	if ((error = zfs_zget(zfsvfs, obj_num, &zp))) {
		goto out;
	}

	zp_gen = zp->z_phys->zp_gen;
	if (zp_gen == 0)
		zp_gen = 1;

	if (zp->z_unlinked || zp_gen != fid_gen) {
		vnode_put(ZTOV(zp));
		error = EINVAL;
		goto out;
	}
	*vpp = ZTOV(zp);
out:
	ZFS_EXIT(zfsvfs);
	return (error);
}

/*
 * Vnode pointer to File handle
 *
 * XXX Do we want to check the DSL sharenfs property?
 */
static int
zfs_vfs_vptofh(vnode_t *vp, int *fhlenp, unsigned char *fhp,
    __unused vfs_context_t context)
{
	zfsvfs_t	*zfsvfs = vfs_fsprivate(vnode_mount(vp));
	zfs_zfid_t	*zfid = (zfs_zfid_t *)fhp;
	znode_t		*zp = VTOZ(vp);
	uint64_t	obj_num;
	uint64_t	zp_gen;
	int		i;
	int		error;

	if (*fhlenp < sizeof (zfs_zfid_t)) {
		return (EOVERFLOW);
	}

	ZFS_ENTER(zfsvfs);

	obj_num = zp->z_id;
	zp_gen = zp->z_phys->zp_gen;
	if (zp_gen == 0)
		zp_gen = 1;

	/*
	 * Store the object and gen numbers in an endian neutral manner
	 */
	for (i = 0; i < sizeof (zfid->zf_object); i++)
		zfid->zf_object[i] = (uint8_t)(obj_num >> (8 * i));

	for (i = 0; i < sizeof (zfid->zf_gen); i++)
		zfid->zf_gen[i] = (uint8_t)(zp_gen >> (8 * i));

	*fhlenp = sizeof (zfs_zfid_t);

	ZFS_EXIT(zfsvfs);
	return (0);
}


static int
zfs_vfs_sysctl(int *name, __unused u_int namelen, user_addr_t oldp,
    size_t *oldlenp, user_addr_t newp, size_t newlen,
    __unused vfs_context_t context)
{
	int error;

	switch(name[0]) {
	case ZFS_SYSCTL_FOOTPRINT: {
		zfs_footprint_stats_t *footprint;
		size_t copyinsize;
		size_t copyoutsize;
		int max_caches;
		int act_caches;

		if (newp) {
			return (EINVAL);
		}
		if (!oldp) {
			*oldlenp = sizeof (zfs_footprint_stats_t);
			return (0);
		}
		copyinsize = *oldlenp;
		if (copyinsize < sizeof (zfs_footprint_stats_t)) {
			*oldlenp = sizeof (zfs_footprint_stats_t);
			return (ENOMEM);
		}
		footprint = kmem_alloc(copyinsize, KM_SLEEP);

		max_caches = copyinsize - sizeof (zfs_footprint_stats_t);
		max_caches += sizeof (kmem_cache_stats_t);
		max_caches /= sizeof (kmem_cache_stats_t);

		footprint->version = ZFS_FOOTPRINT_VERSION;

		footprint->memory_stats.current = zfs_footprint.current;
		footprint->memory_stats.target = zfs_footprint.target;
		footprint->memory_stats.highest = zfs_footprint.highest;
		footprint->memory_stats.maximum = zfs_footprint.maximum;

		arc_get_stats(&footprint->arc_stats);

		kmem_cache_stats(&footprint->cache_stats[0], max_caches, &act_caches);
		footprint->caches_count = act_caches;
		footprint->thread_count = zfs_threads;

		copyoutsize = sizeof (zfs_footprint_stats_t) +
		              ((act_caches - 1) * sizeof (kmem_cache_stats_t));

		error = copyout(footprint, oldp, copyoutsize);

		kmem_free(footprint, copyinsize);

		return (error);
	    }

	case ZFS_SYSCTL_CONFIG_DEBUGMSG:
		error = sysctl_int(oldp, oldlenp, newp, newlen, &zfs_msg_buf_output_level);
		return error;
	case ZFS_SYSCTL_GET_DEBUGMSG_BUFSIZE:
		error = sysctl_rdint(oldp, oldlenp, newp, zfs_msg_buf_size);
		return error;
	case ZFS_SYSCTL_GET_DEBUGMSG:
		return zfs_get_debugmsg(oldp, oldlenp, newp);

	case ZFS_SYSCTL_CONFIG_DPRINTF:
		error = sysctl_int(oldp, oldlenp, newp, newlen, &zfs_dprintf_enabled);
		return error;

	case ZFS_SYSCTL_GET_CODE_COVERAGE_CHECK_INFO:
		return __ccc_get_coverage_info(oldp, oldlenp, newp);
	}

	return (ENOTSUP);
}

static int
zfs_vfs_quotactl(__unused struct mount *mp, __unused int cmds,
    __unused uid_t uid, __unused caddr_t datap, __unused vfs_context_t context)
{
	return (ENOTSUP);
}

static int
zfs_vfs_start(__unused struct mount *mp, __unused int flags,
    __unused vfs_context_t context)
{
	return (0);
}

int
zfs_module_start(void)
{
	struct vfs_fsentry vfe;

	zfs_init();

	printf("zfs_module_start: memory footprint %d (kalloc %d, kernel %d)\n",
		(int)zfs_footprint.current, (int)zfs_kallocmap_size, (int)zfs_kernelmap_size);

	vfe.vfe_vfsops = &zfs_vfsops_template;
	vfe.vfe_vopcnt = ZFS_VNOP_TBL_CNT;
	vfe.vfe_opvdescs = zfs_vnodeop_opv_desc_list;
	strlcpy(vfe.vfe_fsname, "zfs", sizeof(vfe.vfe_fsname));

	/*
	 * Report VFS features that we support.
	 */
	vfe.vfe_flags = VFS_TBLTHREADSAFE |
	                VFS_TBLNOTYPENUM |
	                VFS_TBLLOCALVOL |
	                VFS_TBL64BITREADY |
	                VFS_TBLNATIVEXATTR |
	                VFS_TBLVNOP_PAGEOUTV2|
			VFS_TBLREADDIR_EXTENDED;
	vfe.vfe_reserv[0] = 0;
	vfe.vfe_reserv[1] = 0;

	if (vfs_fsadd(&vfe, &zfs_vfsconf) != 0)
		return KERN_FAILURE;
	else
		return KERN_SUCCESS;
}

int  
zfs_module_stop(void)
{
	if (zfs_active_fs_count != 0 ||
	    spa_busy() ||
	    vfs_fsremove(zfs_vfsconf) != 0) {
		return KERN_FAILURE;   /* ZFS Still busy! */
	}
	zfs_fini();

	printf("zfs_module_stop: memory footprint %d (kalloc %d, kernel %d)\n",
		(int)zfs_footprint.current, (int)zfs_kallocmap_size, (int)zfs_kernelmap_size);

	return KERN_SUCCESS;
}

