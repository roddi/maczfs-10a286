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
 *
 * Portions Copyright 2009 Apple Inc. All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/zfs_context.h>
#include <sys/spa.h>
#include <sys/vdev.h>
#include <sys/vdev_impl.h>
#include <sys/fs/zfs.h>
#include <sys/zio.h>

extern vdev_ops_t vdev_bdsdisk_ops;

#include "zfs_iomedia.h"

typedef zfs_iomedia_handle_t vdev_disk_t;

typedef zfs_iomedia_buf_t vdev_disk_buf_t;



static int
vdev_iomedia_open(vdev_t *vd, uint64_t *psize, uint64_t *ashift)
{
	vdev_disk_t *dvd = (vdev_disk_t *)vd->vdev_tsd;
	zfs_iomedia_info_t info;
	uint64_t blkcnt;
	uint32_t blksize;
	uint32_t features;
	int result;

	/*
	 * Note: for IOMedia vdevs, vdev_tsd is initialized during a pool import
	 */
	if (dvd == NULL) {
		/*
		 * Dynamically default back to BSD disk vdev
		 */
		result = vdev_bdsdisk_ops.vdev_op_open(vd, psize, ashift);
		if (result == 0)
			vd->vdev_ops = &vdev_bdsdisk_ops;
		return (result);
	}

	/*
	 * We must have a pathname, and it must be absolute.
	 */
	if (vd->vdev_path == NULL || vd->vdev_path[0] != '/') {
		vd->vdev_stat.vs_aux = VDEV_AUX_BAD_LABEL;
		printf("vdev_iomedia_open: no path! %s\n", vd->vdev_path ? vd->vdev_path : "");
		return (EINVAL);
	}

	/*
	 * Grab relevant device information.
	 */
	if (zfs_iomedia_getinfo(dvd, &info) != 0) {
		printf("vdev_iomedia_open: can't get info for %s\n", vd->vdev_path);
		return (EINVAL);
	}
	*psize = info.mi_mediasize;
	*ashift = highbit(MAX(info.mi_blocksize, SPA_MINBLOCKSIZE)) - 1;

	vd->vdev_fua = info.mi_forcedunitaccess ? B_TRUE : B_FALSE;
	vd->vdev_nowritecache = B_FALSE;

	return zfs_iomedia_open(dvd, spa_mode & FWRITE);
}

static void
vdev_iomedia_close(vdev_t *vd)
{
	vdev_disk_t *dvd = (vdev_disk_t *)vd->vdev_tsd;

	if (dvd == NULL) {
		printf("vdev_iomedia_close: missing vdev_tsd!\n");
		return;
	}

	zfs_iomedia_close(dvd);
}

static int
vdev_iomedia_ioctl(vdev_t *vd, zio_t *zio)
{
	vdev_disk_t *dvd = (vdev_disk_t *)vd->vdev_tsd;
	int error;

	if (dvd == NULL) {
		printf("vdev_iomedia_ioctl: missing vdev_tsd!\n");
		zio->io_error = ENXIO;
		return (ZIO_PIPELINE_CONTINUE);
	}

	zio_vdev_io_bypass(zio);

	if (!vdev_readable(vd)) {
		zio->io_error = ENXIO;
		return (ZIO_PIPELINE_CONTINUE);
	}

	switch (zio->io_cmd) {

	case DKIOCFLUSHWRITECACHE:
		if (zfs_nocacheflush || vd->vdev_fua)
			break;

		if (vd->vdev_nowritecache) {
			zio->io_error = ENOTSUP;
			break;
		}

		if ((error = zfs_iomedia_flushcache(dvd))) {
		
		if (error == 0) {
			zio->io_error = 0;
			zio_interrupt(zio);

			return (ZIO_PIPELINE_STOP);
		}
		if (error == ENOTSUP || error == ENOTTY)
			vd->vdev_nowritecache = B_TRUE;
		}
		zio->io_error = error;
		break;

	default:
		zio->io_error = ENOTSUP;
	}

	return (ZIO_PIPELINE_CONTINUE);
}

/*
 * Determine if the underlying device is accessible by reading and writing
 * to a known location. We must be able to do this during syncing context
 * and thus we cannot set the vdev state directly.
 */
static int
vdev_iomedia_probe(vdev_t *vd)
{
	return (0);
}

static void
vdev_iomedia_io_intr(vdev_disk_buf_t *vdb)
{
	zio_t *zio = (zio_t *)vdb->zmb_arg;

	if (vdb->zmb_error) {
		printf("vdev_iomedia_io_intr: err %d\n", vdb->zmb_error);
	}
	if ((zio->io_error = vdb->zmb_error) == 0 &&
	    vdb->zmb_actual != vdb->zmb_count) {
		zio->io_error = EIO;
	}
	kmem_free(vdb, sizeof (vdev_disk_buf_t));

	zio_interrupt(zio);
}

static int
vdev_iomedia_io_start(zio_t *zio)
{
	vdev_t *vd = zio->io_vd;
	vdev_disk_t *dvd = (vdev_disk_t *)vd->vdev_tsd;
	vdev_disk_buf_t *vdb;
	int error;

	if (zio->io_type == ZIO_TYPE_IOCTL) {
		return vdev_iomedia_ioctl(vd, zio);
	}

	if ((zio = vdev_queue_io(zio)) == NULL) {
		return (ZIO_PIPELINE_STOP);
	}
	if (zio->io_type == ZIO_TYPE_WRITE)
		error = vdev_writeable(vd) ? vdev_error_inject(vd, zio) : ENXIO;
	else
		error = vdev_readable(vd) ? vdev_error_inject(vd, zio) : ENXIO;
	error = (vd->vdev_remove_wanted || vd->vdev_is_failing) ? ENXIO : error;

	if (error) {
		zio->io_error = error;
		zio_interrupt(zio);
		return (ZIO_PIPELINE_STOP);
	}

	vdb = kmem_alloc(sizeof (vdev_disk_buf_t), KM_SLEEP);

	ASSERT(vdb != NULL);
	ASSERT(zio->io_data != NULL || zio->io_uplinfo != NULL);
	ASSERT(zio->io_size != 0);

	vdb->zmb_start = zio->io_offset;
	vdb->zmb_count = zio->io_size;
	vdb->zmb_actual = 0;
	
	if (zio->io_uplinfo) {
		sharedupl_t *supl = upli_sharedupl(zio->io_uplinfo);
		off_t off = zio->io_uplinfo->ui_f_off - supl->su_upl_f_off;

		vdb->zmb_upl = supl->su_upl;
		vdb->zmb_uploffset = off;
		vdb->zmb_has_upl = TRUE;
	} else {
		vdb->zmb_dataptr = zio->io_data;
		vdb->zmb_has_upl = FALSE;
	}
	vdb->zmb_handle = dvd;
	vdb->zmb_completion = (zfs_vdev_disk_iodone_t *)vdev_iomedia_io_intr;
	vdb->zmb_arg = zio;
	vdb->zmb_error = 0;
	vdb->zmb_readmedia =
	    (zio->io_type == ZIO_TYPE_READ) ? TRUE : FALSE;
	vdb->zmb_failfast = (zio->io_flags & ZIO_FLAG_FAILFAST);
	vdb->zmb_forceunitaccess =
	    ((zio->io_flags & ZIO_FLAG_FUA) && vd->vdev_fua);

	zfs_iomedia_strategy(vdb);

	return (ZIO_PIPELINE_STOP);
}

static int
vdev_iomedia_io_done(zio_t *zio)
{
	vdev_queue_io_done(zio);

	if (zio_injection_enabled && zio->io_error == 0)
		zio->io_error = zio_handle_device_injection(zio->io_vd, EIO);
#ifndef __APPLE__
	/*
	 * If the device returned EIO, then attempt a DKIOCSTATE ioctl to see if
	 * the device has been removed.  If this is the case, then we trigger an
	 * asynchronous removal of the device. Otherwise, probe the device and
	 * make sure it's still accessible.
	 */
	if (zio->io_error == EIO) {
		vdev_t *vd = zio->io_vd;
		vdev_disk_t *dvd = vd->vdev_tsd;
		int state;

		state = DKIO_NONE;
		if (dvd && ldi_ioctl(dvd->vd_lh, DKIOCSTATE, (intptr_t)&state,
		    FKIOCTL, kcred, NULL) == 0 &&
		    state != DKIO_INSERTED) {
			vd->vdev_remove_wanted = B_TRUE;
			spa_async_request(zio->io_spa, SPA_ASYNC_REMOVE);
		} else if (vdev_probe(vd) != 0) {
			ASSERT(vd->vdev_ops->vdev_op_leaf);
			if (!vd->vdev_is_failing) {
				vd->vdev_is_failing = B_TRUE;
				zfs_ereport_post(FM_EREPORT_ZFS_PROBE_FAILURE,
				    vd->vdev_spa, vd, zio, 0, 0);
			}
		}
	}
#endif

	return (ZIO_PIPELINE_CONTINUE);
}

vdev_ops_t vdev_disk_ops = {
	vdev_iomedia_open,
	vdev_iomedia_close,
	vdev_iomedia_probe,
	vdev_default_asize,
	vdev_iomedia_io_start,
	vdev_iomedia_io_done,
	NULL,
	VDEV_TYPE_DISK,		/* name of this vdev type */
	B_TRUE			/* leaf vdev */
};
