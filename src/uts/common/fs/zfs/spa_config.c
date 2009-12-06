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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/spa.h>
#include <sys/spa_impl.h>
#include <sys/nvpair.h>
#include <sys/uio.h>
#include <sys/fs/zfs.h>
#include <sys/vdev_impl.h>
#include <sys/zfs_ioctl.h>
#include <sys/utsname.h>
#include <sys/systeminfo.h>
#include <sys/sunddi.h>
#ifdef _KERNEL
#include <sys/kobj.h>
#endif

/*
 * Pool configuration repository.
 *
 * Pool configuration is stored as a packed nvlist on the filesystem.  By
 * default, all pools are stored in /etc/zfs/zpool.cache and loaded on boot
 * (when the ZFS module is loaded).  Pools can also have the 'cachefile'
 * property set that allows them to be stored in an alternate location until
 * the control of external software.
 *
 * For each cache file, we have a single nvlist which holds all the
 * configuration information.  When the module loads, we read this information
 * from /etc/zfs/zpool.cache and populate the SPA namespace.  This namespace is
 * maintained independently in spa.c.  Whenever the namespace is modified, or
 * the configuration of a pool is changed, we call spa_config_sync(), which
 * walks through all the active pools and writes the configuration to disk.
 */

static uint64_t spa_config_generation = 1;

/*
 * This can be overridden in userland to preserve an alternate namespace for
 * userland pools when doing testing.
 */
const char *spa_config_path = ZPOOL_CACHE;

/*
 * Called when the module is first loaded, this routine loads the configuration
 * file into the SPA namespace.  It does not actually open or load the pools; it
 * only populates the namespace.
 */
void
spa_config_load(void)
{
	void *buf = NULL;
	nvlist_t *nvlist, *child;
	nvpair_t *nvpair;
	spa_t *spa;
	char pathname[128];
	struct _buf *file;
	uint64_t fsize;

	/*
	 * Open the configuration file.
	 */
#ifdef __APPLE__
	(void) snprintf(pathname, sizeof (pathname), "%s", spa_config_path);
#else
	(void) snprintf(pathname, sizeof (pathname), "%s%s",
	    (rootdir != NULL) ? "./" : "", spa_config_path);
#endif

	file = kobj_open_file(pathname);
	if (file == (struct _buf *)-1)
		return;

	if (kobj_get_filesize(file, &fsize) != 0)
		goto out;

	buf = kmem_alloc(fsize, KM_SLEEP);

	/*
	 * Read the nvlist from the file.
	 */
	if (kobj_read_file(file, buf, fsize, 0) < 0)
		goto out;

	/*
	 * Unpack the nvlist.
	 */
	if (nvlist_unpack(buf, fsize, &nvlist, KM_SLEEP) != 0)
		goto out;

	/*
	 * Iterate over all elements in the nvlist, creating a new spa_t for
	 * each one with the specified configuration.
	 */
	mutex_enter(&spa_namespace_lock);
	nvpair = NULL;
	while ((nvpair = nvlist_next_nvpair(nvlist, nvpair)) != NULL) {

		if (nvpair_type(nvpair) != DATA_TYPE_NVLIST)
			continue;

		VERIFY(nvpair_value_nvlist(nvpair, &child) == 0);

		if (spa_lookup(nvpair_name(nvpair)) != NULL)
			continue;
		spa = spa_add(nvpair_name(nvpair), NULL);

		/*
		 * We blindly duplicate the configuration here.  If it's
		 * invalid, we will catch it when the pool is first opened.
		 */
		VERIFY(nvlist_dup(child, &spa->spa_config, 0) == 0);
	}
	mutex_exit(&spa_namespace_lock);

	nvlist_free(nvlist);

out:
	if (buf != NULL)
		kmem_free(buf, fsize);

	kobj_close_file(file);
}

static void
spa_config_write(spa_config_dirent_t *dp, nvlist_t *nvl)
{
	size_t buflen;
	char *buf;
	vnode_t *vp;
	int oflags = FWRITE | FTRUNC | FCREAT | FOFFMAX;
	char tempname[128];

	/*
	 * If the nvlist is empty (NULL), then remove the old cachefile.
	 */
	if (nvl == NULL) {
		(void) vn_remove(dp->scd_path, UIO_SYSSPACE, RMFILE);
		return;
	}

	/*
	 * Pack the configuration into a buffer.
	 */
	VERIFY(nvlist_size(nvl, &buflen, NV_ENCODE_XDR) == 0);

	buf = kmem_alloc(buflen, KM_SLEEP);

	VERIFY(nvlist_pack(nvl, &buf, &buflen, NV_ENCODE_XDR,
	    KM_SLEEP) == 0);

#ifdef __APPLE_KERNEL__
	/*
	 * OS X - since vn_rename() and vn_remove() are both missing from
	 * the KPI, we have to just write over the existing file!  Since
	 * the OS X cache file only contains pools that are built from
	 * file VDEVs, this cache file should be small.
	 */
	(void) snprintf(tempname, sizeof (tempname), "%s", dp->scd_path);
#else
	/*
	 * Write the configuration to disk.  We need to do the traditional
	 * 'write to temporary file, sync, move over original' to make sure we
	 * always have a consistent view of the data.
	 */
	(void) snprintf(tempname, sizeof (tempname), "%s.tmp", dp->scd_path);
#endif

	if (vn_open(tempname, UIO_SYSSPACE, oflags, 0644, &vp, CRCREAT, 0) != 0)
		goto out;

	if (vn_rdwr(UIO_WRITE, vp, buf, buflen, 0, UIO_SYSSPACE,
	    0, RLIM64_INFINITY, kcred, NULL) == 0 &&
	    VOP_FSYNC(vp, FSYNC, kcred, NULL) == 0) {
		(void) vn_rename(tempname, dp->scd_path, UIO_SYSSPACE);
	}

	(void) VOP_CLOSE(vp, oflags, 1, 0, kcred, NULL);
#ifndef __APPLE__
	VN_RELE(vp);
#endif
out:
	(void) vn_remove(tempname, UIO_SYSSPACE, RMFILE);
	kmem_free(buf, buflen);
}

/*
 * Synchronize pool configuration to disk.  This must be called with the
 * namespace lock held.
 */
void
spa_config_sync(spa_t *target, boolean_t removing, boolean_t postsysevent)
{
	spa_t *spa = NULL;
	spa_config_dirent_t *dp, *tdp;
	nvlist_t *nvl;

	ASSERT(MUTEX_HELD(&spa_namespace_lock));

	/*
	 * Iterate over all cachefiles for the pool, past or present.  When the
	 * cachefile is changed, the new one is pushed onto this list, allowing
	 * us to update previous cachefiles that no longer contain this pool.
	 */
	for (dp = list_head(&target->spa_config_list); dp != NULL;
	    dp = list_next(&target->spa_config_list, dp)) {
		spa = NULL;
		if (dp->scd_path == NULL)
			continue;

		/*
		 * Iterate over all pools, adding any matching pools to 'nvl'.
		 */
		nvl = NULL;
		while ((spa = spa_next(spa)) != NULL) {
			if (spa->spa_config == NULL || spa->spa_name == NULL)
				continue;

			if (spa == target && removing)
				continue;

#ifdef __APPLE__
			/* OS X - Omit disk based pools */
			if (vdev_contains_disks(spa->spa_root_vdev))
				continue;
#endif
			tdp = list_head(&spa->spa_config_list);
			ASSERT(tdp != NULL);
			if (tdp->scd_path == NULL ||
			    strcmp(tdp->scd_path, dp->scd_path) != 0)
				continue;

			if (nvl == NULL)
				VERIFY(nvlist_alloc(&nvl, NV_UNIQUE_NAME,
				    KM_SLEEP) == 0);

			VERIFY(nvlist_add_nvlist(nvl, spa->spa_name,
			    spa->spa_config) == 0);
		}

		spa_config_write(dp, nvl);
		nvlist_free(nvl);
	}

	/*
	 * Remove any config entries older than the current one.
	 */
	dp = list_head(&target->spa_config_list);
	while ((tdp = list_next(&target->spa_config_list, dp)) != NULL) {
		list_remove(&target->spa_config_list, tdp);
		if (tdp->scd_path != NULL)
			spa_strfree(tdp->scd_path);
		kmem_free(tdp, sizeof (spa_config_dirent_t));
	}

	spa_config_generation++;

	if (postsysevent)
		spa_event_notify(target, NULL, ESC_ZFS_CONFIG_SYNC);
}

/*
 * Sigh.  Inside a local zone, we don't have access to /etc/zfs/zpool.cache,
 * and we don't want to allow the local zone to see all the pools anyway.
 * So we have to invent the ZFS_IOC_CONFIG ioctl to grab the configuration
 * information for all pool visible within the zone.
 */
nvlist_t *
spa_all_configs(uint64_t *generation)
{
	nvlist_t *pools;
	spa_t *spa;

	if (*generation == spa_config_generation)
		return (NULL);

	VERIFY(nvlist_alloc(&pools, NV_UNIQUE_NAME, KM_SLEEP) == 0);

	spa = NULL;
	mutex_enter(&spa_namespace_lock);
	while ((spa = spa_next(spa)) != NULL) {
#ifndef	__APPLE__
		if (INGLOBALZONE(curproc) ||
		    zone_dataset_visible(spa_name(spa), NULL)) {
#endif
			mutex_enter(&spa->spa_config_cache_lock);
			VERIFY(nvlist_add_nvlist(pools, spa_name(spa),
			    spa->spa_config) == 0);
			mutex_exit(&spa->spa_config_cache_lock);
#ifndef	__APPLE__
		}
#endif
	}
	mutex_exit(&spa_namespace_lock);

	*generation = spa_config_generation;

	return (pools);
}

void
spa_config_set(spa_t *spa, nvlist_t *config)
{
	mutex_enter(&spa->spa_config_cache_lock);
	if (spa->spa_config != NULL)
		nvlist_free(spa->spa_config);
	spa->spa_config = config;
	mutex_exit(&spa->spa_config_cache_lock);
}

/*
 * Generate the pool's configuration based on the current in-core state.
 * We infer whether to generate a complete config or just one top-level config
 * based on whether vd is the root vdev.
 */
nvlist_t *
spa_config_generate(spa_t *spa, vdev_t *vd, uint64_t txg, int getstats)
{
	nvlist_t *config, *nvroot;
	vdev_t *rvd = spa->spa_root_vdev;
	unsigned long hostid = 0;
#ifdef __APPLE__
	boolean_t skipdevpaths = (txg != -1ULL && txg != 0ULL);
#endif
	ASSERT(spa_config_held(spa, RW_READER) ||
	    spa_config_held(spa, RW_WRITER));

	if (vd == NULL)
		vd = rvd;

	/*
	 * If txg is -1, report the current value of spa->spa_config_txg.
	 */
	if (txg == -1ULL)
		txg = spa->spa_config_txg;

	VERIFY(nvlist_alloc(&config, NV_UNIQUE_NAME, KM_SLEEP) == 0);

	VERIFY(nvlist_add_uint64(config, ZPOOL_CONFIG_VERSION,
	    spa_version(spa)) == 0);
	VERIFY(nvlist_add_string(config, ZPOOL_CONFIG_POOL_NAME,
	    spa_name(spa)) == 0);
	VERIFY(nvlist_add_uint64(config, ZPOOL_CONFIG_POOL_STATE,
	    spa_state(spa)) == 0);
	VERIFY(nvlist_add_uint64(config, ZPOOL_CONFIG_POOL_TXG,
	    txg) == 0);
	VERIFY(nvlist_add_uint64(config, ZPOOL_CONFIG_POOL_GUID,
	    spa_guid(spa)) == 0);
#ifndef __APPLE__	
	(void) ddi_strtoul(hw_serial, NULL, 10, &hostid);
#endif
	if (hostid != 0) {
		VERIFY(nvlist_add_uint64(config, ZPOOL_CONFIG_HOSTID,
		    hostid) == 0);
	}
	/*XXX NOEL: If host id identification is a feature we are
	 * interested in having (primarily for poor man's cluster
	 * support), then query for the hostid here and add it to the
	 * nvlist
	 */
#ifndef __APPLE__
	VERIFY(nvlist_add_string(config, ZPOOL_CONFIG_HOSTNAME,
	    utsname.nodename) == 0);
#endif

	if (vd != rvd) {
		VERIFY(nvlist_add_uint64(config, ZPOOL_CONFIG_TOP_GUID,
		    vd->vdev_top->vdev_guid) == 0);
		VERIFY(nvlist_add_uint64(config, ZPOOL_CONFIG_GUID,
		    vd->vdev_guid) == 0);
		if (vd->vdev_isspare)
			VERIFY(nvlist_add_uint64(config, ZPOOL_CONFIG_IS_SPARE,
			    1ULL) == 0);
		if (vd->vdev_islog)
			VERIFY(nvlist_add_uint64(config, ZPOOL_CONFIG_IS_LOG,
			    1ULL) == 0);
		vd = vd->vdev_top;		/* label contains top config */
	}

#ifdef __APPLE__
	nvroot = vdev_config_generate(spa, vd, getstats, B_FALSE, B_FALSE,
	                              skipdevpaths);
#else
	nvroot = vdev_config_generate(spa, vd, getstats, B_FALSE, B_FALSE);
#endif
	VERIFY(nvlist_add_nvlist(config, ZPOOL_CONFIG_VDEV_TREE, nvroot) == 0);
	nvlist_free(nvroot);

	return (config);
}

/*
 * For a pool that's not currently a booting rootpool, update all disk labels,
 * generate a fresh config based on the current in-core state, and sync the
 * global config cache.
 */
void
spa_config_update(spa_t *spa, int what)
{
	spa_config_update_common(spa, what, FALSE);
}

/*
 * Update all disk labels, generate a fresh config based on the current
 * in-core state, and sync the global config cache (do not sync the config
 * cache if this is a booting rootpool).
 */
void
spa_config_update_common(spa_t *spa, int what, boolean_t isroot)
{
	vdev_t *rvd = spa->spa_root_vdev;
	uint64_t txg;
	int c;

	ASSERT(MUTEX_HELD(&spa_namespace_lock));

	spa_config_enter(spa, RW_WRITER, FTAG);
	txg = spa_last_synced_txg(spa) + 1;
	if (what == SPA_CONFIG_UPDATE_POOL) {
		vdev_config_dirty(rvd);
	} else {
		/*
		 * If we have top-level vdevs that were added but have
		 * not yet been prepared for allocation, do that now.
		 * (It's safe now because the config cache is up to date,
		 * so it will be able to translate the new DVAs.)
		 * See comments in spa_vdev_add() for full details.
		 */
		for (c = 0; c < rvd->vdev_children; c++) {
			vdev_t *tvd = rvd->vdev_child[c];
			if (tvd->vdev_ms_array == 0) {
				vdev_init(tvd, txg);
				vdev_config_dirty(tvd);
			}
		}
	}
	spa_config_exit(spa, FTAG);

	/*
	 * Wait for the mosconfig to be regenerated and synced.
	 */
	txg_wait_synced(spa->spa_dsl_pool, txg);

	/*
	 * Update the global config cache to reflect the new mosconfig.
	 */
	if (!isroot)
		spa_config_sync(spa, B_FALSE, what != SPA_CONFIG_UPDATE_POOL);

	if (what == SPA_CONFIG_UPDATE_POOL)
		spa_config_update_common(spa, SPA_CONFIG_UPDATE_VDEVS, isroot);
}