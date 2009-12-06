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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Portions Copyright 2007-2008 Apple Inc. All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Kernel task queues: general-purpose asynchronous task scheduling.
 *
 * A common problem in kernel programming is the need to schedule tasks
 * to be performed later, by another thread. There are several reasons
 * you may want or need to do this:
 *
 * (1) The task isn't time-critical, but your current code path is.
 *
 * (2) The task may require grabbing locks that you already hold.
 *
 * (3) The task may need to block (e.g. to wait for memory), but you
 *     cannot block in your current context.
 *
 * (4) Your code path can't complete because of some condition, but you can't
 *     sleep or fail, so you queue the task for later execution when condition
 *     disappears.
 *
 * (5) You just want a simple way to launch multiple tasks in parallel.
 *
 * Task queues provide such a facility. In its simplest form (used when
 * performance is not a critical consideration) a task queue consists of a
 * single list of tasks, together with one or more threads to service the
 * list. There are some cases when this simple queue is not sufficient:
 *
 * (1) The task queues are very hot and there is a need to avoid data and lock
 *	contention over global resources.
 *
 * (2) Some tasks may depend on other tasks to complete, so they can't be put in
 *	the same list managed by the same thread.
 *
 * (3) Some tasks may block for a long time, and this should not block other
 * 	tasks in the queue.
 *
 * To provide useful service in such cases we define a "dynamic task queue"
 * which has an individual thread for each of the tasks. These threads are
 * dynamically created as they are needed and destroyed when they are not in
 * use. The API for managing task pools is the same as for managing task queues
 * with the exception of a taskq creation flag TASKQ_DYNAMIC which tells that
 * dynamic task pool behavior is desired.
 *
 * Dynamic task queues may also place tasks in the normal queue (called "backing
 * queue") when task pool runs out of resources. Users of task queues may
 * disallow such queued scheduling by specifying TQ_NOQUEUE in the dispatch
 * flags.
 *
 * The backing task queue is also used for scheduling internal tasks needed for
 * dynamic task queue maintenance.
 *
 * INTERFACES:
 *
 * taskq_t *taskq_create(name, nthreads, pri_t pri, minalloc, maxall, flags);
 *
 *	Create a taskq with specified properties.
 *	Possible 'flags':
 *
 *	  TASKQ_DYNAMIC: Create task pool for task management. If this flag is
 * 		specified, 'nthreads' specifies the maximum number of threads in
 *		the task queue. Task execution order for dynamic task queues is
 *		not predictable.
 *
 *		If this flag is not specified (default case) a
 * 		single-list task queue is created with 'nthreads' threads
 * 		servicing it. Entries in this queue are managed by
 * 		taskq_ent_alloc() and taskq_ent_free() which try to keep the
 * 		task population between 'minalloc' and 'maxalloc', but the
 *		latter limit is only advisory for TQ_SLEEP dispatches and the
 *		former limit is only advisory for TQ_NOALLOC dispatches. If
 *		TASKQ_PREPOPULATE is set in 'flags', the taskq will be
 *		prepopulated with 'minalloc' task structures.
 *
 *		Since non-DYNAMIC taskqs are queues, tasks are guaranteed to be
 *		executed in the order they are scheduled if nthreads == 1.
 *		If nthreads > 1, task execution order is not predictable.
 *
 *	  TASKQ_PREPOPULATE: Prepopulate task queue with threads.
 *		Also prepopulate the task queue with 'minalloc' task structures.
 *
 *	The 'pri' field specifies the default priority for the threads that
 *	service all scheduled tasks.
 *
 * void taskq_destroy(tap):
 *
 *	Waits for any scheduled tasks to complete, then destroys the taskq.
 *	Caller should guarantee that no new tasks are scheduled in the closing
 *	taskq.
 *
 * taskqid_t taskq_dispatch(tq, func, arg, flags):
 *
 *	Dispatches the task "func(arg)" to taskq. The 'flags' indicates whether
 *	the caller is willing to block for memory.  The function returns an
 *	opaque value which is zero iff dispatch fails.  If flags is TQ_NOSLEEP
 *	or TQ_NOALLOC and the task can't be dispatched, taskq_dispatch() fails
 *	and returns (taskqid_t)0.
 *
 *	ASSUMES: func != NULL.
 *
 *	Possible flags:
 *	  TQ_NOSLEEP: Do not wait for resources; may fail.
 *
 *	  TQ_NOALLOC: Do not allocate memory; may fail.  May only be used with
 *		non-dynamic task queues.
 *
 *	  TQ_NOQUEUE: Do not enqueue a task if it can't dispatch it due to
 *		lack of available resources and fail. If this flag is not
 * 		set, and the task pool is exhausted, the task may be scheduled
 *		in the backing queue. This flag may ONLY be used with dynamic
 *		task queues.
 *
 *		NOTE: This flag should always be used when a task queue is used
 *		for tasks that may depend on each other for completion.
 *		Enqueueing dependent tasks may create deadlocks.
 *
 *	  TQ_SLEEP:   May block waiting for resources. May still fail for
 * 		dynamic task queues if TQ_NOQUEUE is also specified, otherwise
 *		always succeed.
 *
 *	NOTE: Dynamic task queues are much more likely to fail in
 *		taskq_dispatch() (especially if TQ_NOQUEUE was specified), so it
 *		is important to have backup strategies handling such failures.
 *
 * void taskq_wait(tq):
 *
 *	Waits for all previously scheduled tasks to complete.
 *
 *	NOTE: It does not stop any new task dispatches.
 *	      Do NOT call taskq_wait() from a task: it will cause deadlock.
 *
 * void taskq_suspend(tq)
 *
 *	Suspend all task execution. Tasks already scheduled for a dynamic task
 *	queue will still be executed, but all new scheduled tasks will be
 *	suspended until taskq_resume() is called.
 *
 * int  taskq_suspended(tq)
 *
 *	Returns 1 if taskq is suspended and 0 otherwise. It is intended to
 *	ASSERT that the task queue is suspended.
 *
 * void taskq_resume(tq)
 *
 *	Resume task queue execution.
 *
 * int  taskq_member(tq, thread)
 *
 *	Returns 1 if 'thread' belongs to taskq 'tq' and 0 otherwise. The
 *	intended use is to ASSERT that a given function is called in taskq
 *	context only.
 *
 *
 * IMPLEMENTATION.
 *
 * This is schematic representation of the task queue structures.
 *
 *   taskq:
 *   +-------------+
 *   |tq_lock      | +---< taskq_ent_free()
 *   +-------------+ |
 *   |...          | | tqent:                  tqent:
 *   +-------------+ | +------------+          +------------+
 *   | tq_freelist |-->| tqent_next |--> ... ->| tqent_next |
 *   +-------------+   +------------+          +------------+
 *   |...          |   | ...        |          | ...        |
 *   +-------------+   +------------+          +------------+
 *   | tq_task     |    |
 *   |             |    +-------------->taskq_ent_alloc()
 * +--------------------------------------------------------------------------+
 * | |                     |            tqent                   tqent         |
 * | +---------------------+     +--> +------------+     +--> +------------+  |
 * | | ...		   |     |    | func, arg  |     |    | func, arg  |  |
 * +>+---------------------+ <---|-+  +------------+ <---|-+  +------------+  |
 *   | tq_taskq.tqent_next | ----+ |  | tqent_next | --->+ |  | tqent_next |--+
 *   +---------------------+	   |  +------------+     ^ |  +------------+
 * +-| tq_task.tqent_prev  |	   +--| tqent_prev |     | +--| tqent_prev |  ^
 * | +---------------------+	      +------------+     |    +------------+  |
 * | |...		   |	      | ...        |     |    | ...        |  |
 * | +---------------------+	      +------------+     |    +------------+  |
 * |                                      ^              |                    |
 * |                                      |              |                    |
 * +--------------------------------------+--------------+       TQ_APPEND() -+
 *   |             |                      |
 *   |...          |   taskq_thread()-----+
 *   +-------------+
 *   | tq_buckets  |--+-------> [ NULL ] (for regular task queues)
 *   +-------------+  |
 *                    |   DYNAMIC TASK QUEUES:
 *                    |
 *                    +-> taskq_bucket[nCPU]       	taskq_bucket_dispatch()
 *                        +-------------------+                    ^
 *                   +--->| tqbucket_lock     |                    |
 *                   |    +-------------------+   +--------+      +--------+
 *                   |    | tqbucket_freelist |-->| tqent  |-->...| tqent  | ^
 *                   |    +-------------------+<--+--------+<--...+--------+ |
 *                   |    | ...               |   | thread |      | thread | |
 *                   |    +-------------------+   +--------+      +--------+ |
 *                   |    +-------------------+                              |
 * taskq_dispatch()--+--->| tqbucket_lock     |             TQ_APPEND()------+
 *      TQ_HASH()    |    +-------------------+   +--------+      +--------+
 *                   |    | tqbucket_freelist |-->| tqent  |-->...| tqent  |
 *                   |    +-------------------+<--+--------+<--...+--------+
 *                   |    | ...               |   | thread |      | thread |
 *                   |    +-------------------+   +--------+      +--------+
 *		     +---> 	...
 *
 *
 * Task queues use tq_task field to link new entry in the queue. The queue is a
 * circular doubly-linked list. Entries are put in the end of the list with
 * TQ_APPEND() and processed from the front of the list by taskq_thread() in
 * FIFO order. Task queue entries are cached in the free list managed by
 * taskq_ent_alloc() and taskq_ent_free() functions.
 *
 *	All threads used by task queues mark t_taskq field of the thread to
 *	point to the task queue.
 *
 * Dynamic Task Queues Implementation.
 *
 * For a dynamic task queues there is a 1-to-1 mapping between a thread and
 * taskq_ent_structure. Each entry is serviced by its own thread and each thread
 * is controlled by a single entry.
 *
 * Entries are distributed over a set of buckets. To avoid using modulo
 * arithmetics the number of buckets is 2^n and is determined as the nearest
 * power of two roundown of the number of CPUs in the system. Tunable
 * variable 'taskq_maxbuckets' limits the maximum number of buckets. Each entry
 * is attached to a bucket for its lifetime and can't migrate to other buckets.
 *
 * Entries that have scheduled tasks are not placed in any list. The dispatch
 * function sets their "func" and "arg" fields and signals the corresponding
 * thread to execute the task. Once the thread executes the task it clears the
 * "func" field and places an entry on the bucket cache of free entries pointed
 * by "tqbucket_freelist" field. ALL entries on the free list should have "func"
 * field equal to NULL. The free list is a circular doubly-linked list identical
 * in structure to the tq_task list above, but entries are taken from it in LIFO
 * order - the last freed entry is the first to be allocated. The
 * taskq_bucket_dispatch() function gets the most recently used entry from the
 * free list, sets its "func" and "arg" fields and signals a worker thread.
 *
 * After executing each task a per-entry thread taskq_d_thread() places its
 * entry on the bucket free list and goes to a timed sleep. If it wakes up
 * without getting new task it removes the entry from the free list and destroys
 * itself. The thread sleep time is controlled by a tunable variable
 * `taskq_thread_timeout'.
 *
 * There is various statistics kept in the bucket which allows for later
 * analysis of taskq usage patterns. Also, a global copy of taskq creation and
 * death statistics is kept in the global taskq data structure. Since thread
 * creation and death happen rarely, updating such global data does not present
 * a performance problem.
 *
 * NOTE: Threads are not bound to any CPU and there is absolutely no association
 *       between the bucket and actual thread CPU, so buckets are used only to
 *	 split resources and reduce resource contention. Having threads attached
 *	 to the CPU denoted by a bucket may reduce number of times the job
 *	 switches between CPUs.
 *
 *	 Current algorithm creates a thread whenever a bucket has no free
 *	 entries. It would be nice to know how many threads are in the running
 *	 state and don't create threads if all CPUs are busy with existing
 *	 tasks, but it is unclear how such strategy can be implemented.
 *
 *	 Currently buckets are created statically as an array attached to task
 *	 queue. On some system with nCPUs < max_ncpus it may waste system
 *	 memory. One solution may be allocation of buckets when they are first
 *	 touched, but it is not clear how useful it is.
 *
 * SUSPEND/RESUME implementation.
 *
 *	Before executing a task taskq_thread() (executing non-dynamic task
 *	queues) obtains taskq's thread lock as a reader. The taskq_suspend()
 *	function gets the same lock as a writer blocking all non-dynamic task
 *	execution. The taskq_resume() function releases the lock allowing
 *	taskq_thread to continue execution.
 *
 *	For dynamic task queues, each bucket is marked as TQBUCKET_SUSPEND by
 *	taskq_suspend() function. After that taskq_bucket_dispatch() always
 *	fails, so that taskq_dispatch() will either enqueue tasks for a
 *	suspended backing queue or fail if TQ_NOQUEUE is specified in dispatch
 *	flags.
 *
 *	NOTE: taskq_suspend() does not immediately block any tasks already
 *	      scheduled for dynamic task queues. It only suspends new tasks
 *	      scheduled after taskq_suspend() was called.
 *
 *	taskq_member() function works by comparing a thread t_taskq pointer with
 *	the passed thread pointer.
 *
 * LOCKS and LOCK Hierarchy:
 *
 *   There are two locks used in task queues.
 *
 *   1) Task queue structure has a lock, protecting global task queue state.
 *
 *   2) Each per-CPU bucket has a lock for bucket management.
 *
 *   If both locks are needed, task queue lock should be taken only after bucket
 *   lock.
 *
 * DEBUG FACILITIES.
 *
 * TUNABLES
 *
 *	taskq_thread_timeout	- Maximum idle time for taskq_d_thread()
 *				  Default value: 5 minutes
 *
 *	taskq_maxbuckets	- Maximum number of buckets in any task queue
 *				  Default value: 128
 *
 *	taskq_search_depth	- Maximum # of buckets searched for a free entry
 *				  Default value: 4
 *
 */

#include <sys/taskq_impl.h>
#include <sys/thread.h>
#include <sys/proc.h>
#include <sys/kmem.h>
#include <sys/vmem.h>
#include <sys/callb.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/vmsystm.h>	/* For throttlefree */
#include <sys/sysmacros.h>


static kmem_cache_t *taskq_ent_cache, *taskq_cache;


/*
 * Dynamic task queue threads that don't get any work within
 * taskq_thread_timeout destroy themselves
 */
#define	TASKQ_THREAD_TIMEOUT (60 * 5)
int taskq_thread_timeout = TASKQ_THREAD_TIMEOUT;

#define	TASKQ_MAXBUCKETS 128
int taskq_maxbuckets = TASKQ_MAXBUCKETS;

/*
 * When a bucket has no available entries another buckets are tried.
 * taskq_search_depth parameter limits the amount of buckets that we search
 * before failing. This is mostly useful in systems with many CPUs where we may
 * spend too much time scanning busy buckets.
 */
#define	TASKQ_SEARCH_DEPTH 4
int taskq_search_depth = TASKQ_SEARCH_DEPTH;

/*
 * Hashing function: mix various bits of x. May be pretty much anything.
 */
#define	TQ_HASH(x) ((x) ^ ((x) >> 11) ^ ((x) >> 17) ^ ((x) ^ 27))

/*
 * We do not create any new threads when the system is low on memory and start
 * throttling memory allocations. The following macro tries to estimate such
 * condition.
 */
#ifdef __APPLE__
/* XXX - TBD... */
#define	ENOUGH_MEMORY() (1)
#else
#define	ENOUGH_MEMORY() (freemem > throttlefree)
#endif

/*
 * Static functions.
 */
static taskq_t	*taskq_create_common(const char *, int, int, pri_t, int,
    int, uint_t);
static void taskq_thread(void *);
static void taskq_d_thread(taskq_ent_t *);
static void taskq_bucket_extend(void *);
static int  taskq_constructor(void *, void *, int);
static void taskq_destructor(void *, void *);
static int  taskq_ent_constructor(void *, void *, int);
static void taskq_ent_destructor(void *, void *);
static taskq_ent_t *taskq_ent_alloc(taskq_t *, int);
static void taskq_ent_free(taskq_t *, taskq_ent_t *);
static taskq_ent_t *taskq_bucket_dispatch(taskq_bucket_t *, task_func_t,
    void *);

/*
 * Task queue statistics and fault injection not used in Mac OS X
 */
#define	TQ_STAT(b, x)
#define	TASKQ_S_RANDOM_DISPATCH_FAILURE(tq, flag)
#define	TASKQ_D_RANDOM_DISPATCH_FAILURE(tq, flag)

#define	IS_EMPTY(l) (((l).tqent_prev == (l).tqent_next) &&	\
	((l).tqent_prev == &(l)))

/*
 * Append `tqe' in the end of the doubly-linked list denoted by l.
 */
#define	TQ_APPEND(l, tqe) {					\
	tqe->tqent_next = &l;					\
	tqe->tqent_prev = l.tqent_prev;				\
	tqe->tqent_next->tqent_prev = tqe;			\
	tqe->tqent_prev->tqent_next = tqe;			\
}

/*
 * Schedule a task specified by func and arg into the task queue entry tqe.
 */
#define	TQ_ENQUEUE(tq, tqe, func, arg) {			\
	TQ_APPEND(tq->tq_task, tqe);				\
	tqe->tqent_func = (func);				\
	tqe->tqent_arg = (arg);					\
	tq->tq_tasks++;						\
	if (tq->tq_tasks - tq->tq_executed > tq->tq_maxtasks)	\
		tq->tq_maxtasks = tq->tq_tasks - tq->tq_executed;	\
	cv_signal(&tq->tq_dispatch_cv);				\
	DTRACE_PROBE2(taskq__enqueue, taskq_t *, tq, taskq_ent_t *, tqe); \
}

/*
 * Do-nothing task which may be used to prepopulate thread caches.
 */
/*ARGSUSED*/
#ifndef __APPLE__
void
nulltask(void *unused)
{
}
#endif /*!__APPLE__*/

/*ARGSUSED*/
static int
taskq_constructor(void *buf, void *cdrarg, int kmflags)
{
	taskq_t *tq = buf;

	bzero(tq, sizeof (taskq_t));

	mutex_init(&tq->tq_lock, NULL, MUTEX_DEFAULT, NULL);
	rw_init(&tq->tq_threadlock, NULL, RW_DEFAULT, NULL);
	cv_init(&tq->tq_dispatch_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&tq->tq_wait_cv, NULL, CV_DEFAULT, NULL);

	tq->tq_task.tqent_next = &tq->tq_task;
	tq->tq_task.tqent_prev = &tq->tq_task;

	return (0);
}

/*ARGSUSED*/
static void
taskq_destructor(void *buf, void *cdrarg)
{
	taskq_t *tq = buf;

	mutex_destroy(&tq->tq_lock);
	rw_destroy(&tq->tq_threadlock);
	cv_destroy(&tq->tq_dispatch_cv);
	cv_destroy(&tq->tq_wait_cv);
}

/*ARGSUSED*/
static int
taskq_ent_constructor(void *buf, void *cdrarg, int kmflags)
{
	taskq_ent_t *tqe = buf;

	tqe->tqent_thread = NULL;
	cv_init(&tqe->tqent_cv, NULL, CV_DEFAULT, NULL);
#ifdef __APPLE__
	/* See comment in taskq_d_thread(). */
	mutex_init(&tqe->tqent_thread_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&tqe->tqent_thread_cv, NULL, CV_DEFAULT, NULL);
#endif /*__APPLE*/

	return (0);
}

/*ARGSUSED*/
static void
taskq_ent_destructor(void *buf, void *cdrarg)
{
	taskq_ent_t *tqe = buf;

	ASSERT(tqe->tqent_thread == NULL);
	cv_destroy(&tqe->tqent_cv);
#ifdef __APPLE__
	/* See comment in taskq_d_thread(). */
	mutex_destroy(&tqe->tqent_thread_lock);
	cv_destroy(&tqe->tqent_thread_cv);
#endif /*__APPLE*/
}

void
taskq_init(void)
{
	taskq_ent_cache = kmem_cache_create("taskq_ent_cache",
	    sizeof (taskq_ent_t), 0, taskq_ent_constructor,
	    taskq_ent_destructor, NULL, NULL, NULL, 0);

	taskq_cache = kmem_cache_create("taskq_cache", sizeof (taskq_t),
	    0, taskq_constructor, taskq_destructor, NULL, NULL, NULL, 0);
}

void
taskq_fini(void)
{
	if (taskq_cache) {
		kmem_cache_destroy(taskq_cache);
		taskq_cache = NULL;
	}
	if (taskq_ent_cache) {
		kmem_cache_destroy(taskq_ent_cache);
		taskq_ent_cache = NULL;
	}
}

/*
 * taskq_ent_alloc()
 *
 * Allocates a new taskq_ent_t structure either from the free list or from the
 * cache. Returns NULL if it can't be allocated.
 *
 * Assumes: tq->tq_lock is held.
 */
static taskq_ent_t *
taskq_ent_alloc(taskq_t *tq, int flags)
{
	int kmflags = (flags & TQ_NOSLEEP) ? KM_NOSLEEP : KM_SLEEP;

	taskq_ent_t *tqe;

	ASSERT(MUTEX_HELD(&tq->tq_lock));

	/*
	 * TQ_NOALLOC allocations are allowed to use the freelist, even if
	 * we are below tq_minalloc.
	 */
	if ((tqe = tq->tq_freelist) != NULL &&
	    ((flags & TQ_NOALLOC) || tq->tq_nalloc >= tq->tq_minalloc)) {
		tq->tq_freelist = tqe->tqent_next;
	} else {
		if (flags & TQ_NOALLOC)
			return (NULL);

		mutex_exit(&tq->tq_lock);
		if (tq->tq_nalloc >= tq->tq_maxalloc) {
			if (kmflags & KM_NOSLEEP) {
				mutex_enter(&tq->tq_lock);
				return (NULL);
			}
			/*
			 * We don't want to exceed tq_maxalloc, but we can't
			 * wait for other tasks to complete (and thus free up
			 * task structures) without risking deadlock with
			 * the caller.  So, we just delay for one second
			 * to throttle the allocation rate.
			 */
			delay(hz);
		}
		tqe = kmem_cache_alloc(taskq_ent_cache, kmflags);
		mutex_enter(&tq->tq_lock);
		if (tqe != NULL)
			tq->tq_nalloc++;
	}
	return (tqe);
}

/*
 * taskq_ent_free()
 *
 * Free taskq_ent_t structure by either putting it on the free list or freeing
 * it to the cache.
 *
 * Assumes: tq->tq_lock is held.
 */
static void
taskq_ent_free(taskq_t *tq, taskq_ent_t *tqe)
{
	ASSERT(MUTEX_HELD(&tq->tq_lock));

	if (tq->tq_nalloc <= tq->tq_minalloc) {
		tqe->tqent_next = tq->tq_freelist;
		tq->tq_freelist = tqe;
	} else {
		tq->tq_nalloc--;
		mutex_exit(&tq->tq_lock);
		kmem_cache_free(taskq_ent_cache, tqe);
		mutex_enter(&tq->tq_lock);
	}
}

/*
 * Dispatch a task "func(arg)" to a free entry of bucket b.
 *
 * Assumes: no bucket locks is held.
 *
 * Returns: a pointer to an entry if dispatch was successful.
 *	    NULL if there are no free entries or if the bucket is suspended.
 */
static taskq_ent_t *
taskq_bucket_dispatch(taskq_bucket_t *b, task_func_t func, void *arg)
{
	taskq_ent_t *tqe;

	ASSERT(MUTEX_NOT_HELD(&b->tqbucket_lock));
	ASSERT(func != NULL);

	mutex_enter(&b->tqbucket_lock);

	ASSERT(b->tqbucket_nfree != 0 || IS_EMPTY(b->tqbucket_freelist));
	ASSERT(b->tqbucket_nfree == 0 || !IS_EMPTY(b->tqbucket_freelist));

	/*
	 * Get en entry from the freelist if there is one.
	 * Schedule task into the entry.
	 */
	if ((b->tqbucket_nfree != 0) &&
	    !(b->tqbucket_flags & TQBUCKET_SUSPEND)) {
		tqe = b->tqbucket_freelist.tqent_prev;

		ASSERT(tqe != &b->tqbucket_freelist);
#ifndef __APPLE__
		ASSERT(tqe->tqent_thread != NULL);
#endif
		tqe->tqent_prev->tqent_next = tqe->tqent_next;
		tqe->tqent_next->tqent_prev = tqe->tqent_prev;
		b->tqbucket_nalloc++;
		b->tqbucket_nfree--;
		tqe->tqent_func = func;
		tqe->tqent_arg = arg;
		TQ_STAT(b, tqs_hits);
		cv_signal(&tqe->tqent_cv);
		DTRACE_PROBE2(taskq__d__enqueue, taskq_bucket_t *, b,
		    taskq_ent_t *, tqe);
	} else {
		tqe = NULL;
		TQ_STAT(b, tqs_misses);
	}
	mutex_exit(&b->tqbucket_lock);
	return (tqe);
}

/*
 * Dispatch a task.
 *
 * Assumes: func != NULL
 *
 * Returns: NULL if dispatch failed.
 *	    non-NULL if task dispatched successfully.
 *	    Actual return value is the pointer to taskq entry that was used to
 *	    dispatch a task. This is useful for debugging.
 */
/* ARGSUSED */
taskqid_t
taskq_dispatch(taskq_t *tq, task_func_t func, void *arg, uint_t flags)
{
	taskq_bucket_t *bucket = NULL;	/* Which bucket needs extension */
	taskq_ent_t *tqe = NULL;
	taskq_ent_t *tqe1;

	ASSERT(tq != NULL);
	ASSERT(func != NULL);

	if (!(tq->tq_flags & TASKQ_DYNAMIC)) {
		/*
		 * TQ_NOQUEUE flag can't be used with non-dynamic task queues.
		 */
		ASSERT(! (flags & TQ_NOQUEUE));
	/*
	 * Enqueue the task to the underlying queue.
	 */
	mutex_enter(&tq->tq_lock);

	TASKQ_S_RANDOM_DISPATCH_FAILURE(tq, flags);

	if ((tqe = taskq_ent_alloc(tq, flags)) == NULL) {
		mutex_exit(&tq->tq_lock);
		return ((taskqid_t)NULL);
	}
		TQ_ENQUEUE(tq, tqe, func, arg);
		mutex_exit(&tq->tq_lock);
		return ((taskqid_t)tqe);
	}

	/*
	 * Dynamic taskq dispatching.
	 */
	ASSERT(!(flags & TQ_NOALLOC));
	TASKQ_D_RANDOM_DISPATCH_FAILURE(tq, flags);

	if ((tqe = taskq_bucket_dispatch(tq->tq_buckets, func, arg)) != NULL)
		return ((taskqid_t)tqe);	/* Fastpath */
	bucket = tq->tq_buckets;

	/*
	 * At this point we either scheduled a task and (tqe != NULL) or failed
	 * (tqe == NULL). Try to recover from fails.
	 */

	/*
	 * For KM_SLEEP dispatches, try to extend the bucket and retry dispatch.
	 */
	if ((tqe == NULL) && !(flags & TQ_NOSLEEP)) {
		/*
		 * taskq_bucket_extend() may fail to do anything, but this is
		 * fine - we deal with it later. If the bucket was successfully
		 * extended, there is a good chance that taskq_bucket_dispatch()
		 * will get this new entry, unless someone is racing with us and
		 * stealing the new entry from under our nose.
		 * taskq_bucket_extend() may sleep.
		 */
		taskq_bucket_extend(bucket);
		TQ_STAT(bucket, tqs_disptcreates);
		if ((tqe = taskq_bucket_dispatch(bucket, func, arg)) != NULL)
			return ((taskqid_t)tqe);
	}

	ASSERT(bucket != NULL);
	/*
	 * Since there are not enough free entries in the bucket, extend it
	 * in the background using backing queue.
	 */
	mutex_enter(&tq->tq_lock);
	if ((tqe1 = taskq_ent_alloc(tq, TQ_NOSLEEP)) != NULL) {
		TQ_ENQUEUE(tq, tqe1, taskq_bucket_extend,
		    bucket);
	} else {
		TQ_STAT(bucket, tqs_nomem);
	}

	/*
	 * Dispatch failed and we can't find an entry to schedule a task.
	 * Revert to the backing queue unless TQ_NOQUEUE was asked.
	 */
	if ((tqe == NULL) && !(flags & TQ_NOQUEUE)) {
		if ((tqe = taskq_ent_alloc(tq, flags)) != NULL) {
			TQ_ENQUEUE(tq, tqe, func, arg);
		} else {
			TQ_STAT(bucket, tqs_nomem);
		}
	}
	mutex_exit(&tq->tq_lock);

	return ((taskqid_t)tqe);
}

/*
 * Wait for all pending tasks to complete.
 * Calling taskq_wait from a task will cause deadlock.
 */
void
taskq_wait(taskq_t *tq)
{
	mutex_enter(&tq->tq_lock);
	while (tq->tq_task.tqent_next != &tq->tq_task || tq->tq_active != 0)
		cv_wait(&tq->tq_wait_cv, &tq->tq_lock);
	mutex_exit(&tq->tq_lock);

	if (tq->tq_flags & TASKQ_DYNAMIC) {
		taskq_bucket_t *b = tq->tq_buckets;
		int bid = 0;
		for (; (b != NULL) && (bid < tq->tq_nbuckets); b++, bid++) {
			mutex_enter(&b->tqbucket_lock);
			while (b->tqbucket_nalloc > 0)
				cv_wait(&b->tqbucket_cv, &b->tqbucket_lock);
			mutex_exit(&b->tqbucket_lock);
		}
	}
}

/*
 * Suspend execution of tasks.
 *
 * Tasks in the queue part will be suspended immediately upon return from this
 * function. Pending tasks in the dynamic part will continue to execute, but all
 * new tasks will  be suspended.
 */
void
taskq_suspend(taskq_t *tq)
{
	rw_enter(&tq->tq_threadlock, RW_WRITER);

	if (tq->tq_flags & TASKQ_DYNAMIC) {
		taskq_bucket_t *b = tq->tq_buckets;
		int bid = 0;
		for (; (b != NULL) && (bid < tq->tq_nbuckets); b++, bid++) {
			mutex_enter(&b->tqbucket_lock);
			b->tqbucket_flags |= TQBUCKET_SUSPEND;
			mutex_exit(&b->tqbucket_lock);
		}
	}
	/*
	 * Mark task queue as being suspended. Needed for taskq_suspended().
	 */
	mutex_enter(&tq->tq_lock);
	ASSERT(!(tq->tq_flags & TASKQ_SUSPENDED));
	tq->tq_flags |= TASKQ_SUSPENDED;
	mutex_exit(&tq->tq_lock);
}

/*
 * returns: 1 if tq is suspended, 0 otherwise.
 */
int
taskq_suspended(taskq_t *tq)
{
	return ((tq->tq_flags & TASKQ_SUSPENDED) != 0);
}

/*
 * Resume taskq execution.
 */
void
taskq_resume(taskq_t *tq)
{
	ASSERT(RW_WRITE_HELD(&tq->tq_threadlock));

	if (tq->tq_flags & TASKQ_DYNAMIC) {
		taskq_bucket_t *b = tq->tq_buckets;
		int bid = 0;
		for (; (b != NULL) && (bid < tq->tq_nbuckets); b++, bid++) {
			mutex_enter(&b->tqbucket_lock);
			b->tqbucket_flags &= ~TQBUCKET_SUSPEND;
			mutex_exit(&b->tqbucket_lock);
		}
	}
	mutex_enter(&tq->tq_lock);
	ASSERT(tq->tq_flags & TASKQ_SUSPENDED);
	tq->tq_flags &= ~TASKQ_SUSPENDED;
	mutex_exit(&tq->tq_lock);

	rw_exit(&tq->tq_threadlock);
}

int
taskq_member(taskq_t *tq, kthread_t *thread)
{
#ifdef __APPLE__
	/* XXX - TBD... */
	return (1);
#else
	return (thread->t_taskq == tq);
#endif
}

/*
 * Worker thread for processing task queue.
 */
static void
taskq_thread(void *arg)
{
	taskq_t *tq = arg;
	taskq_ent_t *tqe;
	callb_cpr_t cprinfo;
	hrtime_t start, end;

	CALLB_CPR_INIT(&cprinfo, &tq->tq_lock, callb_generic_cpr,  tq->tq_name);
	mutex_enter(&tq->tq_lock);
	while (tq->tq_flags & TASKQ_ACTIVE) {
		if ((tqe = tq->tq_task.tqent_next) == &tq->tq_task) {
			if (--tq->tq_active == 0)
				cv_broadcast(&tq->tq_wait_cv);
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			cv_wait(&tq->tq_dispatch_cv, &tq->tq_lock);
			CALLB_CPR_SAFE_END(&cprinfo, &tq->tq_lock);
			tq->tq_active++;
			continue;
		}
		tqe->tqent_prev->tqent_next = tqe->tqent_next;
		tqe->tqent_next->tqent_prev = tqe->tqent_prev;
		mutex_exit(&tq->tq_lock);

		rw_enter(&tq->tq_threadlock, RW_READER);
		start = gethrtime();
		DTRACE_PROBE2(taskq__exec__start, taskq_t *, tq,
		    taskq_ent_t *, tqe);
		tqe->tqent_func(tqe->tqent_arg);
		DTRACE_PROBE2(taskq__exec__end, taskq_t *, tq,
		    taskq_ent_t *, tqe);
		end = gethrtime();
		rw_exit(&tq->tq_threadlock);

		mutex_enter(&tq->tq_lock);
		tq->tq_totaltime += end - start;
		tq->tq_executed++;

		taskq_ent_free(tq, tqe);
	}
	tq->tq_nthreads--;
	cv_broadcast(&tq->tq_wait_cv);
	ASSERT(!(tq->tq_flags & TASKQ_CPR_SAFE));
	CALLB_CPR_EXIT(&cprinfo);
	thread_exit();
}

/*
 * Worker per-entry thread for dynamic dispatches.
 */
static void
taskq_d_thread(taskq_ent_t *tqe)
{
	taskq_bucket_t	*bucket = tqe->tqent_bucket;
	taskq_t		*tq = bucket->tqbucket_taskq;
	kmutex_t	*lock = &bucket->tqbucket_lock;
	kcondvar_t	*cv = &tqe->tqent_cv;
	callb_cpr_t	cprinfo;
	clock_t		w;

	CALLB_CPR_INIT(&cprinfo, lock, callb_generic_cpr, tq->tq_name);

#ifdef __APPLE__
	/*
	 * There's no way in Mac OS X KPI to create a thread
	 * in a suspended state (TS_STOPPED). So instead we
	 * use tqent_thread as a flag and wait for it to get
	 * initialized.
	 */
	mutex_enter(&tqe->tqent_thread_lock);
	while (tqe->tqent_thread == (kthread_t *)0xCEDEC0DE)
		cv_wait(&tqe->tqent_thread_cv, &tqe->tqent_thread_lock);
	mutex_exit(&tqe->tqent_thread_lock);
#endif
	mutex_enter(lock);

	for (;;) {
		/*
		 * If a task is scheduled (func != NULL), execute it, otherwise
		 * sleep, waiting for a job.
		 */
		if (tqe->tqent_func != NULL) {
			hrtime_t	start;
			hrtime_t	end;

			ASSERT(bucket->tqbucket_nalloc > 0);

			/*
			 * It is possible to free the entry right away before
			 * actually executing the task so that subsequent
			 * dispatches may immediately reuse it. But this,
			 * effectively, creates a two-length queue in the entry
			 * and may lead to a deadlock if the execution of the
			 * current task depends on the execution of the next
			 * scheduled task. So, we keep the entry busy until the
			 * task is processed.
			 */

			mutex_exit(lock);
			start = gethrtime();
			DTRACE_PROBE3(taskq__d__exec__start, taskq_t *, tq,
			    taskq_bucket_t *, bucket, taskq_ent_t *, tqe);
			tqe->tqent_func(tqe->tqent_arg);
			DTRACE_PROBE3(taskq__d__exec__end, taskq_t *, tq,
			    taskq_bucket_t *, bucket, taskq_ent_t *, tqe);
			end = gethrtime();
			mutex_enter(lock);
			bucket->tqbucket_totaltime += end - start;

			/*
			 * Return the entry to the bucket free list.
			 */
			tqe->tqent_func = NULL;
			TQ_APPEND(bucket->tqbucket_freelist, tqe);
			bucket->tqbucket_nalloc--;
			bucket->tqbucket_nfree++;
			ASSERT(!IS_EMPTY(bucket->tqbucket_freelist));
			/*
			 * taskq_wait() waits for nalloc to drop to zero on
			 * tqbucket_cv.
			 */
			cv_signal(&bucket->tqbucket_cv);
		}

		/*
		 * At this point the entry must be in the bucket free list -
		 * either because it was there initially or because it just
		 * finished executing a task and put itself on the free list.
		 */
		ASSERT(bucket->tqbucket_nfree > 0);
		/*
		 * Go to sleep unless we are closing.
		 * If a thread is sleeping too long, it dies.
		 */
		if (! (bucket->tqbucket_flags & TQBUCKET_CLOSE)) {
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			w = cv_timedwait(cv, lock, lbolt +
			    taskq_thread_timeout * hz);
			CALLB_CPR_SAFE_END(&cprinfo, lock);
		}

		/*
		 * At this point we may be in two different states:
		 *
		 * (1) tqent_func is set which means that a new task is
		 *	dispatched and we need to execute it.
		 *
		 * (2) Thread is sleeping for too long or we are closing. In
		 *	both cases destroy the thread and the entry.
		 */

		/* If func is NULL we should be on the freelist. */
		ASSERT((tqe->tqent_func != NULL) ||
		    (bucket->tqbucket_nfree > 0));
		/* If func is non-NULL we should be allocated */
		ASSERT((tqe->tqent_func == NULL) ||
		    (bucket->tqbucket_nalloc > 0));

		/* Check freelist consistency */
		ASSERT((bucket->tqbucket_nfree > 0) ||
		    IS_EMPTY(bucket->tqbucket_freelist));
		ASSERT((bucket->tqbucket_nfree == 0) ||
		    !IS_EMPTY(bucket->tqbucket_freelist));

		if ((tqe->tqent_func == NULL) &&
		    ((w == -1) || (bucket->tqbucket_flags & TQBUCKET_CLOSE))) {
			/*
			 * This thread is sleeping for too long or we are
			 * closing - time to die.
			 * Thread creation/destruction happens rarely,
			 * so grabbing the lock is not a big performance issue.
			 * The bucket lock is dropped by CALLB_CPR_EXIT().
			 */

			/* Remove the entry from the free list. */
			tqe->tqent_prev->tqent_next = tqe->tqent_next;
			tqe->tqent_next->tqent_prev = tqe->tqent_prev;
			ASSERT(bucket->tqbucket_nfree > 0);
			bucket->tqbucket_nfree--;

			TQ_STAT(bucket, tqs_tdeaths);
			cv_signal(&bucket->tqbucket_cv);
			tqe->tqent_thread = NULL;
			mutex_enter(&tq->tq_lock);
			tq->tq_tdeaths++;
			mutex_exit(&tq->tq_lock);
			CALLB_CPR_EXIT(&cprinfo);
			kmem_cache_free(taskq_ent_cache, tqe);
			thread_exit();
		}
	}
}


/*
 * Taskq creation. May sleep for memory.
 * Always use automatically generated instances to avoid kstat name space
 * collisions.
 */

taskq_t *
taskq_create(const char *name, int nthreads, pri_t pri, int minalloc,
    int maxalloc, uint_t flags)
{
	taskq_t *tq = kmem_cache_alloc(taskq_cache, KM_SLEEP);
	uint_t bsize;	/* # of buckets - always power of 2 */

	ASSERT(tq->tq_buckets == NULL);

	bsize = 1;

	tq->tq_maxsize = nthreads;

#ifdef __APPLE__
	/*
	 * On Mac OS X, use a dynamic task queue instead of
	 * pre allocating multiple threads.
	 */
	if ((nthreads > 1) && (flags & TASKQ_PREPOPULATE)) {
		flags &= ~TASKQ_PREPOPULATE;
		flags |= TASKQ_DYNAMIC;
	}
#endif
	/* For dynamic task queues use just one backup thread */
	if (flags & TASKQ_DYNAMIC)
		nthreads = 1;

	(void) strncpy(tq->tq_name, name, TASKQ_NAMELEN + 1);
	tq->tq_name[TASKQ_NAMELEN] = '\0';

	tq->tq_flags = flags | TASKQ_ACTIVE;
	tq->tq_active = nthreads;
	tq->tq_nthreads = nthreads;
	tq->tq_minalloc = minalloc;
	tq->tq_maxalloc = maxalloc;
	tq->tq_nbuckets = bsize;
	tq->tq_pri = pri;

	if (flags & TASKQ_PREPOPULATE) {
		mutex_enter(&tq->tq_lock);
		while (minalloc-- > 0)
			taskq_ent_free(tq, taskq_ent_alloc(tq, TQ_SLEEP));
		mutex_exit(&tq->tq_lock);
	}

	if (nthreads == 1) {
		tq->tq_thread = thread_create(NULL, 0, taskq_thread, tq,
		    0, &p0, TS_RUN, pri);
		/*
		 * No need to take thread_lock to change the field: no one can
		 * reference it at this point.
		 */
#ifndef __APPLE__
		tq->tq_thread->t_taskq = tq;
#endif
	} else {
		kthread_t **tpp = kmem_alloc(sizeof (kthread_t *) * nthreads,
		    KM_SLEEP);

		tq->tq_threadlist = tpp;

		mutex_enter(&tq->tq_lock);
		while (nthreads-- > 0) {
			*tpp = thread_create(NULL, 0, taskq_thread, tq,
			    0, &p0, TS_RUN, pri);
#ifndef __APPLE__
			(*tpp)->t_taskq = tq;
#endif
			tpp++;
		}
		mutex_exit(&tq->tq_lock);
	}

	if (flags & TASKQ_DYNAMIC) {
		taskq_bucket_t *bucket = kmem_zalloc(sizeof (taskq_bucket_t) *
		    bsize, KM_SLEEP);
		int b_id;

		tq->tq_buckets = bucket;

		/* Initialize each bucket */
		for (b_id = 0; b_id < bsize; b_id++, bucket++) {
			mutex_init(&bucket->tqbucket_lock, NULL, MUTEX_DEFAULT,
			    NULL);
			cv_init(&bucket->tqbucket_cv, NULL, CV_DEFAULT, NULL);
			bucket->tqbucket_taskq = tq;
			bucket->tqbucket_freelist.tqent_next =
			    bucket->tqbucket_freelist.tqent_prev =
			    &bucket->tqbucket_freelist;
			if (flags & TASKQ_PREPOPULATE)
				taskq_bucket_extend(bucket);
		}
	}

	/* Note: kstats currently not used for Mac OS X */

	return (tq);
}

/*
 * taskq_destroy().
 *
 * Assumes: by the time taskq_destroy is called no one will use this task queue
 * in any way and no one will try to dispatch entries in it.
 */
void
taskq_destroy(taskq_t *tq)
{
	taskq_bucket_t *b = tq->tq_buckets;
	int bid = 0;

	/* Note: kstats currently not used for Mac OS X */

	/*
	 * Wait for any pending entries to complete.
	 */
	taskq_wait(tq);

	mutex_enter(&tq->tq_lock);
	ASSERT((tq->tq_task.tqent_next == &tq->tq_task) &&
	    (tq->tq_active == 0));

	if ((tq->tq_nthreads > 1) && (tq->tq_threadlist != NULL))
		kmem_free(tq->tq_threadlist, sizeof (kthread_t *) *
		    tq->tq_nthreads);

	tq->tq_flags &= ~TASKQ_ACTIVE;
	cv_broadcast(&tq->tq_dispatch_cv);
	while (tq->tq_nthreads != 0)
		cv_wait(&tq->tq_wait_cv, &tq->tq_lock);

	tq->tq_minalloc = 0;
	while (tq->tq_nalloc != 0)
		taskq_ent_free(tq, taskq_ent_alloc(tq, TQ_SLEEP));

	mutex_exit(&tq->tq_lock);

	/*
	 * Mark each bucket as closing and wakeup all sleeping threads.
	 */
	for (; (b != NULL) && (bid < tq->tq_nbuckets); b++, bid++) {
		taskq_ent_t *tqe;

		mutex_enter(&b->tqbucket_lock);

		b->tqbucket_flags |= TQBUCKET_CLOSE;
		/* Wakeup all sleeping threads */

		for (tqe = b->tqbucket_freelist.tqent_next;
		    tqe != &b->tqbucket_freelist; tqe = tqe->tqent_next)
			cv_signal(&tqe->tqent_cv);

		ASSERT(b->tqbucket_nalloc == 0);

		/*
		 * At this point we waited for all pending jobs to complete (in
		 * both the task queue and the bucket and no new jobs should
		 * arrive. Wait for all threads to die.
		 */
		while (b->tqbucket_nfree > 0)
			cv_wait(&b->tqbucket_cv, &b->tqbucket_lock);
		mutex_exit(&b->tqbucket_lock);
		mutex_destroy(&b->tqbucket_lock);
		cv_destroy(&b->tqbucket_cv);
	}

	if (tq->tq_buckets != NULL) {
		ASSERT(tq->tq_flags & TASKQ_DYNAMIC);
		kmem_free(tq->tq_buckets,
		    sizeof (taskq_bucket_t) * tq->tq_nbuckets);

		/* Cleanup fields before returning tq to the cache */
		tq->tq_buckets = NULL;
		tq->tq_tcreates = 0;
		tq->tq_tdeaths = 0;
	} else {
		ASSERT(!(tq->tq_flags & TASKQ_DYNAMIC));
	}

	tq->tq_totaltime = 0;
	tq->tq_tasks = 0;
	tq->tq_maxtasks = 0;
	tq->tq_executed = 0;
	kmem_cache_free(taskq_cache, tq);
}

/*
 * Extend a bucket with a new entry on the free list and attach a worker thread
 * to it.
 *
 * Argument: pointer to the bucket.
 *
 * This function may quietly fail. It is only used by taskq_dispatch() which
 * handles such failures properly.
 */
static void
taskq_bucket_extend(void *arg)
{
	taskq_ent_t *tqe;
	taskq_bucket_t *b = (taskq_bucket_t *)arg;
	taskq_t *tq = b->tqbucket_taskq;
	int nthreads;
#ifdef __APPLE__
	kthread_t *thread;
#endif
	if (! ENOUGH_MEMORY()) {
		TQ_STAT(b, tqs_nomem);
		return;
	}

	mutex_enter(&tq->tq_lock);

	/*
	 * Observe global taskq limits on the number of threads.
	 */
	if (tq->tq_tcreates++ - tq->tq_tdeaths > tq->tq_maxsize) {
		tq->tq_tcreates--;
		mutex_exit(&tq->tq_lock);
		return;
	}
	mutex_exit(&tq->tq_lock);

	tqe = kmem_cache_alloc(taskq_ent_cache, KM_NOSLEEP);

	if (tqe == NULL) {
		mutex_enter(&tq->tq_lock);
		TQ_STAT(b, tqs_nomem);
		tq->tq_tcreates--;
		mutex_exit(&tq->tq_lock);
		return;
	}

	ASSERT(tqe->tqent_thread == NULL);

	tqe->tqent_bucket = b;

#ifdef __APPLE__
	/*
	 * There's no way in Mac OS X KPI to create a thread
	 * in a suspended state (TS_STOPPED). So instead we
	 * use tqent_thread as a flag and the thread must wait
	 * for it to be initialized (below).
	 */
	tqe->tqent_thread = (kthread_t *)0xCEDEC0DE;
	thread = thread_create(NULL, 0, taskq_d_thread, tqe, 0, &p0, TS_RUN,
	                       tq->tq_pri);
#else
	/*
	 * Create a thread in a TS_STOPPED state first. If it is successfully
	 * created, place the entry on the free list and start the thread.
	 */
	tqe->tqent_thread = thread_create(NULL, 0, taskq_d_thread, tqe,
	    0, &p0, TS_STOPPED, tq->tq_pri);
#endif /*__APPLE__*/

	/*
	 * Once the entry is ready, link it to the the bucket free list.
	 */
	mutex_enter(&b->tqbucket_lock);
	tqe->tqent_func = NULL;
	TQ_APPEND(b->tqbucket_freelist, tqe);
	b->tqbucket_nfree++;
	TQ_STAT(b, tqs_tcreates);

	mutex_exit(&b->tqbucket_lock);
	/*
	 * Start the stopped thread.
	 */
#ifdef __APPLE__
	mutex_enter(&tqe->tqent_thread_lock);
	tqe->tqent_thread = thread;
	cv_signal(&tqe->tqent_thread_cv);
	mutex_exit(&tqe->tqent_thread_lock);
#else
	thread_lock(tqe->tqent_thread);
	tqe->tqent_thread->t_taskq = tq;
	tqe->tqent_thread->t_schedflag |= TS_ALLSTART;
	setrun_locked(tqe->tqent_thread);
	thread_unlock(tqe->tqent_thread);
#endif /*__APPLE__*/
}


