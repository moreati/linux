/*-
 * Copyright (c) 2015 Nuxi, https://nuxi.nl/
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <linux/list.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/wait.h>

#include <asm/futex.h>
#include <asm/uaccess.h>

#include "cloudabi_syscalldefs.h"
#include "cloudabi_syscalls.h"
#include "cloudabi_util.h"

/*
 * Futexes for CloudABI.
 *
 * On most systems, futexes are implemented as objects of a single type
 * on which a set of operations can be performed. CloudABI makes a clear
 * distinction between locks and condition variables. A lock may have
 * zero or more associated condition variables. A condition variable is
 * always associated with exactly one lock. There is a strict topology.
 * This approach has two advantages:
 *
 * - This topology is guaranteed to be acyclic. Requeueing of threads
 *   only happens in one direction (from condition variables to locks).
 *   This eases locking.
 * - It means that a futex object for a lock exists when it is unlocked,
 *   but has threads waiting on associated condition variables. Threads
 *   can be requeued to a lock even if the thread performing the wakeup
 *   does not have the lock mapped in its address space.
 *
 * This futex implementation only implements a single lock type, namely
 * a read-write lock. A regular mutex type would not be necessary, as
 * the read-write lock is as efficient as a mutex if used as such.
 * Userspace futex locks are 32 bits in size:
 *
 * - 1 bit: has threads waiting in kernel-space.
 * - 1 bit: is write-locked.
 * - 30 bits:
 *   - if write-locked: thread ID of owner.
 *   - if not write-locked: number of read locks held.
 *
 * Condition variables are also 32 bits in size. Its value is modified
 * by kernel-space exclusively. Zero indicates that it has no waiting
 * threads. Non-zero indicates the opposite.
 *
 * This implementation is optimal, in the sense that it only wakes up
 * threads if they can actually continue execution. It does not suffer
 * from the thundering herd problem. If multiple threads waiting on a
 * condition variable need to be woken up, only a single thread is
 * scheduled. All other threads are 'donated' to this thread. After the
 * thread manages to reacquire the lock, it requeues its donated threads
 * to the lock.
 *
 * TODO(ed): Store futex objects in a hash table.
 * TODO(ed): Add actual priority inheritance.
 * TODO(ed): Let futex_queue also take priorities into account.
 * TODO(ed): Make locking fine-grained.
 * TODO(ed): Optimize non-pshared locks.
 */

struct futex_address;
struct futex_condvar;
struct futex_lock;
struct futex_queue;
struct futex_waiter;

/* Identifier of a location in memory. */
/* TODO(ed): Make this work with shared mutexes. */
struct futex_address {
	struct mm_struct *		fa_mm;
	const void *			fa_object;
};

/* A set of waiting threads. */
struct futex_queue {
	struct list_head		fq_list;
	unsigned int			fq_count;
};

/* Condition variables. */
struct futex_condvar {
	/* Address of the condition variable. */
	struct futex_address		fc_address;

	/* The lock the waiters should be moved to when signalled. */
	struct futex_lock *		fc_lock;

	/* Threads waiting on the condition variable. */
	struct futex_queue		fc_waiters;
	/*
	 * Number of threads blocked on this condition variable, or
	 * being blocked on the lock after being requeued.
	 */
	unsigned int			fc_waitcount;

	/* Global list pointers. */
	struct list_head		fc_next;
};

/* Read-write locks. */
struct futex_lock {
	/* Address of the lock. */
	struct futex_address		fl_address;

	/*
	 * Current owner of the lock. LOCK_UNMANAGED if the lock is
	 * currently not owned by the kernel. LOCK_OWNER_UNKNOWN in case
	 * the owner is not known (e.g., when the lock is read-locked).
	 */
	pid_t				fl_owner;
#define LOCK_UNMANAGED 0x0
#define LOCK_OWNER_UNKNOWN 0x1

	/* Writers blocked on the lock. */
	struct futex_queue		fl_writers;
	/* Readers blocked on the lock. */
	struct futex_queue		fl_readers;
	/* Number of threads blocked on this lock + condition variables. */
	unsigned int			fl_waitcount;

	/* Global list pointers. */
	struct list_head		fl_next;
};

/* Information associated with a thread blocked on an object. */
struct futex_waiter {
	/* Thread ID. */
	pid_t				fw_tid;

	/* Queue this waiter is currently placed in. */
	struct futex_queue *		fw_queue;
	/* List pointers of fw_queue. */
	struct list_head		fw_next;

	/* Lock has been acquired. */
	bool				fw_locked;
	/* If not locked, threads that should block after acquiring. */
	struct futex_queue		fw_donated;
};

/* Global data structures. */
static spinlock_t futex_global_lock;

static struct list_head futex_lock_list = LIST_HEAD_INIT(futex_lock_list);
static struct list_head futex_condvar_list = LIST_HEAD_INIT(futex_condvar_list);

/* Utility functions. */
static void futex_lock_assert(const struct futex_lock *);
static struct futex_lock *futex_lock_lookup_locked(struct futex_address *);
static void futex_lock_release(struct futex_lock *);
static int futex_lock_tryrdlock(struct futex_lock *, cloudabi_lock_t __user *);
static int futex_lock_unmanage(struct futex_lock *, cloudabi_lock_t __user *);
static int futex_lock_update_owner(struct futex_lock *,
    cloudabi_lock_t __user *);
static int futex_lock_wake_up_next(struct futex_lock *,
    cloudabi_lock_t __user *);
static unsigned int futex_queue_count(const struct futex_queue *);
static void futex_queue_init(struct futex_queue *);
static void futex_queue_requeue(struct futex_queue *, struct futex_queue *,
    unsigned int);
static int futex_queue_sleep(struct futex_queue *, struct futex_lock *,
    struct futex_waiter *, struct task_struct *, cloudabi_clockid_t,
    cloudabi_timestamp_t, cloudabi_timestamp_t);
static pid_t futex_queue_tid_best(const struct futex_queue *);
static void futex_queue_wake_up_all(struct futex_queue *);
static void futex_queue_wake_up_best(struct futex_queue *);
static void futex_queue_wake_up_donate(struct futex_queue *, unsigned int);
static int futex_user_load(uint32_t __user *, uint32_t *);
static int futex_user_store(uint32_t __user *, uint32_t);
static int futex_user_cmpxchg(uint32_t __user *, uint32_t, uint32_t *,
    uint32_t);

static int cloudabi_futex_condvar_wait_unlocked(struct futex_condvar *,
    struct futex_waiter *, struct task_struct *, cloudabi_condvar_t __user *,
    cloudabi_clockid_t, cloudabi_timestamp_t, cloudabi_timestamp_t);

/*
 * futex_address operations.
 */

static int
futex_address_create(struct futex_address *fa, struct task_struct *task,
    const void *object)
{
	fa->fa_mm = task->mm;
	fa->fa_object = object;
	return 0;
}

static void
futex_address_free(struct futex_address *fa)
{
}

static bool
futex_address_match(const struct futex_address *fa1,
    const struct futex_address *fa2)
{
	return fa1->fa_mm == fa2->fa_mm && fa1->fa_object == fa2->fa_object;
}

/*
 * futex_condvar operations.
 */

static void
futex_condvar_assert(const struct futex_condvar *fc)
{

	BUG_ON(fc->fc_waitcount < futex_queue_count(&fc->fc_waiters));
	futex_lock_assert(fc->fc_lock);
}

static int
futex_condvar_lookup(struct task_struct *task,
    const cloudabi_condvar_t __user *address, struct futex_condvar **fcret)
{
	struct futex_address fa_condvar;
	struct futex_condvar *fc;
	int error;

	error = futex_address_create(&fa_condvar, task, address);
	if (error != 0)
		return (error);

	spin_lock(&futex_global_lock);
	list_for_each_entry(fc, &futex_condvar_list, fc_next) {
		if (futex_address_match(&fc->fc_address, &fa_condvar)) {
			/* Found matching lock object. */
			futex_address_free(&fa_condvar);
			futex_condvar_assert(fc);
			*fcret = fc;
			return (0);
		}
	}
	spin_unlock(&futex_global_lock);
	futex_address_free(&fa_condvar);
	return -ENOENT;
}

static int
futex_condvar_lookup_or_create(struct task_struct *task,
    const cloudabi_condvar_t __user *condvar,
    const cloudabi_lock_t __user *lock, struct futex_condvar **fcret)
{
	struct futex_address fa_condvar, fa_lock;
	struct futex_condvar *fc;
	struct futex_lock *fl;
	int error;

	error = futex_address_create(&fa_condvar, task, condvar);
	if (error != 0)
		return (error);
	error = futex_address_create(&fa_lock, task, lock);
	if (error != 0) {
		futex_address_free(&fa_condvar);
		return (error);
	}

	spin_lock(&futex_global_lock);
	list_for_each_entry(fc, &futex_condvar_list, fc_next) {
		if (!futex_address_match(&fc->fc_address, &fa_condvar))
			continue;
		fl = fc->fc_lock;
		if (!futex_address_match(&fl->fl_address, &fa_lock)) {
			/* Condition variable is owned by a different lock. */
			futex_address_free(&fa_condvar);
			futex_address_free(&fa_lock);
			spin_unlock(&futex_global_lock);
			return -EINVAL;
		}

		/* Found fully matching condition variable. */
		futex_address_free(&fa_condvar);
		futex_address_free(&fa_lock);
		futex_condvar_assert(fc);
		*fcret = fc;
		return (0);
	}

	/* None found. Create new condition variable object. */
	fc = kmalloc(sizeof(*fc), GFP_KERNEL);
	fc->fc_address = fa_condvar;
	fc->fc_lock = futex_lock_lookup_locked(&fa_lock);
	futex_queue_init(&fc->fc_waiters);
	fc->fc_waitcount = 0;
	list_add(&fc->fc_next, &futex_condvar_list);
	*fcret = fc;
	return (0);
}

static void
futex_condvar_release(struct futex_condvar *fc)
{
	struct futex_lock *fl;

	futex_condvar_assert(fc);
	fl = fc->fc_lock;
	if (fc->fc_waitcount == 0) {
		/* Condition variable has no waiters. Deallocate it. */
		futex_address_free(&fc->fc_address);
		list_del(&fc->fc_next);
		kfree(fc);
	}
	futex_lock_release(fl);
}

static int
futex_condvar_unmanage(struct futex_condvar *fc,
    cloudabi_condvar_t __user *condvar)
{
	int error;

	if (futex_queue_count(&fc->fc_waiters) == 0) {
		error = futex_user_store(condvar,
		    CLOUDABI_CONDVAR_HAS_NO_WAITERS);
		if (error != 0)
			return error;
	}
	return (0);
}

/*
 * futex_lock operations.
 */

static void
futex_lock_assert(const struct futex_lock *fl)
{

	/*
	 * A futex lock can only be kernel-managed if it has waiters.
	 * Vice versa: if a futex lock has waiters, it must be
	 * kernel-managed.
	 */
	BUG_ON((fl->fl_owner == LOCK_UNMANAGED) !=
	    (futex_queue_count(&fl->fl_readers) == 0 &&
	    futex_queue_count(&fl->fl_writers) == 0));
	BUG_ON(fl->fl_waitcount == 0 && fl->fl_owner != LOCK_UNMANAGED);
}

static int
futex_lock_lookup(struct task_struct *task,
    const cloudabi_lock_t __user *address, struct futex_lock **flret)
{
	struct futex_address fa;
	int error;

	error = futex_address_create(&fa, task, address);
	if (error != 0)
		return (error);

	spin_lock(&futex_global_lock);
	*flret = futex_lock_lookup_locked(&fa);
	return (0);
}

static struct futex_lock *
futex_lock_lookup_locked(struct futex_address *fa)
{
	struct futex_lock *fl;

	list_for_each_entry(fl, &futex_lock_list, fl_next) {
		if (futex_address_match(&fl->fl_address, fa)) {
			/* Found matching lock object. */
			futex_address_free(fa);
			futex_lock_assert(fl);
			return (fl);
		}
	}

	/* None found. Create new lock object. */
	fl = kmalloc(sizeof(*fl), GFP_KERNEL);
	fl->fl_address = *fa;
	fl->fl_owner = LOCK_UNMANAGED;
	futex_queue_init(&fl->fl_readers);
	futex_queue_init(&fl->fl_writers);
	fl->fl_waitcount = 0;
	list_add(&fl->fl_next, &futex_lock_list);
	return (fl);
}

static int
futex_lock_rdlock(struct futex_lock *fl, struct task_struct *task,
    cloudabi_lock_t __user *lock, cloudabi_clockid_t clock_id,
    cloudabi_timestamp_t timeout, cloudabi_timestamp_t precision)
{
	struct futex_waiter fw;
	int error;

	error = futex_lock_tryrdlock(fl, lock);
	if (error == -EBUSY) {
		/* Suspend execution. */
		BUG_ON(fl->fl_owner == LOCK_UNMANAGED);
		error = futex_queue_sleep(&fl->fl_readers, fl, &fw, task,
		    clock_id, timeout, precision);
		BUG_ON((error == 0) != fw.fw_locked);
		BUG_ON(futex_queue_count(&fw.fw_donated) > 0);
	}
	if (error != 0)
		futex_lock_unmanage(fl, lock);
	return (error);
}

static void
futex_lock_release(struct futex_lock *fl)
{

	futex_lock_assert(fl);
	if (fl->fl_waitcount == 0) {
		/* Lock object is unreferenced. Deallocate it. */
		BUG_ON(fl->fl_owner != LOCK_UNMANAGED);
		futex_address_free(&fl->fl_address);
		list_del(&fl->fl_next);
		kfree(fl);
	}
	spin_unlock(&futex_global_lock);
}

static int
futex_lock_unmanage(struct futex_lock *fl, cloudabi_lock_t __user *lock)
{
	cloudabi_lock_t cmp, old;
	int error;

	if (futex_queue_count(&fl->fl_readers) == 0 &&
	    futex_queue_count(&fl->fl_writers) == 0) {
		/* Lock should be unmanaged. */
		fl->fl_owner = LOCK_UNMANAGED;

		/* Clear kernel-managed bit. */
		error = futex_user_load(lock, &old);
		if (error != 0)
			return error;
		for (;;) {
			cmp = old;
			error = futex_user_cmpxchg(lock, cmp, &old,
			    cmp & ~CLOUDABI_LOCK_KERNEL_MANAGED);
			if (error != 0)
				return error;
			if (old == cmp)
				break;
		}
	}
	return (0);
}

/* Sets an owner of a lock, based on a userspace lock value. */
static void
futex_lock_set_owner(struct futex_lock *fl, cloudabi_lock_t lock)
{

	/* Lock has no explicit owner. */
	if ((lock & ~CLOUDABI_LOCK_WRLOCKED) == 0) {
		fl->fl_owner = LOCK_OWNER_UNKNOWN;
		return;
	}
	lock &= ~(CLOUDABI_LOCK_WRLOCKED | CLOUDABI_LOCK_KERNEL_MANAGED);

	/* Don't allow userspace to silently unlock. */
	if (lock == LOCK_UNMANAGED) {
		fl->fl_owner = LOCK_OWNER_UNKNOWN;
		return;
	}
	fl->fl_owner = lock;
}

static int
futex_lock_unlock(struct futex_lock *fl, struct task_struct *task,
    cloudabi_lock_t __user *lock)
{
	int error;

	/* Validate that this thread is allowed to unlock. */
	error = futex_lock_update_owner(fl, lock);
	if (error != 0)
		return (error);
	if (fl->fl_owner != LOCK_UNMANAGED &&
	    fl->fl_owner != task_pid_vnr(task))
		return -EPERM;
	return (futex_lock_wake_up_next(fl, lock));
}

/* Syncs in the owner of the lock from userspace if needed. */
static int
futex_lock_update_owner(struct futex_lock *fl, cloudabi_lock_t __user *address)
{
	cloudabi_lock_t lock;
	int error;

	if (fl->fl_owner == LOCK_OWNER_UNKNOWN) {
		error = futex_user_load(address, &lock);
		if (error != 0)
			return error;
		futex_lock_set_owner(fl, lock);
	}
	return (0);
}

static int
futex_lock_tryrdlock(struct futex_lock *fl, cloudabi_lock_t __user *address)
{
	cloudabi_lock_t old, cmp;
	int error;

	if (fl->fl_owner != LOCK_UNMANAGED) {
		/* Lock is already acquired. */
		return -EBUSY;
	}

	old = CLOUDABI_LOCK_UNLOCKED;
	for (;;) {
		if ((old & CLOUDABI_LOCK_KERNEL_MANAGED) != 0) {
			/*
			 * Userspace lock is kernel-managed, even though
			 * the kernel disagrees.
			 */
			return -EINVAL;
		}

		if ((old & CLOUDABI_LOCK_WRLOCKED) == 0) {
			/*
			 * Lock is not read-locked. Attempt to acquire
			 * it by increasing the read count.
			 */
			cmp = old;
			error = futex_user_cmpxchg(address, cmp, &old, cmp + 1);
			if (error != 0)
				return error;
			if (old == cmp) {
				/* Success. */
				return (0);
			}
		} else {
			/* Lock is read-locked. Make it kernel-managed. */
			cmp = old;
			error = futex_user_cmpxchg(address, cmp, &old,
			    cmp | CLOUDABI_LOCK_KERNEL_MANAGED);
			if (error != 0)
				return error;
			if (old == cmp) {
				/* Success. */
				futex_lock_set_owner(fl, cmp);
				return -EBUSY;
			}
		}
	}
}

static int
futex_lock_trywrlock(struct futex_lock *fl, cloudabi_lock_t __user *address,
    pid_t tid, bool force_kernel_managed)
{
	cloudabi_lock_t old, new, cmp;
	int error;

	if (fl->fl_owner == tid) {
		/* Attempted to acquire lock recursively. */
		return -EDEADLK;
	}
	if (fl->fl_owner != LOCK_UNMANAGED) {
		/* Lock is already acquired. */
		return -EBUSY;
	}

	old = CLOUDABI_LOCK_UNLOCKED;
	for (;;) {
		if ((old & CLOUDABI_LOCK_KERNEL_MANAGED) != 0) {
			/*
			 * Userspace lock is kernel-managed, even though
			 * the kernel disagrees.
			 */
			return -EINVAL;
		}
		if (old == (tid | CLOUDABI_LOCK_WRLOCKED)) {
			/* Attempted to acquire lock recursively. */
			return -EDEADLK;
		}

		if (old == CLOUDABI_LOCK_UNLOCKED) {
			/* Lock is unlocked. Attempt to acquire it. */
			new = tid | CLOUDABI_LOCK_WRLOCKED;
			if (force_kernel_managed)
				new |= CLOUDABI_LOCK_KERNEL_MANAGED;
			error = futex_user_cmpxchg(address,
			    CLOUDABI_LOCK_UNLOCKED, &old, new);
			if (error != 0)
				return error;
			if (old == CLOUDABI_LOCK_UNLOCKED) {
				/* Success. */
				if (force_kernel_managed)
					fl->fl_owner = tid;
				return (0);
			}
		} else {
			/* Lock is still locked. Make it kernel-managed. */
			cmp = old;
			error = futex_user_cmpxchg(address, cmp, &old,
			    cmp | CLOUDABI_LOCK_KERNEL_MANAGED);
			if (error != 0)
				return error;
			if (old == cmp) {
				/* Success. */
				futex_lock_set_owner(fl, cmp);
				return -EBUSY;
			}
		}
	}
}

static int
futex_lock_wake_up_next(struct futex_lock *fl, cloudabi_lock_t __user *lock)
{
	pid_t tid;
	int error;

	/*
	 * Determine which thread(s) to wake up. Prefer waking up
	 * writers over readers to prevent write starvation.
	 */
	if (futex_queue_count(&fl->fl_writers) > 0) {
		/* Transfer ownership to a single write-locker. */
		if (futex_queue_count(&fl->fl_writers) > 1 ||
		    futex_queue_count(&fl->fl_readers) > 0) {
			/* Lock should remain managed afterwards. */
			tid = futex_queue_tid_best(&fl->fl_writers);
			error = futex_user_store(lock,
			    tid | CLOUDABI_LOCK_WRLOCKED |
			    CLOUDABI_LOCK_KERNEL_MANAGED);
			if (error != 0)
				return error;

			futex_queue_wake_up_best(&fl->fl_writers);
			fl->fl_owner = tid;
		} else {
			/* Lock can become unmanaged afterwards. */
			error = futex_user_store(lock,
			    futex_queue_tid_best(&fl->fl_writers) |
			    CLOUDABI_LOCK_WRLOCKED);
			if (error != 0)
				return error;

			futex_queue_wake_up_best(&fl->fl_writers);
			fl->fl_owner = LOCK_UNMANAGED;
		}
	} else {
		/* Transfer ownership to all read-lockers (if any). */
		error = futex_user_store(lock,
		    futex_queue_count(&fl->fl_readers));
		if (error != 0)
			return error;

		/* Wake up all threads. */
		futex_queue_wake_up_all(&fl->fl_readers);
		fl->fl_owner = LOCK_UNMANAGED;
	}
	return (0);
}

static int
futex_lock_wrlock(struct futex_lock *fl, struct task_struct *task,
    cloudabi_lock_t __user *lock, cloudabi_clockid_t clock_id,
    cloudabi_timestamp_t timeout, cloudabi_timestamp_t precision,
    struct futex_queue *donated)
{
	struct futex_waiter fw;
	int error;

	error = futex_lock_trywrlock(fl, lock, task_pid_vnr(task),
	    futex_queue_count(donated) > 0);

	if (error == 0 || error == -EBUSY) {
		/* Put donated threads in queue before suspending. */
		BUG_ON(futex_queue_count(donated) > 0 &&
		    fl->fl_owner == LOCK_UNMANAGED);
		futex_queue_requeue(donated, &fl->fl_writers, UINT_MAX);
	} else {
		/*
		 * This thread cannot deal with the donated threads.
		 * Wake up the next thread and let it try it by itself.
		 */
		futex_queue_wake_up_donate(donated, UINT_MAX);
	}

	if (error == -EBUSY) {
		/* Suspend execution if the lock was busy. */
		BUG_ON(fl->fl_owner == LOCK_UNMANAGED);
		error = futex_queue_sleep(&fl->fl_writers, fl, &fw, task,
		    clock_id, timeout, precision);
		BUG_ON((error == 0) != fw.fw_locked);
		BUG_ON(futex_queue_count(&fw.fw_donated) > 0);
	}
	if (error != 0)
		futex_lock_unmanage(fl, lock);
	return (error);
}

/*
 * futex_queue operations.
 */

static pid_t
futex_queue_tid_best(const struct futex_queue *fq)
{

	return list_first_entry(&fq->fq_list, struct futex_waiter, fw_next)
	    ->fw_tid;
}

static unsigned int
futex_queue_count(const struct futex_queue *fq)
{

	return (fq->fq_count);
}

static void
futex_queue_init(struct futex_queue *fq)
{

	INIT_LIST_HEAD(&fq->fq_list);
	fq->fq_count = 0;
}

static int
futex_queue_sleep(struct futex_queue *fq, struct futex_lock *fl,
    struct futex_waiter *fw, struct task_struct *task,
    cloudabi_clockid_t clock_id, cloudabi_timestamp_t timeout,
    cloudabi_timestamp_t precision)
{
	/* TODO(ed): Implement! */
	return -ENOSYS;
}

/* Moves up to nwaiters waiters from one queue to another. */
static void
futex_queue_requeue(struct futex_queue *fqfrom, struct futex_queue *fqto,
    unsigned int nwaiters)
{
	struct futex_waiter *fw;

	/* Move waiters to the target queue. */
	while (nwaiters-- > 0 && !list_empty(&fqfrom->fq_list)) {
		fw = list_first_entry(&fqfrom->fq_list, struct futex_waiter,
		    fw_next);
		list_del(&fw->fw_next);
		--fqfrom->fq_count;

		fw->fw_queue = fqto;
		list_add_tail(&fw->fw_next, &fqto->fq_list);
		++fqto->fq_count;
	}
}

/* Wakes up all waiters in a queue. */
static void
futex_queue_wake_up_all(struct futex_queue *fq)
{
	struct futex_waiter *fw;

	list_for_each_entry(fw, &fq->fq_list, fw_next) {
		fw->fw_locked = true;
		fw->fw_queue = NULL;
		/* TODO(ed): cv_signal(&fw->fw_wait); */
	}

	INIT_LIST_HEAD(&fq->fq_list);
	fq->fq_count = 0;
}

/*
 * Wakes up the best waiter (i.e., the waiter having the highest
 * priority) in a queue.
 */
static void
futex_queue_wake_up_best(struct futex_queue *fq)
{
	struct futex_waiter *fw;

	fw = list_first_entry(&fq->fq_list, struct futex_waiter, fw_next);
	fw->fw_locked = true;
	fw->fw_queue = NULL;
	/* TODO(ed): cv_signal(&fw->fw_wait); */

	list_del(&fw->fw_next);
	--fq->fq_count;
}

static void
futex_queue_wake_up_donate(struct futex_queue *fq, unsigned int nwaiters)
{
	struct futex_waiter *fw;

	fw = list_first_entry(&fq->fq_list, struct futex_waiter, fw_next);
	if (fw == NULL)
		return;
	fw->fw_locked = false;
	fw->fw_queue = NULL;
	/* TODO(ed): cv_signal(&fw->fw_wait); */

	list_del(&fw->fw_next);
	--fq->fq_count;
	futex_queue_requeue(fq, &fw->fw_donated, nwaiters);
}

/*
 * futex_user operations. Used to adjust values in userspace.
 */

static int
futex_user_load(uint32_t __user *obj, uint32_t *val)
{
	int error;

	pagefault_disable();
	error = __copy_from_user_inatomic(val, obj, sizeof(*obj));
	pagefault_enable();
	return error != 0 ? -EFAULT : 0;
}

static int
futex_user_store(uint32_t __user *obj, uint32_t val)
{
	int error;

	pagefault_disable();
	error = __copy_to_user_inatomic(obj, &val, sizeof(*obj));
	pagefault_enable();
	return error != 0 ? -EFAULT : 0;
}

static int
futex_user_cmpxchg(uint32_t __user *obj, uint32_t cmp, uint32_t *old,
    uint32_t new)
{
	int error;

	pagefault_disable();
	error = futex_atomic_cmpxchg_inatomic(old, obj, cmp, new);
	pagefault_enable();
	return error;
}

/*
 * Blocking calls: acquiring locks, waiting on condition variables.
 */

int
cloudabi_futex_condvar_wait(struct task_struct *task,
    cloudabi_condvar_t __user *condvar, cloudabi_lock_t __user *lock,
    cloudabi_clockid_t clock_id, cloudabi_timestamp_t timeout,
    cloudabi_timestamp_t precision)
{
	struct futex_condvar *fc;
	struct futex_lock *fl;
	struct futex_waiter fw;
	int error, error2;

	/* Lookup condition variable object. */
	error = futex_condvar_lookup_or_create(task, condvar, lock, &fc);
	if (error != 0)
		return (error);
	fl = fc->fc_lock;

	/* Drop the lock. */
	error = futex_lock_unlock(fl, task, lock);
	if (error != 0) {
		futex_condvar_release(fc);
		return (error);
	}

	++fc->fc_waitcount;
	error = cloudabi_futex_condvar_wait_unlocked(fc, &fw, task, condvar,
	    clock_id, timeout, precision);
	if (fw.fw_locked) {
		/* Waited and got the lock assigned to us. */
		BUG_ON(futex_queue_count(&fw.fw_donated) > 0);
	} else if (error == 0 || error == -ETIMEDOUT) {
		if (error != 0)
			futex_condvar_unmanage(fc, condvar);
		/*
		 * Got woken up without having the lock assigned to us.
		 * This can happen in two cases:
		 *
		 * 1. We observed a timeout on a condition variable.
		 * 2. We got signalled on a condition variable while the
		 *    associated lock is unlocked. We are the first
		 *    thread that gets woken up. This thread is
		 *    responsible for reacquiring the userspace lock.
		 */
		error2 = futex_lock_wrlock(fl, task, lock,
		    CLOUDABI_CLOCK_MONOTONIC, ~(uint64_t)0, 0, &fw.fw_donated);
		if (error2 != 0)
			error = error2;
	} else {
		BUG_ON(futex_queue_count(&fw.fw_donated) > 0);
		futex_condvar_unmanage(fc, condvar);
		futex_lock_unmanage(fl, lock);
	}
	--fc->fc_waitcount;
	futex_condvar_release(fc);
	return (error);
}

static int
cloudabi_futex_condvar_wait_unlocked(struct futex_condvar *fc,
    struct futex_waiter *fw, struct task_struct *task,
    cloudabi_condvar_t __user *condvar, cloudabi_clockid_t clock_id,
    cloudabi_timestamp_t timeout, cloudabi_timestamp_t precision)
{
	int error;

	fw->fw_locked = false;
	futex_queue_init(&fw->fw_donated);

	/*
	 * Clear CLOUDABI_CONDVAR_HAS_NO_WAITERS to make userspace
	 * threads call into the kernel to perform wakeups.
	 */
	error = futex_user_store(condvar, 1);
	if (error != 0)
		return error;

	error = futex_queue_sleep(&fc->fc_waiters, fc->fc_lock, fw, task,
	    clock_id, timeout, precision);
	return (error);
}

int
cloudabi_futex_lock_rdlock(struct task_struct *task,
    cloudabi_lock_t __user *lock, cloudabi_clockid_t clock_id,
    cloudabi_timestamp_t timeout, cloudabi_timestamp_t precision)
{
	struct futex_lock *fl;
	int error;

	/* Look up lock object. */
	error = futex_lock_lookup(task, lock, &fl);
	if (error != 0)
		return (error);

	error = futex_lock_rdlock(fl, task, lock, clock_id, timeout,
	    precision);
	futex_lock_release(fl);
	return (error);
}

int
cloudabi_futex_lock_wrlock(struct task_struct *task,
    cloudabi_lock_t __user *lock, cloudabi_clockid_t clock_id,
    cloudabi_timestamp_t timeout, cloudabi_timestamp_t precision)
{
	struct futex_lock *fl;
	struct futex_queue fq;
	int error;

	/* Look up lock object. */
	error = futex_lock_lookup(task, lock, &fl);
	if (error != 0)
		return (error);

	futex_queue_init(&fq);
	error = futex_lock_wrlock(fl, task, lock, clock_id, timeout,
	    precision, &fq);
	futex_lock_release(fl);
	return (error);
}

/*
 * Non-blocking calls: releasing locks, signalling condition variables.
 */

cloudabi_errno_t cloudabi_sys_condvar_signal(
    const struct cloudabi_sys_condvar_signal_args *uap, unsigned long *retval)
{
	struct futex_condvar *fc;
	struct futex_lock *fl;
	struct task_struct *task;
	cloudabi_nthreads_t nwaiters;
	int error;

	nwaiters = uap->nwaiters;
	if (nwaiters == 0) {
		/* No threads to wake up. */
		return (0);
	}

	/* Look up futex object. */
	task = current;
	error = futex_condvar_lookup(task, uap->condvar, &fc);
	if (error != 0) {
		/* Race condition: condition variable with no waiters. */
		if (error == -ENOENT)
			return (0);
		return cloudabi_convert_errno(error);
	}
	fl = fc->fc_lock;

	if (fl->fl_owner == LOCK_UNMANAGED) {
		/*
		 * The lock is currently not managed by the kernel,
		 * meaning we must attempt to acquire the userspace lock
		 * first. We cannot requeue threads to an unmanaged lock,
		 * as these threads will then never be scheduled.
		 *
		 * Unfortunately, the memory address of the lock is
		 * unknown from this context, meaning that we cannot
		 * acquire the lock on behalf of the first thread to be
		 * scheduled. The lock may even not be mapped within the
		 * address space of the current thread.
		 *
		 * To solve this, wake up a single waiter that will
		 * attempt to acquire the lock. Donate all of the other
		 * waiters that need to be woken up to this waiter, so
		 * it can requeue them after acquiring the lock.
		 */
		futex_queue_wake_up_donate(&fc->fc_waiters, nwaiters - 1);
	} else {
		/*
		 * Lock is already managed by the kernel. This makes it
		 * easy, as we can requeue the threads from the
		 * condition variable directly to the associated lock.
		 */
		futex_queue_requeue(&fc->fc_waiters, &fl->fl_writers, nwaiters);
	}

	/* Clear userspace condition variable if all waiters are gone. */
	error = futex_condvar_unmanage(fc, uap->condvar);
	futex_condvar_release(fc);
	return cloudabi_convert_errno(error);
}

cloudabi_errno_t cloudabi_sys_lock_unlock(
    const struct cloudabi_sys_lock_unlock_args *uap, unsigned long *retval)
{
	struct futex_lock *fl;
	struct task_struct *task;
	int error;

	task = current;
	error = futex_lock_lookup(task, uap->lock, &fl);
	if (error != 0)
		return cloudabi_convert_errno(error);
	error = futex_lock_unlock(fl, task, uap->lock);
	futex_lock_release(fl);
	return cloudabi_convert_errno(error);
}
