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

#include <linux/hrtimer.h>
#include <linux/uaccess.h>

#include "cloudabi_syscalldefs.h"
#include "cloudabi_util.h"
#include "cloudabi64_syscalls.h"

cloudabi_errno_t cloudabi64_sys_poll(
    const struct cloudabi64_sys_poll_args *uap, unsigned long *retval)
{
	struct timespec ts;
	struct task_struct *task;
	int error;
	clockid_t clockid;

	/*
	 * Bandaid to support CloudABI futex constructs.
	 */
	task = current;
	if (uap->nevents == 1) {
		cloudabi64_subscription_t sub;
		cloudabi64_event_t ev = {};

		if (copy_from_user(&sub, uap->in, sizeof(sub)) != 0)
			return CLOUDABI_EFAULT;
		ev.userdata = sub.userdata;
		ev.type = sub.type;
		if (sub.type == CLOUDABI_EVENTTYPE_CLOCK) {
			/* Sleep. */
			/* TODO(ed): This should not be here. */
			error = cloudabi_convert_clockid(sub.clock.clock_id,
			    &clockid);
			if (error == 0) {
				ts.tv_sec = sub.clock.timeout / NSEC_PER_SEC;
				ts.tv_nsec = sub.clock.timeout % NSEC_PER_SEC;
				error = hrtimer_nanosleep(&ts, NULL,
				    HRTIMER_MODE_ABS, clockid);
			}
			ev.error = cloudabi_convert_errno(error);
			retval[0] = 1;
			return copy_to_user(uap->out, &ev, sizeof(ev)) != 0 ?
			    CLOUDABI_EFAULT : 0;
		} else if (sub.type == CLOUDABI_EVENTTYPE_CONDVAR) {
			/* Wait on a condition variable. */
			ev.error = cloudabi_convert_errno(
			    cloudabi_futex_condvar_wait(
			        task, (cloudabi_condvar_t *)sub.condvar.condvar,
			        (cloudabi_lock_t *)sub.condvar.lock,
			        CLOUDABI_CLOCK_MONOTONIC, UINT64_MAX, 0));
			retval[0] = 1;
			return copy_to_user(uap->out, &ev, sizeof(ev)) != 0 ?
			    CLOUDABI_EFAULT : 0;
		} else if (sub.type == CLOUDABI_EVENTTYPE_LOCK_RDLOCK) {
			/* Acquire a read lock. */
			ev.error = cloudabi_convert_errno(
			    cloudabi_futex_lock_rdlock(
			        task, (cloudabi_lock_t *)sub.lock.lock,
			        CLOUDABI_CLOCK_MONOTONIC, UINT64_MAX, 0));
			retval[0] = 1;
			return copy_to_user(uap->out, &ev, sizeof(ev)) != 0 ?
			    CLOUDABI_EFAULT : 0;
		} else if (sub.type == CLOUDABI_EVENTTYPE_LOCK_WRLOCK) {
			/* Acquire a write lock. */
			ev.error = cloudabi_convert_errno(
			    cloudabi_futex_lock_wrlock(
			        task, (cloudabi_lock_t *)sub.lock.lock,
			        CLOUDABI_CLOCK_MONOTONIC, UINT64_MAX, 0));
			retval[0] = 1;
			return copy_to_user(uap->out, &ev, sizeof(ev)) != 0 ?
			    CLOUDABI_EFAULT : 0;
		}
	} else if (uap->nevents == 2) {
		cloudabi64_subscription_t sub[2];
		cloudabi64_event_t ev[2] = {};

		if (copy_from_user(&sub, uap->in, sizeof(sub)) != 0)
			return CLOUDABI_EFAULT;
		ev[0].userdata = sub[0].userdata;
		ev[0].type = sub[0].type;
		ev[1].userdata = sub[1].userdata;
		ev[1].type = sub[1].type;
		if (sub[0].type == CLOUDABI_EVENTTYPE_CONDVAR &&
		    sub[1].type == CLOUDABI_EVENTTYPE_CLOCK) {
			/* Wait for a condition variable with timeout. */
			error = cloudabi_futex_condvar_wait(
			    task, (cloudabi_condvar_t *)sub[0].condvar.condvar,
			    (cloudabi_lock_t *)sub[0].condvar.lock,
			    sub[1].clock.clock_id, sub[1].clock.timeout,
			    sub[1].clock.precision);
			if (error == -ETIMEDOUT) {
				ev[1].error = 0;
				retval[0] = 1;
				return copy_to_user(uap->out, &ev[1],
				    sizeof(ev[1])) != 0 ? CLOUDABI_EFAULT : 0;
			}

			ev[0].error = cloudabi_convert_errno(error);
			retval[0] = 1;
			return copy_to_user(uap->out, &ev[0],
			    sizeof(ev[0])) != 0 ? CLOUDABI_EFAULT : 0;
		} else if (sub[0].type == CLOUDABI_EVENTTYPE_LOCK_RDLOCK &&
		    sub[1].type == CLOUDABI_EVENTTYPE_CLOCK) {
			/* Acquire a read lock with a timeout. */
			error = cloudabi_futex_lock_rdlock(
			    task, (cloudabi_lock_t *)sub[0].lock.lock,
			    sub[1].clock.clock_id, sub[1].clock.timeout,
			    sub[1].clock.precision);
			if (error == -ETIMEDOUT) {
				ev[1].error = 0;
				retval[0] = 1;
				return copy_to_user(uap->out, &ev[1],
				    sizeof(ev[1])) != 0 ? CLOUDABI_EFAULT : 0;
			}

			ev[0].error = cloudabi_convert_errno(error);
			retval[0] = 1;
			return copy_to_user(uap->out, &ev[0],
			    sizeof(ev[0])) != 0 ? CLOUDABI_EFAULT : 0;
		} else if (sub[0].type == CLOUDABI_EVENTTYPE_LOCK_WRLOCK &&
		    sub[1].type == CLOUDABI_EVENTTYPE_CLOCK) {
			/* Acquire a write lock with a timeout. */
			error = cloudabi_futex_lock_wrlock(
			    task, (cloudabi_lock_t *)sub[0].lock.lock,
			    sub[1].clock.clock_id, sub[1].clock.timeout,
			    sub[1].clock.precision);
			if (error == -ETIMEDOUT) {
				ev[1].error = 0;
				retval[0] = 1;
				return copy_to_user(uap->out, &ev[1],
				    sizeof(ev[1])) != 0 ? CLOUDABI_EFAULT : 0;
			}

			ev[0].error = cloudabi_convert_errno(error);
			retval[0] = 1;
			return copy_to_user(uap->out, &ev[0],
			    sizeof(ev[0])) != 0 ? CLOUDABI_EFAULT : 0;
		}
	}

	return CLOUDABI_ENOSYS;
}
