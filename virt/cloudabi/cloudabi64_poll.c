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

#include <linux/uaccess.h>

#include "cloudabi_syscalldefs.h"
#include "cloudabi_util.h"
#include "cloudabi64_syscalls.h"

cloudabi_errno_t cloudabi64_sys_poll(
    const struct cloudabi64_sys_poll_args *uap, unsigned long *retval)
{
	struct task_struct *task;
	int error;

	/*
	 * Bandaid to support CloudABI futex constructs.
	 */
	task = current;
	if (uap->fd == CLOUDABI_POLL_ONCE && uap->nin == 1 && uap->nout >= 1) {
		cloudabi64_event_t ev;
		if (copy_from_user(&ev, uap->in, sizeof(ev)) != 0)
			return CLOUDABI_EFAULT;
		if (ev.type == CLOUDABI_EVENT_TYPE_CONDVAR) {
			/* Wait on a condition variable. */
			ev.error = cloudabi_convert_errno(
			    cloudabi_futex_condvar_wait(
			        task, (cloudabi_condvar_t *)ev.condvar.condvar,
			        (cloudabi_lock_t *)ev.condvar.lock,
			        CLOUDABI_CLOCK_MONOTONIC, UINT64_MAX, 0));
			retval[0] = 1;
			return copy_to_user(uap->out, &ev, sizeof(ev)) != 0 ?
			    CLOUDABI_EFAULT : 0;
		} else if (ev.type == CLOUDABI_EVENT_TYPE_LOCK_RDLOCK) {
			/* Acquire a read lock. */
			ev.error = cloudabi_convert_errno(
			    cloudabi_futex_lock_rdlock(
			        task, (cloudabi_lock_t *)ev.lock.lock,
			        CLOUDABI_CLOCK_MONOTONIC, UINT64_MAX, 0));
			retval[0] = 1;
			return copy_to_user(uap->out, &ev, sizeof(ev)) != 0 ?
			    CLOUDABI_EFAULT : 0;
		} else if (ev.type == CLOUDABI_EVENT_TYPE_LOCK_WRLOCK) {
			/* Acquire a write lock. */
			ev.error = cloudabi_convert_errno(
			    cloudabi_futex_lock_wrlock(
			        task, (cloudabi_lock_t *)ev.lock.lock,
			        CLOUDABI_CLOCK_MONOTONIC, UINT64_MAX, 0));
			retval[0] = 1;
			return copy_to_user(uap->out, &ev, sizeof(ev)) != 0 ?
			    CLOUDABI_EFAULT : 0;
		}
	} else if (uap->fd == CLOUDABI_POLL_ONCE && uap->nin == 2 &&
	    uap->nout >= 2) {
		cloudabi64_event_t ev[2];
		if (copy_from_user(&ev, uap->in, sizeof(ev)) != 0)
			return CLOUDABI_EFAULT;
		if (ev[0].type == CLOUDABI_EVENT_TYPE_CONDVAR &&
		    ev[1].type == CLOUDABI_EVENT_TYPE_CLOCK) {
			/* Wait for a condition variable with timeout. */
			error = cloudabi_futex_condvar_wait(
			    task, (cloudabi_condvar_t *)ev[0].condvar.condvar,
			    (cloudabi_lock_t *)ev[0].condvar.lock,
			    ev[1].clock.clock_id, ev[1].clock.timeout,
			    ev[1].clock.precision);
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
		} else if (ev[0].type == CLOUDABI_EVENT_TYPE_LOCK_RDLOCK &&
		    ev[1].type == CLOUDABI_EVENT_TYPE_CLOCK) {
			/* Acquire a read lock with a timeout. */
			error = cloudabi_futex_lock_rdlock(
			    task, (cloudabi_lock_t *)ev[0].lock.lock,
			    ev[1].clock.clock_id, ev[1].clock.timeout,
			    ev[1].clock.precision);
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
		} else if (ev[0].type == CLOUDABI_EVENT_TYPE_LOCK_WRLOCK &&
		    ev[1].type == CLOUDABI_EVENT_TYPE_CLOCK) {
			/* Acquire a write lock with a timeout. */
			error = cloudabi_futex_lock_wrlock(
			    task, (cloudabi_lock_t *)ev[0].lock.lock,
			    ev[1].clock.clock_id, ev[1].clock.timeout,
			    ev[1].clock.precision);
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
