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

#include <linux/sched.h>
#include <linux/uaccess.h>

#include "cloudabi_syscalldefs.h"
#include "cloudabi_util.h"
#include "cloudabi64_syscalls.h"

cloudabi_errno_t cloudabi64_sys_thread_create(
    const struct cloudabi64_sys_thread_create_args *uap, unsigned long *retval)
{
	cloudabi64_threadattr_t attr;
	struct clone4_args clone4_args = {};
	struct pt_regs *regs;
	struct task_struct *child;
	cloudabi_tid_t tid;

	if (copy_from_user(&attr, uap->attr, sizeof(attr)) != 0)
		return CLOUDABI_EFAULT;

	/* Create a new thread. */
	child = copy_process(CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
	    CLONE_THREAD, &clone4_args, NULL, 0, NULL);
	if (IS_ERR(child))
		return cloudabi_convert_errno(PTR_ERR(child));
	tid = cloudabi_gettid(child);

	/* Set initial registers. */
	regs = task_pt_regs(child);
#ifdef __x86_64__
	/* TODO(ed): This should be solved more elegantly. */
	regs->sp = rounddown(attr.stack + attr.stack_size, 16) - 8;
	regs->ip = attr.entry_point;
	regs->di = tid;
	regs->si = attr.argument;
#else
#error "Unknown architecture"
#endif

	/* Start execution of new thread. */
	wake_up_new_task(child);

	retval[0] = tid;
	return 0;
}
