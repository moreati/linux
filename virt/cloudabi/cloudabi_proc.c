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

#include <linux/binfmts.h>
#include <linux/fdtable.h>
#include <linux/fs_struct.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/tsacct_kern.h>

#include "cloudabi_syscalldefs.h"
#include "cloudabi_syscalls.h"
#include "cloudabi_util.h"

/* Converts CloudABI's signal numbers to Linux's. */
static cloudabi_errno_t convert_signal(cloudabi_signal_t in, int *out)
{
	static const int signals[] = {
		[CLOUDABI_SIGABRT] = SIGABRT,
		[CLOUDABI_SIGALRM] = SIGALRM,
		[CLOUDABI_SIGBUS] = SIGBUS,
		[CLOUDABI_SIGCHLD] = SIGCHLD,
		[CLOUDABI_SIGCONT] = SIGCONT,
		[CLOUDABI_SIGFPE] = SIGFPE,
		[CLOUDABI_SIGHUP] = SIGHUP,
		[CLOUDABI_SIGILL] = SIGILL,
		[CLOUDABI_SIGINT] = SIGINT,
		[CLOUDABI_SIGKILL] = SIGKILL,
		[CLOUDABI_SIGPIPE] = SIGPIPE,
		[CLOUDABI_SIGQUIT] = SIGQUIT,
		[CLOUDABI_SIGSEGV] = SIGSEGV,
		[CLOUDABI_SIGSTOP] = SIGSTOP,
		[CLOUDABI_SIGSYS] = SIGSYS,
		[CLOUDABI_SIGTERM] = SIGTERM,
		[CLOUDABI_SIGTRAP] = SIGTRAP,
		[CLOUDABI_SIGTSTP] = SIGTSTP,
		[CLOUDABI_SIGTTIN] = SIGTTIN,
		[CLOUDABI_SIGTTOU] = SIGTTOU,
		[CLOUDABI_SIGURG] = SIGURG,
		[CLOUDABI_SIGUSR1] = SIGUSR1,
		[CLOUDABI_SIGUSR2] = SIGUSR2,
		[CLOUDABI_SIGVTALRM] = SIGVTALRM,
		[CLOUDABI_SIGXCPU] = SIGXCPU,
		[CLOUDABI_SIGXFSZ] = SIGXFSZ,
	};

	if ((in < sizeof(signals) / sizeof(signals[0]) && signals[in] != 0) ||
	    in == 0) {
		/* Valid signal mapping. */
		*out = signals[in];
		return 0;
	} else {
		/* Invalid signal. */
		return CLOUDABI_EINVAL;
	}
}

/* Copies argument data to the stack of the new executable. */
/* TODO(ed): is the buffer size properly propagated? */
static int copy_argdata(struct linux_binprm *bprm, const void *src,
    size_t srclen) {
	struct page *kmapped_page = NULL;
	unsigned long bytes_to_copy, dstpos, dstoff, kpos;
	const char *srcpos;
	char *kaddr;
	int ret;

	/* Subtract space from the end to fit the argument data. */
	dstpos = bprm->p;
	if (srclen > dstpos)
		return -E2BIG;
	bprm->p -= srclen;

	srcpos = (const char *)src + srclen;
	while (srclen > 0) {
		/* Cancellation point. */
		if (fatal_signal_pending(current)) {
			ret = -ERESTARTNOHAND;
			goto out;
		}
		cond_resched();

		/* Determine how much data to copy. */
		dstoff = dstpos % PAGE_SIZE;
		if (dstoff == 0)
			dstoff = PAGE_SIZE;
		bytes_to_copy = dstoff < srclen ? dstoff : srclen;

		dstpos -= bytes_to_copy;
		dstoff -= bytes_to_copy;
		srcpos -= bytes_to_copy;
		srclen -= bytes_to_copy;

		/* Map a new page if we've crossed the page boundary. */
		if (!kmapped_page || kpos != (dstpos & PAGE_MASK)) {
			struct page *page;

			page = get_arg_page(bprm, dstpos, 1);
			if (!page) {
				ret = -E2BIG;
				goto out;
			}

			if (kmapped_page) {
				flush_kernel_dcache_page(kmapped_page);
				kunmap(kmapped_page);
				put_arg_page(kmapped_page);
			}
			kmapped_page = page;
			kaddr = kmap(kmapped_page);
			kpos = dstpos & PAGE_MASK;
			flush_arg_page(bprm, kpos, kmapped_page);
		}

		/* Copy argument data into page. */
		if (copy_from_user(kaddr + dstoff, srcpos, bytes_to_copy)) {
			ret = -EFAULT;
			goto out;
		}
	}
	ret = 0;

out:
	/* Unmap page if still mapped. */
	if (kmapped_page) {
		flush_kernel_dcache_page(kmapped_page);
		kunmap(kmapped_page);
		put_arg_page(kmapped_page);
	}
	return ret;
}

cloudabi_errno_t cloudabi_sys_proc_exec(
    const struct cloudabi_sys_proc_exec_args *uap, unsigned long *retval)
{
	struct file *file;
	struct files_struct *displaced;
	struct filename *filename;
	struct linux_binprm *bprm;
	char *pathbuf = NULL;
	int error;

	filename = getname_kernel("");
	if (IS_ERR(filename))
		return cloudabi_convert_errno(PTR_ERR(filename));

	if ((current->flags & PF_NPROC_EXCEEDED) &&
	    atomic_read(&current_user()->processes) > rlimit(RLIMIT_NPROC)) {
		error = -EAGAIN;
		goto out_ret;
	}

	/* We're below the limit (still or again), so we don't want to make
	 * further execve() calls fail. */
	current->flags &= ~PF_NPROC_EXCEEDED;

	/* TODO(ed): Install new file descriptor table layout. */
	error = unshare_files(&displaced);
	if (error != 0)
		goto out_ret;

	bprm = kzalloc(sizeof(*bprm), GFP_KERNEL);
	if (bprm == NULL) {
		error = -ENOMEM;
		goto out_files;
	}

	error = prepare_bprm_creds(bprm);
	if (error != 0)
		goto out_free;

	check_unsafe_exec(bprm);
	current->in_execve = 1;

	file = do_open_execat(uap->fd, filename, AT_EMPTY_PATH);
	error = PTR_ERR(file);
	if (IS_ERR(file))
		goto out_unmark;

	sched_exec();
	bprm->file = file;
	pathbuf = kasprintf(GFP_TEMPORARY, "/dev/fd/%u", uap->fd);
	if (pathbuf == NULL) {
		error = -ENOMEM;
		goto out_unmark;
	}
	bprm->interp_flags |= BINPRM_FLAGS_PATH_INACCESSIBLE;
	bprm->filename = pathbuf;
	bprm->interp = bprm->filename;

	error = bprm_mm_init(bprm);
	if (error != 0)
		goto out_unmark;

	error = prepare_binprm(bprm);
	if (error < 0)
		goto out;

	error = copy_strings_kernel(1, &bprm->filename, bprm);
	if (error != 0)
		goto out;

	bprm->exec = bprm->p;

	/* Copy argument data to the new process. */
	error = copy_argdata(bprm, uap->data, uap->datalen);
	if (error != 0)
		goto out;

	error = exec_binprm(bprm);
	if (error != 0)
		goto out;

	/* execve succeeded */
	current->fs->in_exec = 0;
	current->in_execve = 0;
	acct_update_integrals(current);
	task_numa_free(current);
	free_bprm(bprm);
	kfree(pathbuf);
	putname(filename);
	if (displaced)
		put_files_struct(displaced);
	return 0;

out:
	if (bprm->mm) {
		acct_arg_size(bprm, 0);
		mmput(bprm->mm);
	}

out_unmark:
	current->fs->in_exec = 0;
	current->in_execve = 0;

out_free:
	free_bprm(bprm);
	kfree(pathbuf);

out_files:
	if (displaced)
		reset_files_struct(displaced);
out_ret:
	putname(filename);
	return cloudabi_convert_errno(error);
}

cloudabi_errno_t cloudabi_sys_proc_exit(
    const struct cloudabi_sys_proc_exit_args *uap, unsigned long *retval)
{
	return cloudabi_convert_errno(sys_exit_group(uap->rval));
}

cloudabi_errno_t cloudabi_sys_proc_fork(
    const void *uap, unsigned long *retval)
{
#if 0
	struct clone4_args clone4_args = {};
	struct clonefd_setup clonefd_setup;
	struct pt_regs *regs;
	struct task_struct *child;
	cloudabi_tid_t tid;

	/* Create a new process. */
	child = copy_process(CLONE_FD, &clone4_args, NULL, 0, &clonefd_setup);
	if (IS_ERR(child))
		return cloudabi_convert_errno(PTR_ERR(child));
	tid = cloudabi_gettid(child);

	/* Return the new thread ID to the child process. */
	regs = task_pt_regs(child);
#ifdef __x86_64__
	/* TODO(ed): This should be solved more elegantly. */
	regs->di = CLOUDABI_PROCESS_CHILD;
	regs->si = tid;
#else
#error "Unknown architecture"
#endif

	/* Start execution of new process. */
	clonefd_install_fd(&clone4_args, &clonefd_setup);
	wake_up_new_task(child);

	/* Return the new file descriptor to the parent process. */
	retval[0] = clonefd_setup.fd;
	return 0;
#endif
	return CLOUDABI_ENOSYS;
}

cloudabi_errno_t cloudabi_sys_proc_raise(
    const struct cloudabi_sys_proc_raise_args *uap, unsigned long *retval)
{
	struct k_sigaction sigdfl = {
		.sa = {
			.sa_handler = SIG_DFL,
		},
	};
	int signum;
	cloudabi_errno_t error;

	error = convert_signal(uap->sig, &signum);
	if (error != 0)
		return error;

	/* Restore to default signal action and send signal. */
	do_sigaction(signum, &sigdfl, NULL);
	return cloudabi_convert_errno(sys_kill(task_tgid_vnr(current), signum));
}
