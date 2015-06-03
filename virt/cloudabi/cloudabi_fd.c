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

#include <linux/file.h>
#include <linux/fs.h>
#include <linux/syscalls.h>
#include <linux/uio.h>

#include "cloudabi_util.h"
#include "cloudabi_syscalls.h"

cloudabi_errno_t cloudabi_sys_fd_close(
    const struct cloudabi_sys_fd_close_args *uap, unsigned long *retval)
{
	return cloudabi_convert_errno(sys_close(uap->fd));
}

cloudabi_errno_t cloudabi_sys_fd_create1(
    const struct cloudabi_sys_fd_create1_args *uap, unsigned long *retval) {
	/* TODO(ed): Add support for other file descriptor types. */
	switch (uap->type) {
	case CLOUDABI_FILETYPE_POLL: {
		long fd;

		fd = sys_epoll_create1(O_CLOEXEC);
		if (fd < 0)
			return cloudabi_convert_errno(fd);
		retval[0] = fd;
		return 0;
	}
	default:
		return CLOUDABI_EINVAL;
	}
}

cloudabi_errno_t cloudabi_sys_fd_create2(
    const struct cloudabi_sys_fd_create2_args *uap, unsigned long *retval)
{
	/* TODO(ed): Add support for socket pairs. */
	switch (uap->type) {
	case CLOUDABI_FILETYPE_FIFO: {
		int fds[2];
		int error;

		error = do_pipe_flags(fds, 0);
		if (error != 0)
			return cloudabi_convert_errno(error);
		retval[0] = fds[0];
		retval[1] = fds[1];
		return 0;
	}
	default:
		return CLOUDABI_EINVAL;
	}
}

cloudabi_errno_t cloudabi_sys_fd_datasync(
    const struct cloudabi_sys_fd_datasync_args *uap, unsigned long *retval) {
	return cloudabi_convert_errno(sys_fdatasync(uap->fd));
}

cloudabi_errno_t cloudabi_sys_fd_dup(
    const struct cloudabi_sys_fd_dup_args *uap, unsigned long *retval)
{
	long newfd;

	newfd = sys_dup(uap->from);
	if (newfd < 0)
		return cloudabi_convert_errno(newfd);
	retval[0] = newfd;
	return 0;
}

cloudabi_errno_t cloudabi_sys_fd_replace(
    const struct cloudabi_sys_fd_replace_args *uap, unsigned long *retval)
{
	long newfd;

	/* TODO(ed): This should disallow dupping to unused descriptors. */
	newfd = sys_dup2(uap->from, uap->to);
	if (newfd < 0)
		return cloudabi_convert_errno(newfd);
	return 0;
}

cloudabi_errno_t cloudabi_sys_fd_seek(
    const struct cloudabi_sys_fd_seek_args *uap, unsigned long *retval)
{
	unsigned int whence;
	long offset;

	switch (uap->whence) {
	case CLOUDABI_WHENCE_CUR:
		whence = SEEK_CUR;
		break;
	case CLOUDABI_WHENCE_END:
		whence = SEEK_END;
		break;
	case CLOUDABI_WHENCE_SET:
		whence = SEEK_SET;
		break;
	default:
		return CLOUDABI_EINVAL;
	}

	offset = sys_lseek(uap->fd, uap->offset, uap->whence);
	if (offset < 0)
		return cloudabi_convert_errno(offset);
	retval[0] = offset;
	return 0;
}

cloudabi_errno_t cloudabi_sys_fd_stat_get(
    const struct cloudabi_sys_fd_stat_get_args *uap, unsigned long *retval)
{
	cloudabi_fdstat_t fsb = {};
	struct fd fd;
	struct file *file;

	fd = fdget_raw(uap->fd);
	if (fd.file == NULL)
		return CLOUDABI_EBADF;
	file = fd.file;

	/* TODO(ed): Set the file type. */
	fsb.fs_filetype = CLOUDABI_FILETYPE_DIRECTORY;

	/* Convert file descriptor flags. */
	if ((file->f_flags & O_APPEND) != 0)
		fsb.fs_flags |= CLOUDABI_FDFLAG_APPEND;
	if ((file->f_flags & O_DSYNC) != 0)
		fsb.fs_flags |= CLOUDABI_FDFLAG_DSYNC;
	if ((file->f_flags & O_NONBLOCK) != 0)
		fsb.fs_flags |= CLOUDABI_FDFLAG_NONBLOCK;
	if ((file->f_flags & O_SYNC) != 0)
		fsb.fs_flags |= CLOUDABI_FDFLAG_SYNC;

	/* TODO(ed): Set the right value. */
	fsb.fs_rights_base = ~0;
	fsb.fs_rights_inheriting = ~0;

	fdput(fd);
	return copy_to_user(uap->buf, &fsb, sizeof(fsb)) != 0 ?
	    CLOUDABI_EFAULT : 0;
}

cloudabi_errno_t cloudabi_sys_fd_stat_put(
    const struct cloudabi_sys_fd_stat_put_args *uap, unsigned long *retval)
{
	return CLOUDABI_ENOSYS;
}

cloudabi_errno_t cloudabi_sys_fd_sync(
    const struct cloudabi_sys_fd_sync_args *uap, unsigned long *retval)
{
	return cloudabi_convert_errno(sys_fsync(uap->fd));
}
