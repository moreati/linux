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

#include <linux/audit.h>
#include <linux/eventpoll.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/net.h>
#include <linux/shmem_fs.h>
#include <linux/socket.h>
#include <linux/syscalls.h>
#include <linux/uio.h>

#include <net/sock.h>

#include "cloudabi_util.h"
#include "cloudabi_syscalls.h"

cloudabi_errno_t cloudabi_sys_fd_close(
    const struct cloudabi_sys_fd_close_args *uap, unsigned long *retval)
{
	return cloudabi_convert_errno(sys_close(uap->fd));
}

cloudabi_errno_t cloudabi_sys_fd_create1(
    const struct cloudabi_sys_fd_create1_args *uap, unsigned long *retval) {
	long fd;

	switch (uap->type) {
	case CLOUDABI_FILETYPE_POLL:
		fd = sys_epoll_create1(0);
		break;
	case CLOUDABI_FILETYPE_SHARED_MEMORY:
		fd = sys_memfd_create(NULL, 0);
		break;
	case CLOUDABI_FILETYPE_SOCKET_DGRAM:
		fd = sys_socket(AF_UNIX, SOCK_DGRAM, 0);
		break;
	case CLOUDABI_FILETYPE_SOCKET_SEQPACKET:
		fd = sys_socket(AF_UNIX, SOCK_SEQPACKET, 0);
		break;
	case CLOUDABI_FILETYPE_SOCKET_STREAM:
		fd = sys_socket(AF_UNIX, SOCK_STREAM, 0);
		break;
	default:
		return CLOUDABI_EINVAL;
	}

	if (fd < 0)
		return cloudabi_convert_errno(fd);
	retval[0] = fd;
	return 0;
}

static cloudabi_errno_t do_socketpair(int type, unsigned long *retval) {
	struct socket *sock1, *sock2;
	int fd1, fd2, err;
	struct file *newfile1, *newfile2;

	err = sock_create(AF_UNIX, type, 0, &sock1);
	if (err < 0)
		goto out;

	err = sock_create(AF_UNIX, type, 0, &sock2);
	if (err < 0)
		goto out_release_1;

	err = sock1->ops->socketpair(sock1, sock2);
	if (err < 0)
		goto out_release_both;

	fd1 = get_unused_fd_flags(0);
	if (unlikely(fd1 < 0)) {
		err = fd1;
		goto out_release_both;
	}

	fd2 = get_unused_fd_flags(0);
	if (unlikely(fd2 < 0)) {
		err = fd2;
		goto out_put_unused_1;
	}

	newfile1 = sock_alloc_file(sock1, 0, NULL);
	if (IS_ERR(newfile1)) {
		err = PTR_ERR(newfile1);
		goto out_put_unused_both;
	}

	newfile2 = sock_alloc_file(sock2, 0, NULL);
	if (IS_ERR(newfile2)) {
		err = PTR_ERR(newfile2);
		goto out_fput_1;
	}

	audit_fd_pair(fd1, fd2);

	fd_install(fd1, newfile1);
	fd_install(fd2, newfile2);
	retval[0] = fd1;
	retval[1] = fd2;
	return 0;

out_fput_1:
	fput(newfile1);
	put_unused_fd(fd2);
	put_unused_fd(fd1);
	sock_release(sock2);
	goto out;

out_put_unused_both:
	put_unused_fd(fd2);
out_put_unused_1:
	put_unused_fd(fd1);
out_release_both:
	sock_release(sock2);
out_release_1:
	sock_release(sock1);
out:
	return cloudabi_convert_errno(err);
}

cloudabi_errno_t cloudabi_sys_fd_create2(
    const struct cloudabi_sys_fd_create2_args *uap, unsigned long *retval)
{
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
	case CLOUDABI_FILETYPE_SOCKET_DGRAM:
		return do_socketpair(SOCK_DGRAM, retval);
	case CLOUDABI_FILETYPE_SOCKET_SEQPACKET:
		return do_socketpair(SOCK_SEQPACKET, retval);
	case CLOUDABI_FILETYPE_SOCKET_STREAM:
		return do_socketpair(SOCK_STREAM, retval);
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
	struct files_struct *files = current->files;
	struct file *file;
	int err = -EBADF;

	if (uap->to == uap->from) {
		rcu_read_lock();
		if (fcheck_files(files, uap->from))
			err = 0;
		rcu_read_unlock();
	} else {
		spin_lock(&files->file_lock);
		if (uap->to < files->fdtab.max_fds &&
		    (file = fcheck(uap->from)) != NULL)
			err = do_dup2(files, file, uap->to, 0);
		spin_unlock(&files->file_lock);
	}
	return err >= 0 ? 0 : cloudabi_convert_errno(err);
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

	offset = sys_lseek(uap->fd, uap->offset, whence);
	if (offset < 0)
		return cloudabi_convert_errno(offset);
	retval[0] = offset;
	return 0;
}

/* Extracts the CloudABI file descriptor type from st_mode. */
cloudabi_filetype_t cloudabi_convert_filetype_simple(umode_t mode)
{
	if (S_ISBLK(mode))
		return CLOUDABI_FILETYPE_BLOCK_DEVICE;
	else if (S_ISCHR(mode))
		return CLOUDABI_FILETYPE_CHARACTER_DEVICE;
	else if (S_ISDIR(mode))
		return CLOUDABI_FILETYPE_DIRECTORY;
	else if (S_ISFIFO(mode))
		return CLOUDABI_FILETYPE_FIFO;
	else if (S_ISREG(mode))
		return CLOUDABI_FILETYPE_REGULAR_FILE;
	else if (S_ISSOCK(mode)) {
		/* Inaccurate, but the best that we can do. */
		return CLOUDABI_FILETYPE_SOCKET_STREAM;
	} else if (S_ISLNK(mode))
		return CLOUDABI_FILETYPE_SYMBOLIC_LINK;
	else
		return CLOUDABI_FILETYPE_UNKNOWN;
}

/* Converts a file descriptor to a CloudABI file descriptor type. */
cloudabi_filetype_t cloudabi_convert_filetype(struct file *file)
{
	struct socket *sock;
	int err;

	/* Specialized file descriptor types. */
	/* TODO(ed): PROCESS still missing. */
	if (is_file_epoll(file))
		return CLOUDABI_FILETYPE_POLL;
	if (is_file_shmem(file))
		return CLOUDABI_FILETYPE_SHARED_MEMORY;

	/* Determine socket type. */
	sock = sock_from_file(file, &err);
	if (sock != NULL) {
		switch (sock->sk->sk_type) {
		case SOCK_DGRAM:
			return CLOUDABI_FILETYPE_SOCKET_DGRAM;
		case SOCK_SEQPACKET:
			return CLOUDABI_FILETYPE_SOCKET_SEQPACKET;
		case SOCK_STREAM:
			return CLOUDABI_FILETYPE_SOCKET_STREAM;
		default:
			return CLOUDABI_FILETYPE_UNKNOWN;
		}
	}

	/* Fall back to testing the type stored in the inode mode bits. */
	return cloudabi_convert_filetype_simple(
	    file->f_path.dentry->d_inode->i_mode);
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

	fsb.fs_filetype = cloudabi_convert_filetype(file);

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
	cloudabi_fdstat_t fsb;
	int oflags;

	if (copy_from_user(&fsb, uap->buf, sizeof(fsb)) != 0)
		return CLOUDABI_EFAULT;

	if (uap->flags == CLOUDABI_FDSTAT_FLAGS) {
		/* Convert flags. */
		oflags = 0;
		if (fsb.fs_flags & CLOUDABI_FDFLAG_APPEND)
			oflags |= O_APPEND;
		if (fsb.fs_flags & CLOUDABI_FDFLAG_DSYNC)
			oflags |= O_DSYNC;
		if (fsb.fs_flags & CLOUDABI_FDFLAG_NONBLOCK)
			oflags |= O_NONBLOCK;
		if (fsb.fs_flags &
		    (CLOUDABI_FDFLAG_SYNC | CLOUDABI_FDFLAG_RSYNC))
			oflags |= O_SYNC;
		return cloudabi_convert_errno(
		    sys_fcntl(uap->fd, F_SETFL, oflags));
	}
	return CLOUDABI_EINVAL;
}

cloudabi_errno_t cloudabi_sys_fd_sync(
    const struct cloudabi_sys_fd_sync_args *uap, unsigned long *retval)
{
	return cloudabi_convert_errno(sys_fsync(uap->fd));
}
