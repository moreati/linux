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

#include <linux/anon_inodes.h>
#include <linux/audit.h>
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

/* Translation between CloudABI and Capsicum rights. */
#define RIGHTS_MAPPINGS \
	MAPPING(CLOUDABI_RIGHT_FD_DATASYNC, CAP_FSYNC)			\
	MAPPING(CLOUDABI_RIGHT_FD_READ, CAP_READ)			\
	MAPPING(CLOUDABI_RIGHT_FD_SEEK, CAP_SEEK)			\
	MAPPING(CLOUDABI_RIGHT_FD_STAT_PUT_FLAGS, CAP_FCNTL)		\
	MAPPING(CLOUDABI_RIGHT_FD_SYNC, CAP_FSYNC)			\
	MAPPING(CLOUDABI_RIGHT_FD_TELL, CAP_SEEK_TELL)			\
	MAPPING(CLOUDABI_RIGHT_FD_WRITE, CAP_WRITE)			\
	MAPPING(CLOUDABI_RIGHT_FILE_ADVISE)				\
	MAPPING(CLOUDABI_RIGHT_FILE_ALLOCATE, CAP_WRITE)		\
	MAPPING(CLOUDABI_RIGHT_FILE_CREATE_DIRECTORY, CAP_MKDIRAT)	\
	MAPPING(CLOUDABI_RIGHT_FILE_CREATE_FILE, CAP_CREATE)		\
	MAPPING(CLOUDABI_RIGHT_FILE_CREATE_FIFO, CAP_MKFIFOAT)		\
	MAPPING(CLOUDABI_RIGHT_FILE_LINK_SOURCE, CAP_LINKAT_SOURCE)	\
	MAPPING(CLOUDABI_RIGHT_FILE_LINK_TARGET, CAP_LINKAT_TARGET)	\
	MAPPING(CLOUDABI_RIGHT_FILE_OPEN, CAP_LOOKUP)			\
	MAPPING(CLOUDABI_RIGHT_FILE_READDIR, CAP_READ)			\
	MAPPING(CLOUDABI_RIGHT_FILE_READLINK, CAP_LOOKUP)		\
	MAPPING(CLOUDABI_RIGHT_FILE_RENAME_SOURCE, CAP_RENAMEAT_SOURCE)	\
	MAPPING(CLOUDABI_RIGHT_FILE_RENAME_TARGET, CAP_RENAMEAT_TARGET)	\
	MAPPING(CLOUDABI_RIGHT_FILE_STAT_FGET, CAP_FSTAT)		\
	MAPPING(CLOUDABI_RIGHT_FILE_STAT_FPUT_SIZE, CAP_FTRUNCATE)	\
	MAPPING(CLOUDABI_RIGHT_FILE_STAT_FPUT_TIMES, CAP_FUTIMES)	\
	MAPPING(CLOUDABI_RIGHT_FILE_STAT_GET, CAP_FSTATAT)		\
	MAPPING(CLOUDABI_RIGHT_FILE_STAT_PUT_TIMES, CAP_FUTIMESAT)	\
	MAPPING(CLOUDABI_RIGHT_FILE_SYMLINK, CAP_SYMLINKAT)		\
	MAPPING(CLOUDABI_RIGHT_FILE_UNLINK, CAP_UNLINKAT)		\
	MAPPING(CLOUDABI_RIGHT_MEM_MAP, CAP_MMAP)			\
	MAPPING(CLOUDABI_RIGHT_MEM_MAP_EXEC, CAP_MMAP_X)		\
	MAPPING(CLOUDABI_RIGHT_POLL_FD_READWRITE, CAP_POLL_EVENT)	\
	MAPPING(CLOUDABI_RIGHT_POLL_MODIFY, CAP_KQUEUE_CHANGE)		\
	MAPPING(CLOUDABI_RIGHT_POLL_PROC_TERMINATE, CAP_PDWAIT)		\
	MAPPING(CLOUDABI_RIGHT_POLL_WAIT, CAP_KQUEUE_EVENT)		\
	MAPPING(CLOUDABI_RIGHT_PROC_EXEC, CAP_FEXECVE)			\
	MAPPING(CLOUDABI_RIGHT_SOCK_ACCEPT, CAP_ACCEPT)			\
	MAPPING(CLOUDABI_RIGHT_SOCK_BIND_DIRECTORY, CAP_BINDAT)		\
	MAPPING(CLOUDABI_RIGHT_SOCK_BIND_SOCKET, CAP_BIND)		\
	MAPPING(CLOUDABI_RIGHT_SOCK_CONNECT_DIRECTORY, CAP_CONNECTAT)	\
	MAPPING(CLOUDABI_RIGHT_SOCK_CONNECT_SOCKET, CAP_CONNECT)	\
	MAPPING(CLOUDABI_RIGHT_SOCK_LISTEN, CAP_LISTEN)			\
	MAPPING(CLOUDABI_RIGHT_SOCK_SHUTDOWN, CAP_SHUTDOWN)		\
	MAPPING(CLOUDABI_RIGHT_SOCK_STAT_GET, CAP_GETPEERNAME,		\
	    CAP_GETSOCKNAME, CAP_GETSOCKOPT)

cloudabi_errno_t cloudabi_sys_fd_close(cloudabi_fd_t fd)
{
	return cloudabi_convert_errno(sys_close(fd));
}

static cloudabi_errno_t fd_create_shared_memory(cloudabi_fd_t *fd)
{
	struct capsicum_rights rights;
	struct file *file, *installfile;
	int newfd;

	newfd = get_unused_fd_flags(0);
	if (newfd < 0)
		return cloudabi_convert_errno(newfd);

	file = shmem_file_setup("CloudABI shared memory", 0, VM_NORESERVE);
	if (IS_ERR(file)) {
		put_unused_fd(newfd);
		return cloudabi_convert_errno(PTR_ERR(file));
	}
	file->f_flags |= O_RDWR | O_LARGEFILE;

	cap_rights_init(&rights, CAP_FSTAT, CAP_FTRUNCATE, CAP_MMAP_RWX);
	installfile = capsicum_file_install(&rights, file);
	if (IS_ERR(installfile)) {
		put_unused_fd(newfd);
		fput(file);
		return cloudabi_convert_errno(PTR_ERR(installfile));
	}

	fd_install(newfd, installfile);
	*fd = newfd;
	return 0;
}

cloudabi_errno_t cloudabi_sys_fd_create1(cloudabi_filetype_t type,
    cloudabi_fd_t *fd)
{
	long newfd;

	switch (type) {
	case CLOUDABI_FILETYPE_POLL:
		return cloudabi_poll_create(fd);
	case CLOUDABI_FILETYPE_SHARED_MEMORY:
		return fd_create_shared_memory(fd);
	case CLOUDABI_FILETYPE_SOCKET_DGRAM:
		newfd = sys_socket(AF_UNIX, SOCK_DGRAM, 0);
		break;
	case CLOUDABI_FILETYPE_SOCKET_SEQPACKET:
		newfd = sys_socket(AF_UNIX, SOCK_SEQPACKET, 0);
		break;
	case CLOUDABI_FILETYPE_SOCKET_STREAM:
		newfd = sys_socket(AF_UNIX, SOCK_STREAM, 0);
		break;
	default:
		return CLOUDABI_EINVAL;
	}

	if (newfd < 0)
		return cloudabi_convert_errno(newfd);
	*fd = newfd;
	return 0;
}

static cloudabi_errno_t fd_create_pipe(cloudabi_fd_t *fd1, cloudabi_fd_t *fd2)
{
	struct capsicum_rights rights;
	struct file *files[2], *installfile;
	int fds[2];
	int error;

	/* Create a pipe. */
	error = create_pipe_files(files, 0);
	if (error != 0)
		return cloudabi_convert_errno(error);

	/* Apply Capsicum restrictions to the read file descriptor. */
	cap_rights_init(&rights, CAP_EVENT, CAP_FCNTL, CAP_FSTAT, CAP_READ);
	rights.fcntls = CAP_FCNTL_GETFL | CAP_FCNTL_SETFL;
	installfile = capsicum_file_install(&rights, files[0]);
	if (IS_ERR(installfile)) {
		error = PTR_ERR(installfile);
		goto bad;
	}
	files[0] = installfile;

	/* Apply Capsicum restrictions to the write file descriptor. */
	cap_rights_init(&rights, CAP_EVENT, CAP_FCNTL, CAP_FSTAT, CAP_WRITE);
	rights.fcntls = CAP_FCNTL_GETFL | CAP_FCNTL_SETFL;
	installfile = capsicum_file_install(&rights, files[1]);
	if (IS_ERR(installfile)) {
		error = PTR_ERR(installfile);
		goto bad;
	}
	files[1] = installfile;

	/* Allocate file descriptor table entries. */
	fds[0] = get_unused_fd_flags(0);
	if (fds[0] < 0) {
		error = fds[0];
		goto bad;
	}
	fds[1] = get_unused_fd_flags(0);
	if (fds[1] < 0) {
		put_unused_fd(fds[0]);
		error = fds[1];
		goto bad;
	}

	/* Return the pipe. */
	audit_fd_pair(fds[0], fds[1]);
	fd_install(fds[0], files[0]);
	fd_install(fds[1], files[1]);
	*fd1 = fds[0];
	*fd2 = fds[1];
	return 0;

bad:
	fput(files[0]);
	fput(files[1]);
	return cloudabi_convert_errno(error);
}

static cloudabi_errno_t fd_create_socketpair(int type, cloudabi_fd_t *fd1,
    cloudabi_fd_t *fd2)
{
	struct socket *sock1, *sock2;
	int newfd1, newfd2, err;
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

	newfd1 = get_unused_fd_flags(0);
	if (unlikely(newfd1 < 0)) {
		err = newfd1;
		goto out_release_both;
	}

	newfd2 = get_unused_fd_flags(0);
	if (unlikely(newfd2 < 0)) {
		err = newfd2;
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

	audit_fd_pair(newfd1, newfd2);

	fd_install(newfd1, newfile1);
	fd_install(newfd2, newfile2);
	*fd1 = newfd1;
	*fd2 = newfd2;
	return 0;

out_fput_1:
	fput(newfile1);
	put_unused_fd(newfd2);
	put_unused_fd(newfd1);
	sock_release(sock2);
	goto out;

out_put_unused_both:
	put_unused_fd(newfd2);
out_put_unused_1:
	put_unused_fd(newfd1);
out_release_both:
	sock_release(sock2);
out_release_1:
	sock_release(sock1);
out:
	return cloudabi_convert_errno(err);
}

cloudabi_errno_t cloudabi_sys_fd_create2(cloudabi_filetype_t type,
    cloudabi_fd_t *fd1, cloudabi_fd_t *fd2)
{
	switch (type) {
	case CLOUDABI_FILETYPE_FIFO:
		return fd_create_pipe(fd1, fd2);
	case CLOUDABI_FILETYPE_SOCKET_DGRAM:
		return fd_create_socketpair(SOCK_DGRAM, fd1, fd2);
	case CLOUDABI_FILETYPE_SOCKET_SEQPACKET:
		return fd_create_socketpair(SOCK_SEQPACKET, fd1, fd2);
	case CLOUDABI_FILETYPE_SOCKET_STREAM:
		return fd_create_socketpair(SOCK_STREAM, fd1, fd2);
	default:
		return CLOUDABI_EINVAL;
	}
}

cloudabi_errno_t cloudabi_sys_fd_datasync(cloudabi_fd_t fd)
{
	return cloudabi_convert_errno(sys_fdatasync(fd));
}

cloudabi_errno_t cloudabi_sys_fd_dup(cloudabi_fd_t from, cloudabi_fd_t *fd)
{
	long newfd;

	newfd = sys_dup(from);
	if (newfd < 0)
		return cloudabi_convert_errno(newfd);
	*fd = newfd;
	return 0;
}

cloudabi_errno_t cloudabi_sys_fd_replace(cloudabi_fd_t from, cloudabi_fd_t to)
{
	struct files_struct *files = current->files;
	struct file *file;
	int err = -EBADF;

	if (from == to) {
		rcu_read_lock();
		if (fcheck_files(files, from) != NULL)
			err = 0;
		rcu_read_unlock();
	} else {
		spin_lock(&files->file_lock);
		if ((file = fcheck_files(files, from)) != NULL &&
		    fcheck_files(files, to) != NULL) {
			err = do_dup2(files, file, to, 0);
		} else {
			spin_unlock(&files->file_lock);
		}
	}
	return err >= 0 ? 0 : cloudabi_convert_errno(err);
}

cloudabi_errno_t cloudabi_sys_fd_seek(cloudabi_fd_t fd,
    cloudabi_filedelta_t offset, cloudabi_whence_t whence,
    cloudabi_filesize_t *newoffset)
{
	unsigned int kwhence;
	long retval;

	switch (whence) {
	case CLOUDABI_WHENCE_CUR:
		kwhence = SEEK_CUR;
		break;
	case CLOUDABI_WHENCE_END:
		kwhence = SEEK_END;
		break;
	case CLOUDABI_WHENCE_SET:
		kwhence = SEEK_SET;
		break;
	default:
		return CLOUDABI_EINVAL;
	}

	retval = sys_lseek(fd, offset, kwhence);
	if (retval < 0)
		return cloudabi_convert_errno(retval);
	*newoffset = retval;
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
	if (cloudabi_is_poll(file))
		return CLOUDABI_FILETYPE_POLL;
	if (is_file_clonefd(file))
		return CLOUDABI_FILETYPE_PROCESS;
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

/* Removes rights that conflict with the file descriptor type. */
void cloudabi_remove_conflicting_rights(cloudabi_filetype_t filetype,
    cloudabi_rights_t *base, cloudabi_rights_t *inheriting)
{

	/*
	 * CloudABI has a small number of additional rights bits to
	 * disambiguate between multiple purposes. Remove the bits that
	 * don't apply to the type of the file descriptor.
	 *
	 * As file descriptor access modes (O_ACCMODE) has been fully
	 * replaced by rights bits, CloudABI distinguishes between
	 * rights that apply to the file descriptor itself (base) versus
	 * rights of new file descriptors derived from them
	 * (inheriting). The code below approximates the pair by
	 * decomposing depending on the file descriptor type.
	 *
	 * We need to be somewhat accurate about which actions can
	 * actually be performed on the file descriptor, as functions
	 * like fcntl(fd, F_GETFL) are emulated on top of this.
	 */
	switch (filetype) {
	case CLOUDABI_FILETYPE_DIRECTORY:
		*base &= CLOUDABI_RIGHT_FD_STAT_PUT_FLAGS |
		    CLOUDABI_RIGHT_FD_SYNC | CLOUDABI_RIGHT_FILE_ADVISE |
		    CLOUDABI_RIGHT_FILE_CREATE_DIRECTORY |
		    CLOUDABI_RIGHT_FILE_CREATE_FILE |
		    CLOUDABI_RIGHT_FILE_CREATE_FIFO |
		    CLOUDABI_RIGHT_FILE_LINK_SOURCE |
		    CLOUDABI_RIGHT_FILE_LINK_TARGET |
		    CLOUDABI_RIGHT_FILE_OPEN |
		    CLOUDABI_RIGHT_FILE_READDIR |
		    CLOUDABI_RIGHT_FILE_READLINK |
		    CLOUDABI_RIGHT_FILE_RENAME_SOURCE |
		    CLOUDABI_RIGHT_FILE_RENAME_TARGET |
		    CLOUDABI_RIGHT_FILE_STAT_FGET |
		    CLOUDABI_RIGHT_FILE_STAT_FPUT_TIMES |
		    CLOUDABI_RIGHT_FILE_STAT_GET |
		    CLOUDABI_RIGHT_FILE_STAT_PUT_TIMES |
		    CLOUDABI_RIGHT_FILE_SYMLINK |
		    CLOUDABI_RIGHT_FILE_UNLINK |
		    CLOUDABI_RIGHT_POLL_FD_READWRITE |
		    CLOUDABI_RIGHT_SOCK_BIND_DIRECTORY |
		    CLOUDABI_RIGHT_SOCK_CONNECT_DIRECTORY;
		*inheriting &= CLOUDABI_RIGHT_FD_DATASYNC |
		    CLOUDABI_RIGHT_FD_READ |
		    CLOUDABI_RIGHT_FD_SEEK |
		    CLOUDABI_RIGHT_FD_STAT_PUT_FLAGS |
		    CLOUDABI_RIGHT_FD_SYNC |
		    CLOUDABI_RIGHT_FD_TELL |
		    CLOUDABI_RIGHT_FD_WRITE |
		    CLOUDABI_RIGHT_FILE_ADVISE |
		    CLOUDABI_RIGHT_FILE_ALLOCATE |
		    CLOUDABI_RIGHT_FILE_CREATE_DIRECTORY |
		    CLOUDABI_RIGHT_FILE_CREATE_FILE |
		    CLOUDABI_RIGHT_FILE_CREATE_FIFO |
		    CLOUDABI_RIGHT_FILE_LINK_SOURCE |
		    CLOUDABI_RIGHT_FILE_LINK_TARGET |
		    CLOUDABI_RIGHT_FILE_OPEN |
		    CLOUDABI_RIGHT_FILE_READDIR |
		    CLOUDABI_RIGHT_FILE_READLINK |
		    CLOUDABI_RIGHT_FILE_RENAME_SOURCE |
		    CLOUDABI_RIGHT_FILE_RENAME_TARGET |
		    CLOUDABI_RIGHT_FILE_STAT_FGET |
		    CLOUDABI_RIGHT_FILE_STAT_FPUT_SIZE |
		    CLOUDABI_RIGHT_FILE_STAT_FPUT_TIMES |
		    CLOUDABI_RIGHT_FILE_STAT_GET |
		    CLOUDABI_RIGHT_FILE_STAT_PUT_TIMES |
		    CLOUDABI_RIGHT_FILE_SYMLINK |
		    CLOUDABI_RIGHT_FILE_UNLINK |
		    CLOUDABI_RIGHT_MEM_MAP |
		    CLOUDABI_RIGHT_MEM_MAP_EXEC |
		    CLOUDABI_RIGHT_POLL_FD_READWRITE |
		    CLOUDABI_RIGHT_PROC_EXEC |
		    CLOUDABI_RIGHT_SOCK_BIND_DIRECTORY |
		    CLOUDABI_RIGHT_SOCK_CONNECT_DIRECTORY;
		break;
	case CLOUDABI_FILETYPE_FIFO:
		*base &= CLOUDABI_RIGHT_FD_READ |
		    CLOUDABI_RIGHT_FD_STAT_PUT_FLAGS |
		    CLOUDABI_RIGHT_FD_WRITE |
		    CLOUDABI_RIGHT_FILE_STAT_FGET |
		    CLOUDABI_RIGHT_POLL_FD_READWRITE;
		*inheriting = 0;
		break;
	case CLOUDABI_FILETYPE_POLL:
		*base &= ~(CLOUDABI_RIGHT_FILE_ADVISE |
		    CLOUDABI_RIGHT_POLL_FD_READWRITE);
		*inheriting = 0;
		break;
	case CLOUDABI_FILETYPE_PROCESS:
		*base &= ~CLOUDABI_RIGHT_FILE_ADVISE;
		*inheriting = 0;
		break;
	case CLOUDABI_FILETYPE_REGULAR_FILE:
		*base &= CLOUDABI_RIGHT_FD_DATASYNC |
		    CLOUDABI_RIGHT_FD_READ |
		    CLOUDABI_RIGHT_FD_SEEK |
		    CLOUDABI_RIGHT_FD_STAT_PUT_FLAGS |
		    CLOUDABI_RIGHT_FD_SYNC |
		    CLOUDABI_RIGHT_FD_TELL |
		    CLOUDABI_RIGHT_FD_WRITE |
		    CLOUDABI_RIGHT_FILE_ADVISE |
		    CLOUDABI_RIGHT_FILE_ALLOCATE |
		    CLOUDABI_RIGHT_FILE_STAT_FGET |
		    CLOUDABI_RIGHT_FILE_STAT_FPUT_SIZE |
		    CLOUDABI_RIGHT_FILE_STAT_FPUT_TIMES |
		    CLOUDABI_RIGHT_MEM_MAP |
		    CLOUDABI_RIGHT_MEM_MAP_EXEC |
		    CLOUDABI_RIGHT_POLL_FD_READWRITE |
		    CLOUDABI_RIGHT_PROC_EXEC;
		*inheriting = 0;
		break;
	case CLOUDABI_FILETYPE_SHARED_MEMORY:
		*base &= ~(CLOUDABI_RIGHT_FD_SEEK |
		    CLOUDABI_RIGHT_FD_TELL |
		    CLOUDABI_RIGHT_FILE_ADVISE |
		    CLOUDABI_RIGHT_FILE_ALLOCATE |
		    CLOUDABI_RIGHT_FILE_READDIR);
		*inheriting = 0;
		break;
	case CLOUDABI_FILETYPE_SOCKET_DGRAM:
	case CLOUDABI_FILETYPE_SOCKET_SEQPACKET:
	case CLOUDABI_FILETYPE_SOCKET_STREAM:
		*base &= CLOUDABI_RIGHT_FD_READ |
		    CLOUDABI_RIGHT_FD_STAT_PUT_FLAGS |
		    CLOUDABI_RIGHT_FD_WRITE |
		    CLOUDABI_RIGHT_FILE_STAT_FGET |
		    CLOUDABI_RIGHT_POLL_FD_READWRITE |
		    CLOUDABI_RIGHT_SOCK_ACCEPT |
		    CLOUDABI_RIGHT_SOCK_BIND_SOCKET |
		    CLOUDABI_RIGHT_SOCK_CONNECT_SOCKET |
		    CLOUDABI_RIGHT_SOCK_LISTEN |
		    CLOUDABI_RIGHT_SOCK_SHUTDOWN |
		    CLOUDABI_RIGHT_SOCK_STAT_GET;
		break;
	default:
		*inheriting = 0;
		break;
	}
}

/* Converts Linux's Capsicum rights to CloudABI's set of rights. */
static void
convert_capabilities(const struct capsicum_rights *capabilities,
    cloudabi_filetype_t filetype, cloudabi_rights_t *base,
    cloudabi_rights_t *inheriting)
{
	struct capsicum_rights little;
	cloudabi_rights_t rights;

	/* Convert Linux bits to CloudABI bits. */
	rights = 0;
#define MAPPING(cloudabi, ...) do {				\
	cap_rights_init(&little, ##__VA_ARGS__);		\
	if (cap_rights_contains(capabilities, &little))		\
		rights |= (cloudabi);				\
} while (0);
	RIGHTS_MAPPINGS
#undef MAPPING

	*base = rights;
	*inheriting = rights;
	cloudabi_remove_conflicting_rights(filetype, base, inheriting);
}

cloudabi_errno_t cloudabi_sys_fd_stat_get(cloudabi_fd_t fd,
    cloudabi_fdstat_t __user *buf)
{
	struct capsicum_rights rights;
	cloudabi_fdstat_t fsb = {};
	struct fd f;
	const struct capsicum_rights *actual_rights;
	struct file *file;

	f = fdget_raw(fd);
	if (f.file == NULL)
		return CLOUDABI_EBADF;
	file = f.file;

	/* Obtain file descriptor capabilities. */
	cap_rights_init(&rights);
	file = capsicum_file_lookup(file, &rights, &actual_rights);
	rights = *actual_rights;

	/* Determine file descriptor type. */
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
	fdput(f);

	/* Convert capabilities to CloudABI rights. */
	convert_capabilities(&rights, fsb.fs_filetype,
	    &fsb.fs_rights_base, &fsb.fs_rights_inheriting);
	return copy_to_user(buf, &fsb, sizeof(fsb)) != 0 ? CLOUDABI_EFAULT : 0;
}

/* Converts CloudABI rights to a set of Capsicum capabilities. */
cloudabi_errno_t cloudabi_convert_rights(cloudabi_rights_t in,
                                         struct capsicum_rights *out)
{
	cap_rights_init(out);
	if (in & CLOUDABI_RIGHT_FD_STAT_PUT_FLAGS)
		out->fcntls |= CAP_FCNTL_SETFL;
#define MAPPING(cloudabi, ...) do {			\
	if (in & (cloudabi)) {				\
		cap_rights_set(out, ##__VA_ARGS__);	\
		in &= ~(cloudabi);			\
	}						\
} while (0);
	RIGHTS_MAPPINGS
#undef MAPPING
	if (in != 0)
		return CLOUDABI_ENOTCAPABLE;
	return 0;
}

cloudabi_errno_t cloudabi_sys_fd_stat_put(cloudabi_fd_t fd,
    const cloudabi_fdstat_t __user *buf, cloudabi_fdsflags_t flags)
{
	struct capsicum_rights rights;
	cloudabi_fdstat_t fsb;
	cloudabi_errno_t error;
	int oflags;

	if (copy_from_user(&fsb, buf, sizeof(fsb)) != 0)
		return CLOUDABI_EFAULT;

	if (flags == CLOUDABI_FDSTAT_FLAGS) {
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
		    sys_fcntl(fd, F_SETFL, oflags));
	} else if (flags == CLOUDABI_FDSTAT_RIGHTS) {
		/* Convert rights. */
		error = cloudabi_convert_rights(
		    fsb.fs_rights_base | fsb.fs_rights_inheriting, &rights);
		if (error != 0)
			return error;
		return cloudabi_convert_errno(
		    capsicum_rights_limit(fd, &rights));
	}
	return CLOUDABI_EINVAL;
}

cloudabi_errno_t cloudabi_sys_fd_sync(cloudabi_fd_t fd)
{
	return cloudabi_convert_errno(sys_fsync(fd));
}
