/*
 * CloudABI filesystem operations.
 *
 * Based on linux/fs/namei.c.
 *
 * Copyright (c) 2015 Nuxi, https://nuxi.nl/
 * Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <linux/capsicum.h>
#include <linux/dcache.h>
#include <linux/fadvise.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>

#include "cloudabi_syscalldefs.h"
#include "cloudabi_syscalls.h"
#include "cloudabi_util.h"

cloudabi_errno_t cloudabi_sys_file_advise(
    const struct cloudabi_sys_file_advise_args *uap, unsigned long *retval)
{
	int advice;

	switch (uap->advice) {
	case CLOUDABI_ADVICE_DONTNEED:
		advice = POSIX_FADV_DONTNEED;
		break;
	case CLOUDABI_ADVICE_NOREUSE:
		advice = POSIX_FADV_NOREUSE;
		break;
	case CLOUDABI_ADVICE_NORMAL:
		advice = POSIX_FADV_NORMAL;
		break;
	case CLOUDABI_ADVICE_RANDOM:
		advice = POSIX_FADV_RANDOM;
		break;
	case CLOUDABI_ADVICE_SEQUENTIAL:
		advice = POSIX_FADV_SEQUENTIAL;
		break;
	case CLOUDABI_ADVICE_WILLNEED:
		advice = POSIX_FADV_WILLNEED;
		break;
	default:
		return CLOUDABI_EINVAL;
	}
	return cloudabi_convert_errno(sys_fadvise64_64(uap->fd, uap->offset,
	    uap->len, advice));
}

cloudabi_errno_t cloudabi_sys_file_allocate(
    const struct cloudabi_sys_file_allocate_args *uap, unsigned long *retval)
{
	return cloudabi_convert_errno(sys_fallocate(uap->fd, 0, uap->offset,
	    uap->len));
}

cloudabi_errno_t cloudabi_sys_file_create(
    const struct cloudabi_sys_file_create_args *uap, unsigned long *retval)
{
	struct dentry *dentry;
	struct path path;
	int error;
	unsigned int lookup_flags;
	struct capsicum_rights rights;
	umode_t mode;

	switch (uap->type) {
	case CLOUDABI_FILETYPE_DIRECTORY:
		lookup_flags = 0;
		cap_rights_init(&rights, CAP_LOOKUP, CAP_MKDIRAT);
		break;
	case CLOUDABI_FILETYPE_FIFO:
		lookup_flags = LOOKUP_DIRECTORY;
		cap_rights_init(&rights, CAP_LOOKUP, CAP_MKFIFOAT);
		break;
	default:
		return CLOUDABI_EINVAL;
	}

retry:
	dentry = user_path_create_fixed_length(uap->fd, uap->path, uap->pathlen,
	    &path, lookup_flags, &rights);
	if (IS_ERR(dentry)) {
		error = PTR_ERR(dentry);
		goto out;
	}

	mode = 0777;
	if (!IS_POSIXACL(path.dentry->d_inode))
		mode &= ~current_umask();

	switch (uap->type) {
	case CLOUDABI_FILETYPE_DIRECTORY:
		error = security_path_mkdir(&path, dentry, mode);
		if (error == 0)
			error = vfs_mkdir(path.dentry->d_inode, dentry, mode);
		break;
	case CLOUDABI_FILETYPE_FIFO:
		mode |= S_IFIFO;
		error = security_path_mknod(&path, dentry, mode, 0);
		if (error == 0)
			error = vfs_mknod(path.dentry->d_inode, dentry, mode,0);
		break;
	}

	done_path_create(&path, dentry);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
out:
	return cloudabi_convert_errno(error);
}

cloudabi_errno_t cloudabi_sys_file_link(
    const struct cloudabi_sys_file_link_args *uap, unsigned long *retval)
{
	return CLOUDABI_ENOSYS;
}

cloudabi_errno_t cloudabi_sys_file_open(
    const struct cloudabi_sys_file_open_args *uap, unsigned long *retval)
{
	cloudabi_fdstat_t fds;
	long fd;
	int oflags;

	/* Copy in initial file descriptor properties. */
	if (copy_from_user(&fds, uap->fds, sizeof(fds)) != 0)
		return CLOUDABI_EFAULT;

	/* Translate flags. */
	oflags = O_NOCTTY;
#define	COPY_FLAG(flag) do {						\
	if (uap->oflags & CLOUDABI_O_##flag)				\
		oflags |= O_##flag;					\
} while (0)
	COPY_FLAG(CREAT);
	COPY_FLAG(DIRECTORY);
	COPY_FLAG(EXCL);
	COPY_FLAG(TRUNC);
#undef COPY_FLAG
#define	COPY_FLAG(flag) do {						\
	if (fds.fs_flags & CLOUDABI_FDFLAG_##flag)			\
		oflags |= O_##flag;					\
} while (0)
	COPY_FLAG(APPEND);
	COPY_FLAG(DSYNC);
	COPY_FLAG(NONBLOCK);
#undef COPY_FLAG
	if (fds.fs_flags & (CLOUDABI_FDFLAG_SYNC | CLOUDABI_FDFLAG_RSYNC))
		oflags |= O_SYNC;
	if ((uap->fd & CLOUDABI_LOOKUP_SYMLINK_FOLLOW) == 0)
		oflags |= O_NOFOLLOW;

	/* Roughly convert rights to open() access mode. */
	if ((fds.fs_rights_base &
	    (CLOUDABI_RIGHT_FD_READ | CLOUDABI_RIGHT_FILE_READDIR)) != 0 &&
	    (fds.fs_rights_base & CLOUDABI_RIGHT_FD_WRITE) != 0)
		oflags |= O_RDWR;
	else if ((fds.fs_rights_base &
	    (CLOUDABI_RIGHT_FD_READ | CLOUDABI_RIGHT_FILE_READDIR)) != 0)
		oflags |= O_RDONLY;
	else if ((fds.fs_rights_base & CLOUDABI_RIGHT_FD_WRITE) != 0)
		oflags |= O_WRONLY;
	else if ((fds.fs_rights_base &
	    (CLOUDABI_RIGHT_PROC_EXEC | CLOUDABI_RIGHT_FILE_OPEN)) != 0)
		oflags |= O_RDONLY;
	else
		return CLOUDABI_EINVAL;

	/* TODO(ed): Respect path length! */
	fd = sys_openat(uap->fd, uap->path, oflags, 0777);
	if (fd < 0)
		return cloudabi_convert_errno(fd);
	retval[0] = fd;
	return 0;
}

cloudabi_errno_t cloudabi_sys_file_readdir(
    const struct cloudabi_sys_file_readdir_args *uap, unsigned long *retval)
{
	return CLOUDABI_ENOSYS;
}

cloudabi_errno_t cloudabi_sys_file_readlink(
    const struct cloudabi_sys_file_readlink_args *uap, unsigned long *retval)
{
	return CLOUDABI_ENOSYS;
}

cloudabi_errno_t cloudabi_sys_file_rename(
    const struct cloudabi_sys_file_rename_args *uap, unsigned long *retval)
{
	return CLOUDABI_ENOSYS;
}

/* Converts a struct timespec to a timestamp in nanoseconds since the Epoch. */
static cloudabi_timestamp_t
convert_timestamp(const struct timespec *ts)
{
	cloudabi_timestamp_t s, ns;

	/* Timestamps from before the Epoch cannot be expressed. */
	if (ts->tv_sec < 0)
		return 0;

	s = ts->tv_sec;
	ns = ts->tv_nsec;
	if (s > UINT64_MAX / NSEC_PER_SEC || (s == UINT64_MAX / NSEC_PER_SEC &&
	    ns > UINT64_MAX % NSEC_PER_SEC)) {
		/* Addition of seconds would cause an overflow. */
		ns = UINT64_MAX;
	} else {
		ns += s * NSEC_PER_SEC;
	}
	return ns;
}

/* Converts a Linux stat structure to a CloudABI stat structure. */
static void
convert_stat(const struct kstat *sb, cloudabi_filestat_t *csb)
{
	cloudabi_filestat_t res = {
		.st_dev		= sb->dev,
		.st_ino		= sb->ino,
		.st_nlink	= sb->nlink,
		.st_size	= sb->size,
		.st_atim	= convert_timestamp(&sb->atime),
		.st_mtim	= convert_timestamp(&sb->mtime),
		.st_ctim	= convert_timestamp(&sb->ctime),
	};

	/* TODO(ed): How can we derive the file type more accurately? */
	if (S_ISBLK(sb->mode))
		res.st_filetype = CLOUDABI_FILETYPE_BLOCK_DEVICE;
	else if (S_ISCHR(sb->mode))
		res.st_filetype = CLOUDABI_FILETYPE_CHARACTER_DEVICE;
	else if (S_ISDIR(sb->mode))
		res.st_filetype = CLOUDABI_FILETYPE_DIRECTORY;
	else if (S_ISFIFO(sb->mode))
		res.st_filetype = CLOUDABI_FILETYPE_FIFO;
	else if (S_ISREG(sb->mode))
		res.st_filetype = CLOUDABI_FILETYPE_REGULAR_FILE;
	else if (S_ISSOCK(sb->mode)) {
		/* Inaccurate, but the best that we can do. */
		res.st_filetype = CLOUDABI_FILETYPE_SOCKET_STREAM;
	} else if (S_ISLNK(sb->mode))
		res.st_filetype = CLOUDABI_FILETYPE_SYMBOLIC_LINK;
	else
		res.st_filetype = CLOUDABI_FILETYPE_UNKNOWN;
	*csb = res;
}

cloudabi_errno_t cloudabi_sys_file_stat_fget(
    const struct cloudabi_sys_file_stat_fget_args *uap, unsigned long *retval)
{
	struct fd fd;
	struct kstat sb;
	cloudabi_filestat_t csb;
	int error;

	fd = fdgetr_raw(uap->fd, CAP_FSTAT);
	if (IS_ERR(fd.file))
		return cloudabi_convert_errno(PTR_ERR(fd.file));
	error = vfs_getattr(&fd.file->f_path, &sb);
	fdput(fd);
	if (error != 0)
		return cloudabi_convert_errno(error);

	/* Convert results and return them. */
	convert_stat(&sb, &csb);
	return copy_to_user(uap->buf, &csb, sizeof(csb)) ? CLOUDABI_EFAULT : 0;
}

cloudabi_errno_t cloudabi_sys_file_stat_fput(
    const struct cloudabi_sys_file_stat_fput_args *uap, unsigned long *retval)
{
	return CLOUDABI_ENOSYS;
}

cloudabi_errno_t cloudabi_sys_file_stat_get(
    const struct cloudabi_sys_file_stat_get_args *uap, unsigned long *retval)
{
	return CLOUDABI_ENOSYS;
}

cloudabi_errno_t cloudabi_sys_file_stat_put(
    const struct cloudabi_sys_file_stat_put_args *uap, unsigned long *retval)
{
	return CLOUDABI_ENOSYS;
}

cloudabi_errno_t cloudabi_sys_file_symlink(
    const struct cloudabi_sys_file_symlink_args *uap, unsigned long *retval)
{
	return CLOUDABI_ENOSYS;
}

cloudabi_errno_t cloudabi_sys_file_unlink(
    const struct cloudabi_sys_file_unlink_args *uap, unsigned long *retval)
{
	return CLOUDABI_ENOSYS;
}
