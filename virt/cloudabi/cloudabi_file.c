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
#include <linux/mount.h>
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
	struct dentry *new_dentry;
	struct path old_path, new_path;
	struct inode *delegated_inode = NULL;
	struct capsicum_rights rights;
	int how = 0;
	int error;

	if (uap->fd1 & AT_SYMLINK_FOLLOW)
		how |= LOOKUP_FOLLOW;
	cap_rights_init(&rights, CAP_LINKAT_TARGET);
retry:
	error = user_path_at_fixed_length(uap->fd1, uap->path1, uap->path1len,
	    how, &old_path, CAP_LINKAT_SOURCE);
	if (error != 0)
		return cloudabi_convert_errno(error);

	new_dentry = user_path_create_fixed_length(uap->fd2, uap->path2,
	    uap->path2len, &new_path, how & LOOKUP_REVAL, &rights);
	error = PTR_ERR(new_dentry);
	if (IS_ERR(new_dentry))
		goto out;

	if (old_path.mnt != new_path.mnt) {
		error = -EXDEV;
		goto out_dput;
	}
	/* TODO(ed): Properly call may_linkat(). */
	error = security_path_link(old_path.dentry, &new_path, new_dentry);
	if (error != 0)
		goto out_dput;
	error = vfs_link(old_path.dentry, new_path.dentry->d_inode, new_dentry,
	    &delegated_inode);
out_dput:
	done_path_create(&new_path, new_dentry);
	if (delegated_inode != NULL) {
		error = break_deleg_wait(&delegated_inode);
		if (error == 0) {
			path_put(&old_path);
			goto retry;
		}
	}
	if (retry_estale(error, how)) {
		path_put(&old_path);
		how |= LOOKUP_REVAL;
		goto retry;
	}
out:
	path_put(&old_path);
	return cloudabi_convert_errno(error);
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
	struct path path;
	struct inode *inode;
	unsigned int lookup_flags = 0;
	int error;

retry:
	error = user_path_at_fixed_length(uap->fd, uap->path, uap->pathlen,
	    lookup_flags, &path);
	if (error != 0)
		return cloudabi_convert_errno(error);

	inode = d_backing_inode(path.dentry);
	if (inode->i_op->readlink == NULL) {
		path_put(&path);
		return CLOUDABI_EINVAL;
	}

	error = security_inode_readlink(path.dentry);
	if (error == 0) {
		touch_atime(&path);
		error = inode->i_op->readlink(path.dentry, uap->buf,
		    uap->bufsize);
	}
	path_put(&path);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
	if (error < 0)
		return cloudabi_convert_errno(error);
	retval[0] = error;
	return 0;
}

cloudabi_errno_t cloudabi_sys_file_rename(
    const struct cloudabi_sys_file_rename_args *uap, unsigned long *retval)
{
	/* TODO(ed): Reenable this system call. */
#if 0
	struct dentry *old_dir, *new_dir;
	struct dentry *old_dentry, *new_dentry;
	struct dentry *trap;
	struct nameidata oldnd, newnd;
	struct inode *delegated_inode = NULL;
	struct filename *from;
	struct filename *to;
	struct capsicum_rights old_rights;
	struct capsicum_rights new_rights;
	unsigned int lookup_flags = 0;
	bool should_retry = false;
	int error;

	cap_rights_init(&old_rights, CAP_RENAMEAT);
	cap_rights_init(&new_rights, CAP_LINKAT);

retry:
	from = user_path_parent_fixed_length(uap->oldfd, uap->old, uap->oldlen,
	    &oldnd, lookup_flags, &old_rights);
	if (IS_ERR(from)) {
		error = PTR_ERR(from);
		goto exit;
	}

	to = user_path_parent_fixed_length(uap->newfd, uap->new, uap->newlen,
	    &newnd, lookup_flags, &new_rights);
	if (IS_ERR(to)) {
		error = PTR_ERR(to);
		goto exit1;
	}

	if (oldnd.path.mnt != newnd.path.mnt) {
		error = -EXDEV;
		goto exit2;
	}

	old_dir = oldnd.path.dentry;
	new_dir = newnd.path.dentry;
	if (oldnd.last_type != LAST_NORM || newnd.last_type != LAST_NORM) {
		error = -EINVAL;
		goto exit2;
	}

	error = mnt_want_write(oldnd.path.mnt);
	if (error != 0)
		goto exit2;

	oldnd.flags &= ~LOOKUP_PARENT;
	newnd.flags &= ~LOOKUP_PARENT;
	newnd.flags |= LOOKUP_RENAME_TARGET;

retry_deleg:
	trap = lock_rename(new_dir, old_dir);

	old_dentry = lookup_hash(&oldnd);
	if (IS_ERR(old_dentry)) {
		error = PTR_ERR(old_dentry);
		goto exit3;
	}
	/* source must exist */
	if (d_is_negative(old_dentry)) {
		error = -ENOENT;
		goto exit4;
	}
	new_dentry = lookup_hash(&newnd);
	if (IS_ERR(new_dentry)) {
		error = PTR_ERR(new_dentry);
		goto exit4;
	}
	/* unless the source is a directory trailing slashes give -ENOTDIR */
	if (!d_is_dir(old_dentry)) {
		if (oldnd.last.name[oldnd.last.len]) {
			error = -ENOTDIR;
			goto exit5;
		}
		if (newnd.last.name[newnd.last.len]) {
			error = -ENOTDIR;
			goto exit5;
		}
	}
	/* source should not be ancestor of target */
	if (old_dentry == trap) {
		error = -EINVAL;
		goto exit5;
	}
	/* target should not be an ancestor of source */
	if (new_dentry == trap) {
		error = -ENOTEMPTY;
		goto exit5;
	}

	error = security_path_rename(&oldnd.path, old_dentry,
				     &newnd.path, new_dentry, 0);
	if (error != 0)
		goto exit5;
	error = vfs_rename(old_dir->d_inode, old_dentry,
			   new_dir->d_inode, new_dentry,
			   &delegated_inode, 0);
exit5:
	dput(new_dentry);
exit4:
	dput(old_dentry);
exit3:
	unlock_rename(new_dir, old_dir);
	if (delegated_inode) {
		error = break_deleg_wait(&delegated_inode);
		if (error == 0)
			goto retry_deleg;
	}
	mnt_drop_write(oldnd.path.mnt);
exit2:
	if (retry_estale(error, lookup_flags))
		should_retry = true;
	path_put(&newnd.path);
	putname(to);
exit1:
	path_put(&oldnd.path);
	putname(from);
	if (should_retry) {
		should_retry = false;
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
exit:
	return cloudabi_convert_errno(error);
#endif
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

static void
convert_utimens_arguments(const cloudabi_filestat_t *fs,
    cloudabi_fsflags_t flags, struct timespec *ts)
{

	if ((flags & CLOUDABI_FILESTAT_ATIM_NOW) != 0) {
		ts[0].tv_nsec = UTIME_NOW;
	} else if ((flags & CLOUDABI_FILESTAT_ATIM) != 0) {
		ts[0].tv_sec = fs->st_atim / NSEC_PER_SEC;
		ts[0].tv_nsec = fs->st_atim % NSEC_PER_SEC;
	} else {
		ts[0].tv_nsec = UTIME_OMIT;
	}

	if ((flags & CLOUDABI_FILESTAT_MTIM_NOW) != 0) {
		ts[1].tv_nsec = UTIME_NOW;
	} else if ((flags & CLOUDABI_FILESTAT_MTIM) != 0) {
		ts[1].tv_sec = fs->st_mtim / NSEC_PER_SEC;
		ts[1].tv_nsec = fs->st_mtim % NSEC_PER_SEC;
	} else {
		ts[1].tv_nsec = UTIME_OMIT;
	}
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
	cloudabi_filestat_t fs;

	if (copy_from_user(&fs, uap->buf, sizeof(fs)) != 0)
		return CLOUDABI_EFAULT;

	if ((uap->flags & CLOUDABI_FILESTAT_SIZE) != 0) {
		/* Call into sys_ftruncate() for file truncation. */
		if ((uap->flags & ~CLOUDABI_FILESTAT_SIZE) != 0)
			return CLOUDABI_EINVAL;
		return cloudabi_convert_errno(
		    sys_ftruncate(uap->fd, fs.st_size));
	} else if ((uap->flags & (CLOUDABI_FILESTAT_ATIM |
	    CLOUDABI_FILESTAT_ATIM_NOW | CLOUDABI_FILESTAT_MTIM |
	    CLOUDABI_FILESTAT_MTIM_NOW)) != 0) {
		struct timespec ts[2];

		/* Call into do_utimes() for timestamp modification. */
		if ((uap->flags & ~(CLOUDABI_FILESTAT_ATIM |
		    CLOUDABI_FILESTAT_ATIM_NOW | CLOUDABI_FILESTAT_MTIM |
		    CLOUDABI_FILESTAT_MTIM_NOW)) != 0)
			return (EINVAL);
		convert_utimens_arguments(&fs, uap->flags, ts);
		return cloudabi_convert_errno(
		    do_utimes(uap->fd, NULL, ts, 0));
	}
	return CLOUDABI_EINVAL;
}

cloudabi_errno_t cloudabi_sys_file_stat_get(
    const struct cloudabi_sys_file_stat_get_args *uap, unsigned long *retval)
{
	struct kstat sb;
	struct path path;
	cloudabi_filestat_t csb;
	unsigned int lookup_flags;
	int error;

	lookup_flags = (uap->fd & CLOUDABI_LOOKUP_SYMLINK_FOLLOW) != 0 ?
	    LOOKUP_FOLLOW : 0;
retry:
	error = user_path_at_fixed_length(uap->fd, uap->path, uap->pathlen,
	    lookup_flags, &path, CAP_FSTAT);
	if (error != 0)
		return cloudabi_convert_errno(error);

	error = vfs_getattr(&path, &sb);
	path_put(&path);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
	if (error != 0)
		return cloudabi_convert_errno(error);

	/* Convert results and return them. */
	convert_stat(&sb, &csb);
	return copy_to_user(uap->buf, &csb, sizeof(csb)) ? CLOUDABI_EFAULT : 0;
}

cloudabi_errno_t cloudabi_sys_file_stat_put(
    const struct cloudabi_sys_file_stat_put_args *uap, unsigned long *retval)
{
	return CLOUDABI_ENOSYS;
}

cloudabi_errno_t cloudabi_sys_file_symlink(
    const struct cloudabi_sys_file_symlink_args *uap, unsigned long *retval)
{
	int error;
	struct filename *from;
	struct dentry *dentry;
	struct path path;
	unsigned int lookup_flags = 0;
	struct capsicum_rights rights;

	from = getname_fixed_length(uap->path1, uap->path1len);
	if (IS_ERR(from))
		return cloudabi_convert_errno(PTR_ERR(from));
	cap_rights_init(&rights, CAP_SYMLINKAT);
retry:
	dentry = user_path_create_fixed_length(uap->fd2, uap->path2,
	    uap->path2len, &path, lookup_flags, &rights);
	error = PTR_ERR(dentry);
	if (IS_ERR(dentry))
		goto out_putname;

	error = security_path_symlink(&path, dentry, from->name);
	if (error == 0)
		error = vfs_symlink(path.dentry->d_inode, dentry, from->name);
	done_path_create(&path, dentry);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
out_putname:
	putname(from);
	return cloudabi_convert_errno(error);
}

cloudabi_errno_t cloudabi_sys_file_unlink(
    const struct cloudabi_sys_file_unlink_args *uap, unsigned long *retval)
{
	return CLOUDABI_ENOSYS;
}
