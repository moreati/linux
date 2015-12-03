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

#ifndef CLOUDABI_SYSCALLS_H
#define CLOUDABI_SYSCALLS_H

#include "cloudabi_syscalldefs.h"

/*
 * Structures with system call arguments.
 *
 * The system call entry code places all the arguments in an array on
 * the stack. We then cast the address of this array to a structure,
 * containing properly typed system call arguments.
 *
 * We need to ensure that the members in these structures are placed at
 * the right offset. Add leading or trailing padding to the members to
 * let them overlap with the array members correctly.
 */

#define PAD(type) \
	((sizeof(long) - (sizeof(type) % sizeof(long))) % sizeof(long))
#ifdef __LITTLE_ENDIAN
#define ARG(type, name)			\
	type name;			\
	char name##_pad[PAD(type)];
#else
#define ARG(type, name)			\
	char name##_pad[PAD(type)];	\
	type name;
#endif

struct cloudabi_sys_clock_res_get_args {
	ARG(cloudabi_clockid_t, clock_id);
};
struct cloudabi_sys_clock_time_get_args {
	ARG(cloudabi_clockid_t, clock_id);
	ARG(cloudabi_timestamp_t, precision);
};
struct cloudabi_sys_condvar_signal_args {
	ARG(cloudabi_condvar_t __user *, condvar);
	ARG(cloudabi_mflags_t, scope);
	ARG(cloudabi_nthreads_t, nwaiters);
};
struct cloudabi_sys_fd_close_args {
	ARG(cloudabi_fd_t, fd);
};
struct cloudabi_sys_fd_create1_args {
	ARG(cloudabi_filetype_t, type);
};
struct cloudabi_sys_fd_create2_args {
	ARG(cloudabi_filetype_t, type);
};
struct cloudabi_sys_fd_datasync_args {
	ARG(cloudabi_fd_t, fd);
};
struct cloudabi_sys_fd_dup_args {
	ARG(cloudabi_fd_t, from);
};
struct cloudabi_sys_fd_replace_args {
	ARG(cloudabi_fd_t, from);
	ARG(cloudabi_fd_t, to);
};
struct cloudabi_sys_fd_seek_args {
	ARG(cloudabi_fd_t, fd);
	ARG(cloudabi_filedelta_t, offset);
	ARG(cloudabi_whence_t, whence);
};
struct cloudabi_sys_fd_stat_get_args {
	ARG(cloudabi_fd_t, fd);
	ARG(cloudabi_fdstat_t __user *, buf);
};
struct cloudabi_sys_fd_stat_put_args {
	ARG(cloudabi_fd_t, fd);
	ARG(const cloudabi_fdstat_t __user *, buf);
	ARG(cloudabi_fdsflags_t, flags);
};
struct cloudabi_sys_fd_sync_args {
	ARG(cloudabi_fd_t, fd);
};
struct cloudabi_sys_file_advise_args {
	ARG(cloudabi_fd_t, fd);
	ARG(cloudabi_filesize_t, offset);
	ARG(cloudabi_filesize_t, len);
	ARG(cloudabi_advice_t, advice);
};
struct cloudabi_sys_file_allocate_args {
	ARG(cloudabi_fd_t, fd);
	ARG(cloudabi_filesize_t, offset);
	ARG(cloudabi_filesize_t, len);
};
struct cloudabi_sys_file_create_args {
	ARG(cloudabi_fd_t, fd);
	ARG(const char __user *, path);
	ARG(size_t, pathlen);
	ARG(cloudabi_filetype_t, type);
};
struct cloudabi_sys_file_link_args {
	ARG(cloudabi_lookup_t, fd1);
	ARG(const char __user *, path1);
	ARG(size_t, path1len);
	ARG(cloudabi_fd_t, fd2);
	ARG(const char __user *, path2);
	ARG(size_t, path2len);
};
struct cloudabi_sys_file_open_args {
	ARG(cloudabi_lookup_t, fd);
	ARG(const char __user *, path);
	ARG(size_t, pathlen);
	ARG(cloudabi_oflags_t, oflags);
	ARG(const cloudabi_fdstat_t __user *, fds);
};
struct cloudabi_sys_file_readdir_args {
	ARG(cloudabi_fd_t, fd);
	ARG(void __user *, buf);
	ARG(size_t, nbyte);
	ARG(cloudabi_dircookie_t, cookie);
};
struct cloudabi_sys_file_readlink_args {
	ARG(cloudabi_fd_t, fd);
	ARG(const char __user *, path);
	ARG(size_t, pathlen);
	ARG(void __user *, buf);
	ARG(size_t, bufsize);
};
struct cloudabi_sys_file_rename_args {
	ARG(cloudabi_fd_t, oldfd);
	ARG(const char __user *, old);
	ARG(size_t, oldlen);
	ARG(cloudabi_fd_t, newfd);
	ARG(const char __user *, new);
	ARG(size_t, newlen);
};
struct cloudabi_sys_file_stat_fget_args {
	ARG(cloudabi_fd_t, fd);
	ARG(cloudabi_filestat_t __user *, buf)
};
struct cloudabi_sys_file_stat_fput_args {
	ARG(cloudabi_fd_t, fd);
	ARG(const cloudabi_filestat_t __user *, buf)
	ARG(cloudabi_fsflags_t, flags);
};
struct cloudabi_sys_file_stat_get_args {
	ARG(cloudabi_lookup_t, fd);
	ARG(const char __user *, path);
	ARG(size_t, pathlen);
	ARG(cloudabi_filestat_t __user *, buf);
};
struct cloudabi_sys_file_stat_put_args {
	ARG(cloudabi_lookup_t, fd);
	ARG(const char __user *, path);
	ARG(size_t, pathlen);
	ARG(const cloudabi_filestat_t __user *, buf);
	ARG(cloudabi_fsflags_t, flags);
};
struct cloudabi_sys_file_symlink_args {
	ARG(const char __user *, path1);
	ARG(size_t, path1len);
	ARG(cloudabi_fd_t, fd2);
	ARG(const char __user *, path2);
	ARG(size_t, path2len);
};
struct cloudabi_sys_file_unlink_args {
	ARG(cloudabi_fd_t, fd);
	ARG(const char __user *, path);
	ARG(size_t, pathlen);
	ARG(cloudabi_ulflags_t, flag);
};
struct cloudabi_sys_lock_unlock_args {
	ARG(cloudabi_lock_t __user *, lock);
	ARG(cloudabi_mflags_t, scope);
};
struct cloudabi_sys_mem_advise_args {
	ARG(void __user *, addr);
	ARG(size_t, len);
	ARG(cloudabi_advice_t, advice);
};
struct cloudabi_sys_mem_lock_args {
	ARG(const void __user *, addr);
	ARG(size_t, len);
};
struct cloudabi_sys_mem_map_args {
	ARG(void __user *, addr);
	ARG(size_t, len);
	ARG(cloudabi_mprot_t, prot);
	ARG(cloudabi_mflags_t, flags);
	ARG(cloudabi_fd_t, fd);
	ARG(cloudabi_filesize_t, off);
};
struct cloudabi_sys_mem_protect_args {
	ARG(void __user *, addr);
	ARG(size_t, len);
	ARG(cloudabi_mprot_t, prot);
};
struct cloudabi_sys_mem_sync_args {
	ARG(void __user *, addr);
	ARG(size_t, len);
	ARG(cloudabi_msflags_t, flags);
};
struct cloudabi_sys_mem_unlock_args {
	ARG(const void __user *, addr);
	ARG(size_t, len);
};
struct cloudabi_sys_mem_unmap_args {
	ARG(void __user *, addr);
	ARG(size_t, len);
};
struct cloudabi_sys_proc_exit_args {
	ARG(cloudabi_exitcode_t, rval);
};
struct cloudabi_sys_proc_raise_args {
	ARG(cloudabi_signal_t, sig);
};
struct cloudabi_sys_random_get_args {
	ARG(void __user *, buf);
	ARG(size_t, nbyte);
};
struct cloudabi_sys_sock_accept_args {
	ARG(cloudabi_fd_t, s);
	ARG(cloudabi_sockstat_t __user *, buf);
};
struct cloudabi_sys_sock_bind_args {
	ARG(cloudabi_fd_t, s);
	ARG(cloudabi_fd_t, fd);
	ARG(const char __user *, path);
	ARG(size_t, pathlen);
};
struct cloudabi_sys_sock_connect_args {
	ARG(cloudabi_fd_t, s);
	ARG(cloudabi_fd_t, fd);
	ARG(const char __user *, path);
	ARG(size_t, pathlen);
};
struct cloudabi_sys_sock_listen_args {
	ARG(cloudabi_fd_t, s);
	ARG(cloudabi_backlog_t, backlog);
};
struct cloudabi_sys_sock_shutdown_args {
	ARG(cloudabi_fd_t, s);
	ARG(cloudabi_sdflags_t, how);
};
struct cloudabi_sys_sock_stat_get_args {
	ARG(cloudabi_fd_t, fd);
	ARG(cloudabi_sockstat_t __user *, buf);
	ARG(cloudabi_ssflags_t, flags);
};
struct cloudabi_sys_thread_exit_args {
	ARG(cloudabi_lock_t __user *, lock);
};
struct cloudabi_sys_thread_tcb_set_args {
	ARG(void __user *, tcb);
};

#undef PAD
#undef ARG

cloudabi_errno_t cloudabi_sys_clock_res_get(
    const struct cloudabi_sys_clock_res_get_args *, unsigned long *);
cloudabi_errno_t cloudabi_sys_clock_time_get(
    const struct cloudabi_sys_clock_time_get_args *, unsigned long *);
cloudabi_errno_t cloudabi_sys_condvar_signal(
    const struct cloudabi_sys_condvar_signal_args *, unsigned long *);
cloudabi_errno_t cloudabi_sys_enosys(const void *, unsigned long *);
cloudabi_errno_t cloudabi_sys_fd_close(
    const struct cloudabi_sys_fd_close_args *, unsigned long *);
cloudabi_errno_t cloudabi_sys_fd_create1(
    const struct cloudabi_sys_fd_create1_args *, unsigned long *);
cloudabi_errno_t cloudabi_sys_fd_create2(
    const struct cloudabi_sys_fd_create2_args *, unsigned long *);
cloudabi_errno_t cloudabi_sys_fd_datasync(
    const struct cloudabi_sys_fd_datasync_args *, unsigned long *);
cloudabi_errno_t cloudabi_sys_fd_dup(
    const struct cloudabi_sys_fd_dup_args *, unsigned long *);
cloudabi_errno_t cloudabi_sys_fd_replace(
    const struct cloudabi_sys_fd_replace_args *, unsigned long *);
cloudabi_errno_t cloudabi_sys_fd_seek(
    const struct cloudabi_sys_fd_seek_args *, unsigned long *);
cloudabi_errno_t cloudabi_sys_fd_stat_get(
    const struct cloudabi_sys_fd_stat_get_args *, unsigned long *);
cloudabi_errno_t cloudabi_sys_fd_stat_put(
    const struct cloudabi_sys_fd_stat_put_args *, unsigned long *);
cloudabi_errno_t cloudabi_sys_fd_sync(
    const struct cloudabi_sys_fd_sync_args *, unsigned long *);
cloudabi_errno_t cloudabi_sys_file_advise(
    const struct cloudabi_sys_file_advise_args *, unsigned long *);
cloudabi_errno_t cloudabi_sys_file_allocate(
    const struct cloudabi_sys_file_allocate_args *, unsigned long *);
cloudabi_errno_t cloudabi_sys_file_create(
    const struct cloudabi_sys_file_create_args *, unsigned long *);
cloudabi_errno_t cloudabi_sys_file_link(
    const struct cloudabi_sys_file_link_args *, unsigned long *);
cloudabi_errno_t cloudabi_sys_file_open(
    const struct cloudabi_sys_file_open_args *, unsigned long *);
cloudabi_errno_t cloudabi_sys_file_readdir(
    const struct cloudabi_sys_file_readdir_args *, unsigned long *);
cloudabi_errno_t cloudabi_sys_file_readlink(
    const struct cloudabi_sys_file_readlink_args *, unsigned long *);
cloudabi_errno_t cloudabi_sys_file_rename(
    const struct cloudabi_sys_file_rename_args *, unsigned long *);
cloudabi_errno_t cloudabi_sys_file_stat_fget(
    const struct cloudabi_sys_file_stat_fget_args *, unsigned long *);
cloudabi_errno_t cloudabi_sys_file_stat_fput(
    const struct cloudabi_sys_file_stat_fput_args *, unsigned long *);
cloudabi_errno_t cloudabi_sys_file_stat_get(
    const struct cloudabi_sys_file_stat_get_args *, unsigned long *);
cloudabi_errno_t cloudabi_sys_file_stat_put(
    const struct cloudabi_sys_file_stat_put_args *, unsigned long *);
cloudabi_errno_t cloudabi_sys_file_symlink(
    const struct cloudabi_sys_file_symlink_args *, unsigned long *);
cloudabi_errno_t cloudabi_sys_file_unlink(
    const struct cloudabi_sys_file_unlink_args *, unsigned long *);
cloudabi_errno_t cloudabi_sys_lock_unlock(
    const struct cloudabi_sys_lock_unlock_args *, unsigned long *);
cloudabi_errno_t cloudabi_sys_mem_advise(
    const struct cloudabi_sys_mem_advise_args *, unsigned long *);
cloudabi_errno_t cloudabi_sys_mem_lock(
    const struct cloudabi_sys_mem_lock_args *, unsigned long *);
cloudabi_errno_t cloudabi_sys_mem_map(
    const struct cloudabi_sys_mem_map_args *, unsigned long *);
cloudabi_errno_t cloudabi_sys_mem_protect(
    const struct cloudabi_sys_mem_protect_args *, unsigned long *);
cloudabi_errno_t cloudabi_sys_mem_sync(
    const struct cloudabi_sys_mem_sync_args *, unsigned long *);
cloudabi_errno_t cloudabi_sys_mem_unlock(
    const struct cloudabi_sys_mem_unlock_args *, unsigned long *);
cloudabi_errno_t cloudabi_sys_mem_unmap(
    const struct cloudabi_sys_mem_unmap_args *, unsigned long *);
cloudabi_errno_t cloudabi_sys_proc_exit(
    const struct cloudabi_sys_proc_exit_args *, unsigned long *);
cloudabi_errno_t cloudabi_sys_proc_fork(const void *, unsigned long *);
cloudabi_errno_t cloudabi_sys_proc_raise(
    const struct cloudabi_sys_proc_raise_args *, unsigned long *);
cloudabi_errno_t cloudabi_sys_random_get(
    const struct cloudabi_sys_random_get_args *, unsigned long *);
cloudabi_errno_t cloudabi_sys_sock_accept(
    const struct cloudabi_sys_sock_accept_args *, unsigned long *);
cloudabi_errno_t cloudabi_sys_sock_bind(
    const struct cloudabi_sys_sock_bind_args *, unsigned long *);
cloudabi_errno_t cloudabi_sys_sock_connect(
    const struct cloudabi_sys_sock_connect_args *, unsigned long *);
cloudabi_errno_t cloudabi_sys_sock_listen(
    const struct cloudabi_sys_sock_listen_args *, unsigned long *);
cloudabi_errno_t cloudabi_sys_sock_shutdown(
    const struct cloudabi_sys_sock_shutdown_args *, unsigned long *);
cloudabi_errno_t cloudabi_sys_sock_stat_get(
    const struct cloudabi_sys_sock_stat_get_args *, unsigned long *);
cloudabi_errno_t cloudabi_sys_thread_exit(
    const struct cloudabi_sys_thread_exit_args *, unsigned long *);
cloudabi_errno_t cloudabi_sys_thread_tcb_set(
    const struct cloudabi_sys_thread_tcb_set_args *, unsigned long *);
cloudabi_errno_t cloudabi_sys_thread_yield(const void *, unsigned long *);

#endif
