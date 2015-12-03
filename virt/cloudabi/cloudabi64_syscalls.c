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

#include "cloudabi_syscalls.h"
#include "cloudabi64_syscalls.h"

typedef cloudabi_errno_t (*cloudabi_syscall_t)(void *, unsigned long *);

const cloudabi_syscall_t cloudabi64_syscalls[] = {
	(cloudabi_syscall_t)cloudabi_sys_clock_res_get,
	(cloudabi_syscall_t)cloudabi_sys_clock_time_get,
	(cloudabi_syscall_t)cloudabi_sys_condvar_signal,
	(cloudabi_syscall_t)cloudabi_sys_fd_close,
	(cloudabi_syscall_t)cloudabi_sys_fd_create1,
	(cloudabi_syscall_t)cloudabi_sys_fd_create2,
	(cloudabi_syscall_t)cloudabi_sys_fd_datasync,
	(cloudabi_syscall_t)cloudabi_sys_fd_dup,
	(cloudabi_syscall_t)cloudabi64_sys_fd_pread,
	(cloudabi_syscall_t)cloudabi64_sys_fd_pwrite,
	(cloudabi_syscall_t)cloudabi64_sys_fd_read,
	(cloudabi_syscall_t)cloudabi_sys_fd_replace,
	(cloudabi_syscall_t)cloudabi_sys_fd_seek,
	(cloudabi_syscall_t)cloudabi_sys_fd_stat_get,
	(cloudabi_syscall_t)cloudabi_sys_fd_stat_put,
	(cloudabi_syscall_t)cloudabi_sys_fd_sync,
	(cloudabi_syscall_t)cloudabi64_sys_fd_write,
	(cloudabi_syscall_t)cloudabi_sys_file_advise,
	(cloudabi_syscall_t)cloudabi_sys_file_allocate,
	(cloudabi_syscall_t)cloudabi_sys_file_create,
	(cloudabi_syscall_t)cloudabi_sys_file_link,
	(cloudabi_syscall_t)cloudabi_sys_file_open,
	(cloudabi_syscall_t)cloudabi_sys_file_readdir,
	(cloudabi_syscall_t)cloudabi_sys_file_readlink,
	(cloudabi_syscall_t)cloudabi_sys_file_rename,
	(cloudabi_syscall_t)cloudabi_sys_file_stat_fget,
	(cloudabi_syscall_t)cloudabi_sys_file_stat_fput,
	(cloudabi_syscall_t)cloudabi_sys_file_stat_get,
	(cloudabi_syscall_t)cloudabi_sys_file_stat_put,
	(cloudabi_syscall_t)cloudabi_sys_file_symlink,
	(cloudabi_syscall_t)cloudabi_sys_file_unlink,
	(cloudabi_syscall_t)cloudabi_sys_lock_unlock,
	(cloudabi_syscall_t)cloudabi_sys_mem_advise,
	(cloudabi_syscall_t)cloudabi_sys_mem_lock,
	(cloudabi_syscall_t)cloudabi_sys_mem_map,
	(cloudabi_syscall_t)cloudabi_sys_mem_protect,
	(cloudabi_syscall_t)cloudabi_sys_mem_sync,
	(cloudabi_syscall_t)cloudabi_sys_mem_unlock,
	(cloudabi_syscall_t)cloudabi_sys_mem_unmap,
	(cloudabi_syscall_t)cloudabi64_sys_poll,
	(cloudabi_syscall_t)cloudabi_sys_proc_exec,
	(cloudabi_syscall_t)cloudabi_sys_proc_exit,
	(cloudabi_syscall_t)cloudabi_sys_proc_fork,
	(cloudabi_syscall_t)cloudabi_sys_proc_raise,
	(cloudabi_syscall_t)cloudabi_sys_random_get,
	(cloudabi_syscall_t)cloudabi_sys_sock_accept,
	(cloudabi_syscall_t)cloudabi_sys_sock_bind,
	(cloudabi_syscall_t)cloudabi_sys_sock_connect,
	(cloudabi_syscall_t)cloudabi_sys_sock_listen,
	(cloudabi_syscall_t)cloudabi64_sys_sock_recv,
	(cloudabi_syscall_t)cloudabi64_sys_sock_send,
	(cloudabi_syscall_t)cloudabi_sys_sock_shutdown,
	(cloudabi_syscall_t)cloudabi_sys_sock_stat_get,
	(cloudabi_syscall_t)cloudabi64_sys_thread_create,
	(cloudabi_syscall_t)cloudabi_sys_thread_exit,
	(cloudabi_syscall_t)cloudabi_sys_thread_tcb_set,
	(cloudabi_syscall_t)cloudabi_sys_thread_yield,

	(cloudabi_syscall_t)cloudabi_sys_enosys,
};
static_assert(
    sizeof(cloudabi64_syscalls) / sizeof(cloudabi64_syscalls[0]) == 57 + 1,
    "Invalid system call table size");
