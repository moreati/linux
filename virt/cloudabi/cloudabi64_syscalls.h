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

#ifndef CLOUDABI64_SYSCALLS_H
#define CLOUDABI64_SYSCALLS_H

#include "cloudabi_syscalldefs.h"
#include "cloudabi64_syscalldefs.h"

/*
 * System calls that depend on 64-bit types and data structures.
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

struct cloudabi64_sys_fd_pread_args {
	ARG(cloudabi_fd_t, fd);
	ARG(const struct cloudabi64_iovec_t __user *, iov);
	ARG(cloudabi64_size_t, iovlen);
	ARG(cloudabi_filesize_t, offset);
};
struct cloudabi64_sys_fd_pwrite_args {
	ARG(cloudabi_fd_t, fd);
	ARG(const struct cloudabi64_ciovec_t __user *, iov);
	ARG(cloudabi64_size_t, iovlen);
	ARG(cloudabi_filesize_t, offset);
};
struct cloudabi64_sys_fd_read_args {
	ARG(cloudabi_fd_t, fd);
	ARG(const struct cloudabi64_iovec_t __user *, iov);
	ARG(cloudabi64_size_t, iovlen);
};
struct cloudabi64_sys_fd_write_args {
	ARG(cloudabi_fd_t, fd);
	ARG(const struct cloudabi64_ciovec_t __user *, iov);
	ARG(cloudabi64_size_t, iovlen);
};
struct cloudabi64_sys_poll_args {
	ARG(const cloudabi64_subscription_t __user *, in);
	ARG(cloudabi64_event_t __user *, out);
	ARG(cloudabi64_size_t, nevents);
};
struct cloudabi64_sys_proc_exec_args {
	ARG(cloudabi_fd_t, fd);
	ARG(const struct cloudabi64_ciovec_t __user *, iov);
	ARG(cloudabi64_size_t, iovcnt);
	ARG(const cloudabi_fd_t __user *, fds);
	ARG(cloudabi64_size_t, fdscnt);
};
struct cloudabi64_sys_sock_recv_args {
	ARG(cloudabi_fd_t, s);
	ARG(const cloudabi64_recv_in_t __user *, in);
	ARG(cloudabi64_recv_out_t __user *, out);
};
struct cloudabi64_sys_sock_send_args {
	ARG(cloudabi_fd_t, s);
	ARG(const cloudabi64_send_in_t __user *, in);
	ARG(cloudabi64_send_out_t __user *, out);
};
struct cloudabi64_sys_thread_create_args {
	ARG(const cloudabi64_threadattr_t __user *, attr);
};

#undef PAD
#undef ARG

cloudabi_errno_t cloudabi64_sys_fd_pread(
    const struct cloudabi64_sys_fd_pread_args *, unsigned long *);
cloudabi_errno_t cloudabi64_sys_fd_pwrite(
    const struct cloudabi64_sys_fd_pwrite_args *, unsigned long *);
cloudabi_errno_t cloudabi64_sys_fd_read(
    const struct cloudabi64_sys_fd_read_args *, unsigned long *);
cloudabi_errno_t cloudabi64_sys_fd_write(
    const struct cloudabi64_sys_fd_write_args *, unsigned long *);
cloudabi_errno_t cloudabi64_sys_poll(
    const struct cloudabi64_sys_poll_args *, unsigned long *);
cloudabi_errno_t cloudabi64_sys_proc_exec(
    const struct cloudabi64_sys_proc_exec_args *, unsigned long *);
cloudabi_errno_t cloudabi64_sys_sock_recv(
    const struct cloudabi64_sys_sock_recv_args *, unsigned long *);
cloudabi_errno_t cloudabi64_sys_sock_send(
    const struct cloudabi64_sys_sock_send_args *, unsigned long *);
cloudabi_errno_t cloudabi64_sys_thread_create(
    const struct cloudabi64_sys_thread_create_args *, unsigned long *);

#endif
