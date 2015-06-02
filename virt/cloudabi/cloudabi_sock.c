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

#include <linux/net.h>
#include <linux/syscalls.h>

#include "cloudabi_syscalldefs.h"
#include "cloudabi_syscalls.h"
#include "cloudabi_util.h"

cloudabi_errno_t cloudabi_sys_sock_accept(
    const struct cloudabi_sys_sock_accept_args *uap, unsigned long *retval)
{
	return CLOUDABI_ENOSYS;
}

cloudabi_errno_t cloudabi_sys_sock_bind(
    const struct cloudabi_sys_sock_bind_args *uap, unsigned long *retval)
{
	return CLOUDABI_ENOSYS;
}

cloudabi_errno_t cloudabi_sys_sock_connect(
    const struct cloudabi_sys_sock_connect_args *uap, unsigned long *retval)
{
	return CLOUDABI_ENOSYS;
}

cloudabi_errno_t cloudabi_sys_sock_listen(
    const struct cloudabi_sys_sock_listen_args *uap, unsigned long *retval)
{
	return cloudabi_convert_errno(sys_listen(uap->s, uap->backlog));
}

cloudabi_errno_t cloudabi_sys_sock_shutdown(
    const struct cloudabi_sys_sock_shutdown_args *uap, unsigned long *retval)
{
	int how;

	switch (uap->how) {
	case CLOUDABI_SHUT_RD:
		how = SHUT_RD;
		break;
	case CLOUDABI_SHUT_WR:
		how = SHUT_WR;
		break;
	case CLOUDABI_SHUT_RD | CLOUDABI_SHUT_WR:
		how = SHUT_RDWR;
		break;
	default:
		return CLOUDABI_EINVAL;
	}
	return cloudabi_convert_errno(sys_shutdown(uap->s, how));
}

cloudabi_errno_t cloudabi_sys_sock_stat_get(
    const struct cloudabi_sys_sock_stat_get_args *uap, unsigned long *retval)
{
	return CLOUDABI_ENOSYS;
}
