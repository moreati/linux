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

#include <linux/in.h>
#include <linux/in6.h>
#include <linux/namei.h>
#include <linux/net.h>
#include <linux/syscalls.h>

#include <net/sock.h>

#include "cloudabi_syscalldefs.h"
#include "cloudabi_syscalls.h"
#include "cloudabi_util.h"

static void cloudabi_convert_sockaddr(const struct sockaddr_storage *ss,
                                      cloudabi_sockaddr_t *rsa)
{
	const struct sockaddr_in *sin;
	const struct sockaddr_in6 *sin6;

	switch (ss->ss_family) {
	case AF_INET:
		sin = (const struct sockaddr_in *)ss;
		rsa->sa_family = CLOUDABI_AF_INET;
		memcpy(&rsa->sa_inet.addr, &sin->sin_addr,
		    sizeof(rsa->sa_inet.addr));
		rsa->sa_inet.port = ntohs(sin->sin_port);
		return;
	case AF_INET6:
		sin6 = (const struct sockaddr_in6 *)ss;
		rsa->sa_family = CLOUDABI_AF_INET6;
		memcpy(&rsa->sa_inet6.addr, &sin6->sin6_addr,
		    sizeof(rsa->sa_inet6.addr));
		rsa->sa_inet6.port = ntohs(sin6->sin6_port);
		return;
	case AF_UNIX:
		rsa->sa_family = CLOUDABI_AF_UNIX;
		return;
	}
}

cloudabi_errno_t cloudabi_sys_sock_accept(
    const struct cloudabi_sys_sock_accept_args *uap, unsigned long *retval)
{
	return CLOUDABI_ENOSYS;
}

cloudabi_errno_t cloudabi_sys_sock_bind(
    const struct cloudabi_sys_sock_bind_args *uap, unsigned long *retval)
{
	struct capsicum_rights rights;
	struct fd f_sock;
	struct path path;
	struct dentry *dentry;
	struct socket *sock;
	int err = 0;

	cap_rights_init(&rights, CAP_BIND);
	f_sock = fdget_raw_rights(uap->s, &rights);
	if (IS_ERR(f_sock.file))
		return cloudabi_convert_errno(PTR_ERR(f_sock.file));
	sock = sock_from_file(f_sock.file, &err);
	if (sock == NULL)
		goto out;

	cap_rights_init(&rights, CAP_BINDAT);
	dentry = user_path_create_fixed_length(uap->fd, uap->path,
	    uap->pathlen, &path, 0, &rights);
	err = PTR_ERR(dentry);
	if (IS_ERR(dentry)) {
		if (err == -EEXIST)
			err = -EADDRINUSE;
	} else {
		err = sock->ops->bindat(sock, &path, dentry);
		done_path_create(&path, dentry);
	}
out:
	fdput(f_sock);
	return cloudabi_convert_errno(err);
}

cloudabi_errno_t cloudabi_sys_sock_connect(
    const struct cloudabi_sys_sock_connect_args *uap, unsigned long *retval)
{
	struct capsicum_rights rights;
	struct fd f_sock;
	struct path path;
	struct socket *sock;
	int err = 0;

	cap_rights_init(&rights, CAP_CONNECT);
	f_sock = fdget_raw_rights(uap->s, &rights);
	if (IS_ERR(f_sock.file))
		return cloudabi_convert_errno(PTR_ERR(f_sock.file));
	sock = sock_from_file(f_sock.file, &err);
	if (sock == NULL)
		goto out;

	err = user_path_at_fixed_length(uap->fd, uap->path, uap->pathlen,
	    0, &path, CAP_CONNECTAT);
	if (err == 0) {
		err = sock->ops->connectat(sock, &path, sock->file->f_flags);
		path_put(&path);
	}
out:
	fdput(f_sock);
	return cloudabi_convert_errno(err);
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
	cloudabi_sockstat_t ss = {};
	struct capsicum_rights rights;
	struct fd f_sock;
	struct sockaddr_storage address;
	struct socket *sock;
	int err = 0, len;

	cap_rights_init(&rights,
	                CAP_GETSOCKOPT, CAP_GETPEERNAME, CAP_GETSOCKNAME);
	f_sock = fdget_raw_rights(uap->fd, &rights);
	if (IS_ERR(f_sock.file))
		return cloudabi_convert_errno(PTR_ERR(f_sock.file));
	sock = sock_from_file(f_sock.file, &err);
	if (sock == NULL)
		goto out;

	/* Fill ss_sockname and ss_peername. */
	if (sock->ops->getname(sock, (struct sockaddr *)&address, &len, 0) == 0)
		cloudabi_convert_sockaddr(&address, &ss.ss_sockname);
	if (sock->ops->getname(sock, (struct sockaddr *)&address, &len, 1) == 0)
		cloudabi_convert_sockaddr(&address, &ss.ss_peername);

	/* Fill ss_error. */
	ss.ss_error = cloudabi_convert_errno(sock_error(sock->sk));

	/* Fill ss_state. */
	if (sock->sk->sk_state == TCP_LISTEN)
		ss.ss_state |= CLOUDABI_SOCKSTAT_ACCEPTCONN;

	if (copy_to_user(uap->buf, &ss, sizeof(ss)) != 0)
		err = -EFAULT;

out:
	fdput(f_sock);
	return cloudabi_convert_errno(err);
}
