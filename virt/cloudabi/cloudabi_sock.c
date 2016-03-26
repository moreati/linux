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

#include "cloudabi_syscalls.h"
#include "cloudabi_types_common.h"
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

int create_sockstat(struct socket *sock, void __user *buf,
                    cloudabi_ssflags_t flags)
{
	cloudabi_sockstat_t ss = {};
	struct sockaddr_storage address;
	int len;

	/* Fill ss_sockname and ss_peername. */
	if (sock->ops->getname(sock, (struct sockaddr *)&address, &len, 0) == 0)
		cloudabi_convert_sockaddr(&address, &ss.ss_sockname);
	if (sock->sk->sk_state == TCP_ESTABLISHED &&
	    sock->sk->sk_shutdown != SHUTDOWN_MASK &&
	    sock->ops->getname(sock, (struct sockaddr *)&address, &len, 1) == 0)
		cloudabi_convert_sockaddr(&address, &ss.ss_peername);

	/* Fill ss_error. */
	if ((flags & CLOUDABI_SOCKSTAT_CLEAR_ERROR) != 0)
		ss.ss_error = cloudabi_convert_errno(sock_error(sock->sk));
	else
		ss.ss_error = cloudabi_convert_errno(sock->sk->sk_err);

	/* Fill ss_state. */
	if (sock->sk->sk_state == TCP_LISTEN)
		ss.ss_state |= CLOUDABI_SOCKSTATE_ACCEPTCONN;
	return copy_to_user(buf, &ss, sizeof(ss)) != 0 ? -EFAULT : 0;
}

cloudabi_errno_t cloudabi_sys_sock_accept(cloudabi_fd_t sock,
    cloudabi_sockstat_t __user *buf, cloudabi_fd_t *conn)
{
	struct fd f;
	struct socket *sk, *newsk;
	struct file *newfile;
	struct file *installfile;
	int err, newfd;
	struct capsicum_rights rights;
	const struct capsicum_rights *listen_rights = NULL;
	struct file *underlying;

	f = fdget_raw(sock);
	if (!f.file)
		return CLOUDABI_EBADF;
	underlying = file_unwrap(f.file,
				 cap_rights_init(&rights, CAP_ACCEPT),
				 &listen_rights, false);
	if (IS_ERR(underlying)) {
		err = PTR_ERR(underlying);
		goto out_put;
	}
	sk = sock_from_file(underlying, &err);
	if (!sk)
		goto out_put;

	err = -ENFILE;
	newsk = sock_alloc();
	if (!newsk)
		goto out_put;

	newsk->type = sk->type;
	newsk->ops = sk->ops;

	/*
	 * We don't need try_module_get here, as the listening socket (sk)
	 * has the protocol module (sk->ops->owner) held.
	 */
	__module_get(newsk->ops->owner);

	newfd = get_unused_fd_flags(0);
	if (unlikely(newfd < 0)) {
		err = newfd;
		sock_release(newsk);
		goto out_put;
	}
	newfile = sock_alloc_file(newsk, 0, sk->sk->sk_prot_creator->name);
	if (IS_ERR(newfile)) {
		err = PTR_ERR(newfile);
		put_unused_fd(newfd);
		sock_release(newsk);
		goto out_put;
	}

	err = security_socket_accept(sk, newsk);
	if (err)
		goto out_fd;

	err = sk->ops->accept(sk, newsk, sk->file->f_flags);
	if (err < 0)
		goto out_fd;

	if (buf != NULL) {
		err = create_sockstat(newsk, buf, 0);
		if (err != 0)
			goto out_fd;
	}

	/* File flags are not inherited via accept() unlike another OSes. */

	/* However, any Capsicum capability rights are inherited. */
	installfile = capsicum_file_install(listen_rights, newfile);
	if (IS_ERR(installfile)) {
		err = PTR_ERR(installfile);
		goto out_fd;
	}
	fd_install(newfd, installfile);
	*conn = newfd;

out_put:
	fdput(f);
	return cloudabi_convert_errno(err);
out_fd:
	fput(newfile);
	put_unused_fd(newfd);
	goto out_put;
}

cloudabi_errno_t cloudabi_sys_sock_bind(cloudabi_fd_t sock, cloudabi_fd_t fd,
    const char __user *path, size_t pathlen)
{
	struct capsicum_rights rights;
	struct fd f_sock;
	struct path kpath;
	struct dentry *dentry;
	struct socket *sk;
	int err;

	cap_rights_init(&rights, CAP_BIND);
	f_sock = fdget_raw_rights(sock, &rights);
	if (IS_ERR(f_sock.file))
		return cloudabi_convert_errno(PTR_ERR(f_sock.file));
	sk = sock_from_file(f_sock.file, &err);
	if (sk == NULL)
		goto out;

	cap_rights_init(&rights, CAP_BINDAT);
	dentry = user_path_create_fixed_length(fd, path, pathlen, &kpath, 0,
	    &rights);
	err = PTR_ERR(dentry);
	if (IS_ERR(dentry)) {
		if (err == -EEXIST)
			err = -EADDRINUSE;
	} else {
		err = sk->ops->bindat(sk, &kpath, dentry);
		done_path_create(&kpath, dentry);
	}
out:
	fdput(f_sock);
	return cloudabi_convert_errno(err);
}

cloudabi_errno_t cloudabi_sys_sock_connect(cloudabi_fd_t sock, cloudabi_fd_t fd,
    const char __user *path, size_t pathlen)
{
	struct capsicum_rights rights;
	struct fd f_sock;
	struct path kpath;
	struct socket *sk;
	int err;

	cap_rights_init(&rights, CAP_CONNECT);
	f_sock = fdget_raw_rights(sock, &rights);
	if (IS_ERR(f_sock.file))
		return cloudabi_convert_errno(PTR_ERR(f_sock.file));
	sk = sock_from_file(f_sock.file, &err);
	if (sk == NULL)
		goto out;

	err = user_path_at_fixed_length(fd, path, pathlen, 0, &kpath,
	    CAP_CONNECTAT);
	if (err == 0) {
		err = sk->ops->connectat(sk, &kpath, sk->file->f_flags);
		path_put(&kpath);
	}
out:
	fdput(f_sock);
	return cloudabi_convert_errno(err);
}

cloudabi_errno_t cloudabi_sys_sock_listen(cloudabi_fd_t sock,
    cloudabi_backlog_t backlog)
{
	return cloudabi_convert_errno(sys_listen(sock, backlog));
}

cloudabi_errno_t cloudabi_sys_sock_shutdown(cloudabi_fd_t sock,
    cloudabi_sdflags_t how)
{
	int shut;

	switch (how) {
	case CLOUDABI_SHUT_RD:
		shut = SHUT_RD;
		break;
	case CLOUDABI_SHUT_WR:
		shut = SHUT_WR;
		break;
	case CLOUDABI_SHUT_RD | CLOUDABI_SHUT_WR:
		shut = SHUT_RDWR;
		break;
	default:
		return CLOUDABI_EINVAL;
	}
	return cloudabi_convert_errno(sys_shutdown(sock, shut));
}

cloudabi_errno_t cloudabi_sys_sock_stat_get(cloudabi_fd_t sock,
    cloudabi_sockstat_t __user *buf, cloudabi_ssflags_t flags)
{
	struct capsicum_rights rights;
	struct fd f_sock;
	struct socket *sk;
	int err;

	cap_rights_init(&rights,
	                CAP_GETSOCKOPT, CAP_GETPEERNAME, CAP_GETSOCKNAME);
	f_sock = fdget_raw_rights(sock, &rights);
	if (IS_ERR(f_sock.file))
		return cloudabi_convert_errno(PTR_ERR(f_sock.file));
	sk = sock_from_file(f_sock.file, &err);
	if (sk != NULL)
		err = create_sockstat(sk, buf, flags);
	fdput(f_sock);
	return cloudabi_convert_errno(err);
}
