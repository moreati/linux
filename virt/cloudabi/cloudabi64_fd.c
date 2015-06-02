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

#include <linux/syscalls.h>
#include <linux/uio.h>

#include "cloudabi_util.h"
#include "cloudabi64_syscalls.h"

static_assert(sizeof(cloudabi64_ciovec_t) == sizeof(struct iovec),
    "Size mismatch");
static_assert(offsetof(cloudabi64_ciovec_t, iov_base) ==
    offsetof(struct iovec, iov_base), "Offset mismatch");
static_assert(offsetof(cloudabi64_ciovec_t, iov_len) ==
    offsetof(struct iovec, iov_len), "Offset mismatch");

static_assert(sizeof(cloudabi64_iovec_t) == sizeof(struct iovec),
    "Size mismatch");
static_assert(offsetof(cloudabi64_iovec_t, iov_base) ==
    offsetof(struct iovec, iov_base), "Offset mismatch");
static_assert(offsetof(cloudabi64_iovec_t, iov_len) ==
    offsetof(struct iovec, iov_len), "Offset mismatch");

/* Extracts the top bits from the offset if long is smaller than 64 bits. */
#if BITS_PER_LONG < 64
#define TOP_BITS(offset) ((offset) >> BITS_PER_LONG)
#else
#define TOP_BITS(offset) 0
#endif

cloudabi_errno_t cloudabi64_sys_fd_pread(
    const struct cloudabi64_sys_fd_pread_args *uap, unsigned long *retval) {
	long length;

	length = sys_preadv(uap->fd, (const struct iovec __user *)uap->iov,
	    uap->iovlen, uap->offset, TOP_BITS(uap->offset));
	if (length < 0)
		return cloudabi_convert_errno(length);
	retval[0] = length;
	return 0;
}

cloudabi_errno_t cloudabi64_sys_fd_pwrite(
    const struct cloudabi64_sys_fd_pwrite_args *uap, unsigned long *retval) {
	long length;

	length = sys_pwritev(uap->fd, (const struct iovec __user *)uap->iov,
	    uap->iovlen, uap->offset, TOP_BITS(uap->offset));
	if (length < 0)
		return cloudabi_convert_errno(length);
	retval[0] = length;
	return 0;
}

cloudabi_errno_t cloudabi64_sys_fd_read(
    const struct cloudabi64_sys_fd_read_args *uap, unsigned long *retval) {
	long length;

	length = sys_readv(uap->fd, (const struct iovec __user *)uap->iov,
	    uap->iovlen);
	if (length < 0)
		return cloudabi_convert_errno(length);
	retval[0] = length;
	return 0;
}

cloudabi_errno_t cloudabi64_sys_fd_write(
    const struct cloudabi64_sys_fd_write_args *uap, unsigned long *retval) {
	long length;

	length = sys_writev(uap->fd, (const struct iovec __user *)uap->iov,
	    uap->iovlen);
	if (length < 0)
		return cloudabi_convert_errno(length);
	retval[0] = length;
	return 0;
}
