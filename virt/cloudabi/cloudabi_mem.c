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

#include <asm/mman.h>

#include "cloudabi_syscalls.h"
#include "cloudabi_types_common.h"
#include "cloudabi_util.h"

static cloudabi_errno_t
convert_mprot(cloudabi_mprot_t in, int *out)
{
	/* Unknown protection flags. */
	if ((in & ~(CLOUDABI_PROT_EXEC | CLOUDABI_PROT_WRITE |
	    CLOUDABI_PROT_READ)) != 0)
		return CLOUDABI_ENOTSUP;
	/* W^X: Write and exec cannot be enabled at the same time. */
	if ((in & (CLOUDABI_PROT_EXEC | CLOUDABI_PROT_WRITE)) ==
	    (CLOUDABI_PROT_EXEC | CLOUDABI_PROT_WRITE))
		return CLOUDABI_ENOTSUP;

	*out = 0;
	if (in & CLOUDABI_PROT_EXEC)
		*out |= PROT_EXEC;
	if (in & CLOUDABI_PROT_WRITE)
		*out |= PROT_WRITE;
	if (in & CLOUDABI_PROT_READ)
		*out |= PROT_READ;
	return 0;
}

cloudabi_errno_t cloudabi_sys_mem_advise(void __user *addr, size_t len,
    cloudabi_advice_t advice)
{
	int behavior;

	switch (advice) {
	case CLOUDABI_ADVICE_DONTNEED:
		behavior = MADV_DONTNEED;
		break;
	case CLOUDABI_ADVICE_NORMAL:
		behavior = MADV_NORMAL;
		break;
	case CLOUDABI_ADVICE_RANDOM:
		behavior = MADV_RANDOM;
		break;
	case CLOUDABI_ADVICE_SEQUENTIAL:
		behavior = MADV_SEQUENTIAL;
		break;
	case CLOUDABI_ADVICE_WILLNEED:
		behavior = MADV_WILLNEED;
		break;
	default:
		return CLOUDABI_EINVAL;
	}
	return cloudabi_convert_errno(
	    sys_madvise((unsigned long)addr, len, behavior));
}

cloudabi_errno_t
cloudabi_sys_mem_lock(const void __user *addr, size_t len)
{
	return cloudabi_convert_errno(sys_mlock((unsigned long)addr, len));
}

cloudabi_errno_t
cloudabi_sys_mem_map(void __user *addr, size_t len, cloudabi_mprot_t prot,
    cloudabi_mflags_t flags, cloudabi_fd_t fd, cloudabi_filesize_t off,
    void __user **mem)
{
	cloudabi_errno_t error;
	unsigned long kflags;
	long retval;
	int kprot;

	/* Address needs to be page aligned. */
	if ((off & ~PAGE_MASK) != 0)
		return CLOUDABI_EINVAL;

	/* Translate flags. */
	kflags = 0;
	if (flags & CLOUDABI_MAP_ANON) {
		kflags |= MAP_ANONYMOUS;
		if (fd != CLOUDABI_MAP_ANON_FD)
			return CLOUDABI_EINVAL;
	}
	if (flags & CLOUDABI_MAP_FIXED)
		kflags |= MAP_FIXED;
	if (flags & CLOUDABI_MAP_PRIVATE)
		kflags |= MAP_PRIVATE;
	if (flags & CLOUDABI_MAP_SHARED)
		kflags |= MAP_SHARED;

	error = convert_mprot(prot, &kprot);
	if (error != 0)
		return error;

	retval = sys_mmap_pgoff((unsigned long)addr, len, kprot, kflags, fd,
	    off);
	if (retval < 0 && retval >= -MAX_ERRNO)
		return cloudabi_convert_errno(retval);
	*mem = (void __user *)retval;
	return 0;
}

cloudabi_errno_t cloudabi_sys_mem_protect(void __user *addr, size_t len,
    cloudabi_mprot_t prot)
{
	cloudabi_errno_t error;
	int kprot;

	error = convert_mprot(prot, &kprot);
	if (error != 0)
		return error;

	return cloudabi_convert_errno(
	    sys_mprotect((unsigned long)addr, len, kprot));
}

cloudabi_errno_t
cloudabi_sys_mem_sync(void __user *addr, size_t len, cloudabi_msflags_t flags)
{
	int kflags;

	/* Convert flags. */
	kflags = 0;
	switch (flags & (CLOUDABI_MS_ASYNC | CLOUDABI_MS_SYNC)) {
	case CLOUDABI_MS_ASYNC:
		kflags |= MS_ASYNC;
		break;
	case CLOUDABI_MS_SYNC:
		kflags |= MS_SYNC;
		break;
	default:
		return CLOUDABI_EINVAL;
	}
	if ((flags & CLOUDABI_MS_INVALIDATE) != 0)
		kflags |= MS_INVALIDATE;

	return cloudabi_convert_errno(
	    sys_msync((unsigned long)addr, len, kflags));
}

cloudabi_errno_t cloudabi_sys_mem_unlock(const void __user *addr, size_t len)
{
	return cloudabi_convert_errno(sys_munlock((unsigned long)addr, len));
}

cloudabi_errno_t cloudabi_sys_mem_unmap(void __user *addr, size_t len)
{
	return cloudabi_convert_errno(sys_munmap((unsigned long)addr, len));
}
