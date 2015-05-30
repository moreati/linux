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

#include "cloudabi_syscalldefs.h"
#include "cloudabi_syscalls.h"
#include "cloudabi_util.h"

static unsigned long
convert_mprot(cloudabi_mprot_t in)
{
	unsigned long out;

	out = 0;
	if (in & CLOUDABI_PROT_EXEC)
		out |= PROT_EXEC;
	if (in & CLOUDABI_PROT_WRITE)
		out |= PROT_WRITE;
	if (in & CLOUDABI_PROT_READ)
		out |= PROT_READ;
	return out;
}

cloudabi_errno_t cloudabi_sys_mem_advise(
    const struct cloudabi_sys_mem_advise_args *uap, unsigned long *retval)
{
	return CLOUDABI_ENOSYS;
}

cloudabi_errno_t cloudabi_sys_mem_lock(
    const struct cloudabi_sys_mem_lock_args *uap, unsigned long *retval)
{
	return cloudabi_convert_errno(
	    sys_mlock((unsigned long)uap->addr, uap->len));
}

cloudabi_errno_t cloudabi_sys_mem_map(
    const struct cloudabi_sys_mem_map_args *uap, unsigned long *retval)
{
	unsigned long flags;
	long addr;

	/* Address needs to be page aligned. */
	if ((uap->off & ~PAGE_MASK) != 0)
		return CLOUDABI_EINVAL;

	/* Translate flags. */
	flags = 0;
	if (uap->flags & CLOUDABI_MAP_ANON)
		flags |= MAP_ANONYMOUS;
	if (uap->flags & CLOUDABI_MAP_FIXED)
		flags |= MAP_FIXED;
	if (uap->flags & CLOUDABI_MAP_PRIVATE)
		flags |= MAP_PRIVATE;
	if (uap->flags & CLOUDABI_MAP_SHARED)
		flags |= MAP_SHARED;

	addr = sys_mmap_pgoff((unsigned long)uap->addr, uap->len,
	    convert_mprot(uap->prot), flags, uap->fd, uap->off);
	if (addr < 0 && addr >= -MAX_ERRNO)
		return cloudabi_convert_errno(addr);
	retval[0] = addr;
	return 0;
}

cloudabi_errno_t cloudabi_sys_mem_protect(
    const struct cloudabi_sys_mem_protect_args *uap, unsigned long *retval)
{
	return cloudabi_convert_errno(sys_mprotect((unsigned long)uap->addr,
	    uap->len, convert_mprot(uap->prot)));
}

cloudabi_errno_t cloudabi_sys_mem_sync(
    const struct cloudabi_sys_mem_sync_args *uap, unsigned long *retval)
{
	return CLOUDABI_ENOSYS;
}

cloudabi_errno_t cloudabi_sys_mem_unlock(
    const struct cloudabi_sys_mem_unlock_args *uap, unsigned long *retval)
{
	return cloudabi_convert_errno(
	    sys_munlock((unsigned long)uap->addr, uap->len));
}

cloudabi_errno_t cloudabi_sys_mem_unmap(
    const struct cloudabi_sys_mem_unmap_args *uap, unsigned long *retval)
{
	return cloudabi_convert_errno(
	    sys_munmap((unsigned long)uap->addr, uap->len));
}
