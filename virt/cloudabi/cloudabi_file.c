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

#include "cloudabi_syscalldefs.h"
#include "cloudabi_syscalls.h"

cloudabi_errno_t cloudabi_sys_file_advise(
    const struct cloudabi_sys_file_advise_args *uap, unsigned long *retval)
{
	return CLOUDABI_ENOSYS;
}

cloudabi_errno_t cloudabi_sys_file_allocate(
    const struct cloudabi_sys_file_allocate_args *uap, unsigned long *retval)
{
	return CLOUDABI_ENOSYS;
}

cloudabi_errno_t cloudabi_sys_file_create(
    const struct cloudabi_sys_file_create_args *uap, unsigned long *retval)
{
	return CLOUDABI_ENOSYS;
}

cloudabi_errno_t cloudabi_sys_file_link(
    const struct cloudabi_sys_file_link_args *uap, unsigned long *retval)
{
	return CLOUDABI_ENOSYS;
}

cloudabi_errno_t cloudabi_sys_file_open(
    const struct cloudabi_sys_file_open_args *uap, unsigned long *retval)
{
	return CLOUDABI_ENOSYS;
}

cloudabi_errno_t cloudabi_sys_file_readdir(
    const struct cloudabi_sys_file_readdir_args *uap, unsigned long *retval)
{
	return CLOUDABI_ENOSYS;
}

cloudabi_errno_t cloudabi_sys_file_readlink(
    const struct cloudabi_sys_file_readlink_args *uap, unsigned long *retval)
{
	return CLOUDABI_ENOSYS;
}

cloudabi_errno_t cloudabi_sys_file_rename(
    const struct cloudabi_sys_file_rename_args *uap, unsigned long *retval)
{
	return CLOUDABI_ENOSYS;
}

cloudabi_errno_t cloudabi_sys_file_stat_fget(
    const struct cloudabi_sys_file_stat_fget_args *uap, unsigned long *retval)
{
	return CLOUDABI_ENOSYS;
}

cloudabi_errno_t cloudabi_sys_file_stat_fput(
    const struct cloudabi_sys_file_stat_fput_args *uap, unsigned long *retval)
{
	return CLOUDABI_ENOSYS;
}

cloudabi_errno_t cloudabi_sys_file_stat_get(
    const struct cloudabi_sys_file_stat_get_args *uap, unsigned long *retval)
{
	return CLOUDABI_ENOSYS;
}

cloudabi_errno_t cloudabi_sys_file_stat_put(
    const struct cloudabi_sys_file_stat_put_args *uap, unsigned long *retval)
{
	return CLOUDABI_ENOSYS;
}

cloudabi_errno_t cloudabi_sys_file_symlink(
    const struct cloudabi_sys_file_symlink_args *uap, unsigned long *retval)
{
	return CLOUDABI_ENOSYS;
}

cloudabi_errno_t cloudabi_sys_file_unlink(
    const struct cloudabi_sys_file_unlink_args *uap, unsigned long *retval)
{
	return CLOUDABI_ENOSYS;
}
