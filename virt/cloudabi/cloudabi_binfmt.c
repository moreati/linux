/*
 * Support for CloudABI executables.
 *
 * Based on fs/binfmt_elf.c.
 *
 * Copyright (c) 2015 Nuxi, https://nuxi.nl/
 * Copyright 1993, 1994: Eric Youngdale (ericy@cais.com)
 */

#include <linux/binfmts.h>
#include <linux/elf-randomize.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/module.h>
#include <linux/ptrace.h>
#include <linux/random.h>
#include <linux/slab.h>

#include <asm/uaccess.h>

#include "cloudabi_util.h"
#include "cloudabi64_syscalldefs.h"

#if ELF_EXEC_PAGESIZE > PAGE_SIZE
#define ELF_MIN_ALIGN	ELF_EXEC_PAGESIZE
#else
#define ELF_MIN_ALIGN	PAGE_SIZE
#endif

#define STACK_ALIGN 16

#define ELF_PAGESTART(a) ((a) & ~(unsigned long)(ELF_MIN_ALIGN - 1))
#define ELF_PAGEOFFSET(a) ((a) & (ELF_MIN_ALIGN - 1))
#define ELF_PAGEALIGN(a) (((a) + ELF_MIN_ALIGN - 1) & ~(ELF_MIN_ALIGN - 1))

#define MAX_ADDR	TASK_SIZE

static int cloudabi_binfmt_load_binary(struct linux_binprm *);

static struct linux_binfmt cloudabi_binfmt_format = {
	.module		= THIS_MODULE,
	.load_binary	= cloudabi_binfmt_load_binary,
	.load_shlib	= NULL,
	.core_dump	= NULL,
	.min_coredump	= 0,
};

static int cloudabi_binfmt_setbrk(unsigned long start, unsigned long end)
{
	unsigned long addr;

	start = ELF_PAGEALIGN(start);
	end = ELF_PAGEALIGN(end);
	if (end > start) {
		addr = vm_brk(start, end - start);
		if (addr >= MAX_ADDR)
			return addr;
	}
	current->mm->start_brk = current->mm->brk = end;
	return 0;
}

static int cloudabi_binfmt_padzero(unsigned long elf_bss)
{
	unsigned long nbyte;

	nbyte = ELF_PAGEOFFSET(elf_bss);
	if (nbyte) {
		nbyte = ELF_MIN_ALIGN - nbyte;
		if (clear_user((void __user *) elf_bss, nbyte))
			return -EFAULT;
	}
	return 0;
}

static unsigned long cloudabi_binfmt_randomize_stack(void)
{
	unsigned long random_variable = 0;

	if ((current->flags & PF_RANDOMIZE) != 0 &&
	    (current->personality & ADDR_NO_RANDOMIZE) == 0) {
		random_variable = (unsigned long)get_random_int();
		random_variable &= STACK_RND_MASK;
		random_variable <<= PAGE_SHIFT;
	}
#ifdef CONFIG_STACK_GROWSUP
	return PAGE_ALIGN(STACK_TOP) + random_variable;
#else
	return PAGE_ALIGN(STACK_TOP) - random_variable;
#endif
}

static unsigned long cloudabi_binfmt_phdr_map(struct file *file,
    struct elf_phdr *phdr)
{
	unsigned long addr = ELF_PAGESTART(phdr->p_vaddr);
	unsigned long off = phdr->p_offset - ELF_PAGEOFFSET(phdr->p_vaddr);
	unsigned long size = phdr->p_filesz + ELF_PAGEOFFSET(phdr->p_vaddr);
	unsigned long prot = 0;

	/* vm_mmap() will return -EINVAL if given a zero size. */
	if (size == 0)
		return addr;

	/* Translate permission bits and map file region. */
	if (phdr->p_flags & PF_R)
		prot = PROT_READ;
	if (phdr->p_flags & PF_W)
		prot |= PROT_WRITE;
	if (phdr->p_flags & PF_X)
		prot |= PROT_EXEC;
	return vm_mmap(file, addr, size, prot,
	    MAP_PRIVATE | MAP_DENYWRITE | MAP_EXECUTABLE | MAP_FIXED, off);
}

static int cloudabi_binfmt_init_stack(struct linux_binprm *bprm,
    struct elfhdr *hdr, unsigned long load_addr) {
	struct mm_struct *mm = current->mm;
	unsigned long argdatalen = mm->arg_end - mm->arg_start;
	unsigned long p;

	/* Create an auxiliary vector. */
	cloudabi64_auxv_t auxv[] = {
#define	VAL(type, val)	{ .a_type = (type), .a_val = (val) }
#define	PTR(type, ptr)	{ .a_type = (type), .a_ptr = (uintptr_t)(ptr) }
		VAL(CLOUDABI_AT_ARGDATA, mm->arg_start),
		VAL(CLOUDABI_AT_ARGDATALEN,
		    argdatalen > 0 ? argdatalen - 1 : 0),
		/* TODO(ed): CLOUDABI_AT_CANARY{,LEN}. */
		VAL(CLOUDABI_AT_PAGESZ, PAGE_SIZE),
		PTR(CLOUDABI_AT_PHDR, load_addr + hdr->e_phoff),
		VAL(CLOUDABI_AT_PHNUM, hdr->e_phnum),
		VAL(CLOUDABI_AT_TID, cloudabi_gettid(current)),
#undef VAL
#undef PTR
		{ .a_type = CLOUDABI_AT_NULL },
	};

	/*
	 * Determine where the auxiliary vector needs to go on the stack
	 * and adjust the stack address accordingly.
	 */
	p = arch_align_stack(bprm->p);
#ifdef CONFIG_STACK_GROWSUP
	p = roundup(p, STACK_ALIGN);
	bprm->p = p + roundup(sizeof(auxv), STACK_ALIGN);
#else
	bprm->p = p = rounddown(p, STACK_ALIGN) -
	    roundup(sizeof(auxv), STACK_ALIGN);
#endif

	if (copy_to_user((cloudabi64_auxv_t __user *)p, auxv,
	    sizeof(auxv)) != 0)
		return -EFAULT;
	return 0;
}

static int cloudabi_binfmt_load_binary(struct linux_binprm *bprm) {
	struct elfhdr *hdr;
	struct elf_phdr *phdr, *phdrs;
	struct file *file;
	struct mm_struct *mm;
	struct pt_regs *regs;
	size_t phdrslen;
	unsigned long bss, brk, addr, entry, start_code, end_code, start_data,
	    end_data, len, load_addr, p;
	int argc, error, i;
	bool load_addr_set;

	/*
	 * Only match statically linked CloudABI executables for the
	 * architecture of the running system. Also ensure that the
	 * number of program headers in the executable makes sense.
	 */
	hdr = (struct elfhdr *)bprm->buf;
	if (hdr->e_ident[EI_MAG0] != ELFMAG0 ||
	    hdr->e_ident[EI_MAG1] != ELFMAG1 ||
	    hdr->e_ident[EI_MAG2] != ELFMAG2 ||
	    hdr->e_ident[EI_MAG3] != ELFMAG3 ||
	    hdr->e_ident[EI_OSABI] != ELFOSABI_CLOUDABI ||
	    hdr->e_type != ET_EXEC ||
	    hdr->e_phentsize != sizeof(struct elf_phdr) ||
	    hdr->e_phnum < 1 ||
	    hdr->e_phnum > ELF_MIN_ALIGN / sizeof(struct elf_phdr))
		return -ENOEXEC;
	if (!elf_check_arch(hdr))
		return -ENOEXEC;

	/* We need support for mmaping the executable. */
	file = bprm->file;
	if (file->f_op->mmap == NULL)
		return -ENOEXEC;

	/* Read program headers from the executable. */
	phdrslen = hdr->e_phnum * sizeof(struct elf_phdr);
	phdrs = kmalloc(phdrslen, GFP_KERNEL);
	if (phdrs == NULL)
		return -ENOMEM;
	error = kernel_read(file, hdr->e_phoff, (char *)phdrs, phdrslen);
	if (error != phdrslen) {
		if (error >= 0)
			error = -EIO;
		goto out;
	}

	/* TODO(ed): Process PT_*PROC! */

	error = flush_old_exec(bprm);
	if (error != 0)
		goto out;

	if (elf_read_implies_exec(loc->elf_ex, EXSTACK_DISABLE_X))
		current->personality |= READ_IMPLIES_EXEC;

	if ((current->personality & ADDR_NO_RANDOMIZE) == 0 &&
	    randomize_va_space)
		current->flags |= PF_RANDOMIZE;

	setup_new_exec(bprm);

	error = setup_arg_pages(bprm, cloudabi_binfmt_randomize_stack(),
	    EXSTACK_DISABLE_X);
	if (error != 0)
		goto out;
	mm = current->mm;
	mm->start_stack = bprm->p;

	bss = 0;
	brk = 0;
	start_code = ULONG_MAX;
	end_code = 0;
	start_data = 0;
	end_data = 0;
	load_addr = 0;
	load_addr_set = 0;

	for (i = 0; i < hdr->e_phnum; ++i) {
		phdr = &phdrs[i];
		if (phdr->p_type != PT_LOAD)
			continue;

		if (bss < brk) {
			error = cloudabi_binfmt_setbrk(bss, brk);
			if (error != 0)
				goto out;
			len = ELF_PAGEOFFSET(bss);
			if (len != 0) {
				len = ELF_MIN_ALIGN - len;
				if (len > brk - bss)
					len = brk - bss;
				if (clear_user((void __user *)bss, len)) {
					/* TODO(ed): Error handling. */
				}
			}
		}

		addr = cloudabi_binfmt_phdr_map(file, phdr);
		if (addr >= MAX_ADDR) {
			error = IS_ERR((void *)addr) ?
			    PTR_ERR((void *)addr) : -EINVAL;
			goto out;
		}

		if (!load_addr_set) {
			load_addr = phdr->p_vaddr - phdr->p_offset;
			load_addr_set = true;
		}

		/*
		 * Compute the start/end addresses of code and data, to
		 * be stored in the task's mm.
		 */
		addr = phdr->p_vaddr;
		if (start_code > addr)
			start_code = addr;
		if (start_data < addr)
			start_data = addr;

		/* TODO(ed): Overflow checks! */
		addr = phdr->p_vaddr + phdr->p_filesz;
		if (bss < addr)
			bss = addr;
		if ((phdr->p_flags & PF_X) != 0 && end_code < addr)
			end_code = addr;
		if (end_data < addr)
			end_data = addr;

		addr = phdr->p_vaddr + phdr->p_memsz;
		if (brk < addr)
			brk = addr;
	}

	error = cloudabi_binfmt_setbrk(bss, brk);
	if (error != 0)
		goto out;
	if (bss != brk) {
		error = cloudabi_binfmt_padzero(bss);
		if (error != 0)
			goto out;
	}

	set_binfmt(&cloudabi_binfmt_format);

	/* Determine where argument and environment data starts/ends. */
	p = mm->arg_end = mm->arg_start;
	for (argc = bprm->argc; argc > 0; argc--) {
		size_t len = strnlen_user((void __user *)p, MAX_ARG_STRLEN);
		if (!len || len > MAX_ARG_STRLEN)
			return -EINVAL;
		p += len;
	}
	mm->arg_end = mm->env_start = mm->env_end = p;

	install_exec_creds(bprm);
	error = cloudabi_binfmt_init_stack(bprm, hdr, load_addr);
	if (error != 0)
		goto out;

	mm->start_code = start_code;
	mm->end_code = end_code;
	mm->start_data = start_data;
	mm->end_data = end_data;
	mm->start_stack = bprm->p;

	if ((current->flags & PF_RANDOMIZE) != 0 && randomize_va_space > 1) {
		mm->brk = mm->start_brk = arch_randomize_brk(mm);
#ifdef CONFIG_COMPAT_BRK
		current->brk_randomized = 1;
#endif
	}

	entry = hdr->e_entry;
	if (entry >= MAX_ADDR) {
		error = -EINVAL;
		goto out;
	}

	/* Set initial register values. */
	regs = current_pt_regs();
	ELF_PLAT_INIT(regs, reloc_func_desc);
#ifdef __x86_64__
	/* TODO(ed): This should be solved more elegantly. */
	regs->di = bprm->p;
	bprm->p = rounddown(bprm->p, 16) - 8;
#else
#error "Unknown architecture"
#endif
	start_thread(regs, entry, bprm->p);
	set_tsk_thread_flag(current, TIF_CLOUDABI);
	task_set_openat_beneath(current);

	error = 0;
out:
	kfree(phdrs);
	return error;
}

static int __init cloudabi_binfmt_init(void)
{
	register_binfmt(&cloudabi_binfmt_format);
	return 0;
}

static void __exit cloudabi_binfmt_exit(void)
{
	unregister_binfmt(&cloudabi_binfmt_format);
}

core_initcall(cloudabi_binfmt_init);
module_exit(cloudabi_binfmt_exit);
MODULE_LICENSE("GPL");
