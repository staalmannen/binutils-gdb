/* BFD back-end for Plan 9 386 binaries.
   Copyright (C) 1990, 91, 92, 94, 95, 96, 1998 Free Software Foundation, Inc.

This file is part of BFD, the Binary File Descriptor library.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. */

/* TODO: this code is ~20 years old from binutils 2.11.2 and shoe-horned
 * into a modern binutils. Lots of style changes have happened in that time
 * and we should try to make the code specific for the plan9 target as small
 * as possible and leverage common aout code as much as possible. This version 
 * of the file is however as close as possible to the original port */

/* old style stuff that are now replaced */
// PARAMS ((x))  -->  (x) /* manually edited */
// (PTR) --> void * /* manually edited */
#define true TRUE
#define false FALSE
#define CONST const
#define boolean bfd_boolean
#define _raw_size rawsize
#define bfd_false _bfd_bool_bfd_false_error
#define link_order_head map_head.link_order
#define link_order_tail map_tail.link_order

#define MY(OP) CONCAT2 (i386_plan9_,OP) /* commented out the old version */
//#define NAME(x,y) CONCAT3 (i386_plan9,_32_,y)

#define NO_WRITE_HEADER_KLUDGE 1
/* back to old original code ...*/

#define	BYTES_IN_WORD	4
#undef TARGET_IS_BIG_ENDIAN_P

#define	TARGET_PAGE_SIZE	4096
#define	SEGMENT_SIZE	TARGET_PAGE_SIZE

#define	DEFAULT_ARCH	bfd_arch_i386
#define	DEFAULT_MID 	M_386

//#define MY(OP) CAT(plan9_i386_,OP)
#define TARGETNAME "plan9-i386"

/* This is the normal load address for executables.  */
#define TEXT_START_ADDR		TARGET_PAGE_SIZE

/* see include/aout/aout64.h; neither value describes Plan 9 exactly  */
#define N_HEADER_IN_TEXT(x)	1

/* Determine if this is a shared library.  */
#define N_SHARED_LIB(x) 	0

#define	_MAGIC(b)	((((4*b)+0)*b)+7)
#define	I_MAGIC		_MAGIC(11)	/* intel 386 */
#define	QMAGIC I_MAGIC	/* fake out aout macros */

#include "sysdep.h"         /* changed header order for config.h dependency */
#include "bfd.h"
#include "libbfd.h"
#include "aout/aout64.h"    /*header in i386aout.c*/
#include "libaout.h"

#define MY_symbol_leading_char '\0'

#define MY_BFD_TARGET
#define MY_object_p MY(object_p)
#define MY_get_section_contents aout_32_get_section_contents /* new addition */
#define MY_write_object_contents MY(write_object_contents) 
//#define MY_get_symtab_upper_bound plan9_i386_get_symtab_upper_bound
//#define MY_get_symtab plan9_i386_get_symtab

static boolean MY(write_dynamic_symbol)
  (bfd *, struct bfd_link_info *, struct aout_link_hash_entry *);

static boolean MY(add_one_symbol)
  (struct bfd_link_info *, bfd *, const char *, flagword, asection *, bfd_vma, const char *, boolean,
		boolean, struct bfd_link_hash_entry **);

static boolean MY(finish_dynamic_link)
  (bfd *, struct bfd_link_info *);

#define	N_BADMAG(x) (N_MAGIC(x) != QMAGIC && N_MAGIC(x) != OMAGIC)
#define	MY_backend_data &MY(backend_data)

#undef N_SYMOFF
// #define N_SYMOFF(x)	( N_MAGIC(x) == QMAGIC ? N_DATOFF(x) + (x).a_data : N_DRELOFF(x) + (x).a_drsize )
#define N_SYMOFF(x)	( N_MAGIC(x) == QMAGIC ? N_DATOFF(x) + (x)->a_data : N_DRELOFF(x) + (x)->a_drsize )
  
#include "aout-target.h"

static CONST struct aout_backend_data MY(backend_data) = {
	0,	/* zmagic_contiguous */
	1,	/* text_includes_header */
	0,	/* entry_is_text_address */
	0,	/* exec_hdr_flags */
	0x1020,	/* default_text_vma */
	MY_set_sizes,
	0,	/* exec_header_not_counted */
	0,	/* add_dynamic_symbols */
	MY(add_one_symbol),
	0,	/* link_dynamic_object */
	MY(write_dynamic_symbol),
	0,	/* check_dynamic_reloc */
	MY(finish_dynamic_link),
};

/* Write an object file.
   Section contents have already been written.  We write the
   file header only. */

static boolean
MY(write_object_contents) (abfd)
     bfd *abfd;
{
	struct external_exec exec_bytes;
	struct internal_exec *execp = exec_hdr (abfd);
//	bfd_size_type text_size;
//	file_ptr text_end;

	/*
		We must make certain that the magic number has been set.  This
		will normally have been done by set_section_contents, but only if
		there actually are some section contents.
	*/
	if (! abfd->output_has_begun)
		NAME(aout,adjust_sizes_and_vmas) (abfd); /*arguments text_size and text_end removed */

	if(adata(abfd).magic == o_magic) {
		obj_reloc_entry_size (abfd) = RELOC_STD_SIZE;
		WRITE_HEADERS(abfd, execp);
		return true;
	}

	switch (bfd_get_arch(abfd)) {
	case bfd_arch_i386:
		execp->a_info = QMAGIC;
		break;
	default:
		execp->a_info = 0;
		break;
	}

	execp->a_syms = obj_sym_filepos (abfd)-N_SYMOFF (execp); /* changed *execp to execp*/
	execp->a_trsize = 0;
	execp->a_drsize = 0;
	execp->a_entry = bfd_get_start_address (abfd);

	/* stupid hack, because N_HEADER_IN_TEXT can't describe us exactly */
	execp->a_text -= 0x20;

	NAME(aout,swap_exec_header_out) (abfd, execp, &exec_bytes);

	if (bfd_seek (abfd, (file_ptr) 0, SEEK_SET) != 0) return false;
	if (bfd_write ((void *) &exec_bytes, 1, EXEC_BYTES_SIZE, abfd) != EXEC_BYTES_SIZE)
		return false;

	return true;
}

/* Finish up the reading of an a.out file header */

static const bfd_target *
some_plan9_object_p (abfd, execp, callback_to_real_object_p)
     bfd *abfd;
     struct internal_exec *execp;
     const bfd_target *(*callback_to_real_object_p) (bfd *);
{
	struct aout_data_struct *rawptr, *oldrawptr;
	const bfd_target *result;

	rawptr = (struct aout_data_struct  *) bfd_zalloc (abfd, sizeof (struct aout_data_struct ));
	if (rawptr == NULL)
		return 0;

	oldrawptr = abfd->tdata.aout_data;
	abfd->tdata.aout_data = rawptr;

	/* Copy the contents of the old tdata struct.*/
	if (oldrawptr != NULL)
		*abfd->tdata.aout_data = *oldrawptr;

	abfd->tdata.aout_data->a.hdr = &rawptr->e;
	*(abfd->tdata.aout_data->a.hdr) = *execp;	/* Copy in the internal_exec struct */
	execp = abfd->tdata.aout_data->a.hdr;

	/* Set the file flags */
	abfd->flags = BFD_NO_FLAGS;
	/* Setting of EXEC_P has been deferred to the bottom of this function */
	if (execp->a_syms)
		abfd->flags |= HAS_LINENO | HAS_DEBUG | HAS_SYMS | HAS_LOCALS;
	if (N_DYNAMIC(execp))
		abfd->flags |= DYNAMIC;       

	adata (abfd).magic = z_magic;

	/* stupid hack, because N_HEADER_IN_TEXT can't describe us exactly */
	execp->a_text += 0x20;

    execp->a_entry = bfd_get_start_address (abfd); /* switched lvalue and rvalue */

	obj_aout_symbols (abfd) = (aout_symbol_type *)NULL;
	abfd->symcount = 0;	/* XXX */ /*replaced bfd_get_symcount (abfd) */
	obj_reloc_entry_size (abfd) = 1;
	obj_symbol_entry_size (abfd) = 1;

#ifdef USE_MMAP
	bfd_init_window (&obj_aout_sym_window (abfd));
	bfd_init_window (&obj_aout_string_window (abfd));
#endif
	obj_aout_external_syms (abfd) = NULL;
	obj_aout_external_strings (abfd) = NULL;
	obj_aout_sym_hashes (abfd) = NULL;

	if (! NAME(aout,make_sections) (abfd))
		return NULL;

	obj_datasec (abfd)->_raw_size = execp->a_data;
	obj_bsssec (abfd)->_raw_size = execp->a_bss;

	obj_textsec (abfd)->flags =
		(execp->a_trsize != 0
		? (SEC_ALLOC | SEC_LOAD | SEC_CODE | SEC_HAS_CONTENTS | SEC_RELOC)
		: (SEC_ALLOC | SEC_LOAD | SEC_CODE | SEC_HAS_CONTENTS));
	obj_datasec (abfd)->flags =
		(execp->a_drsize != 0
		? (SEC_ALLOC | SEC_LOAD | SEC_DATA | SEC_HAS_CONTENTS | SEC_RELOC)
		: (SEC_ALLOC | SEC_LOAD | SEC_DATA | SEC_HAS_CONTENTS));
	obj_bsssec (abfd)->flags = SEC_ALLOC;

	result = (*callback_to_real_object_p) (abfd);

	/* Now that the segment addresses have been worked out, take a better
		guess at whether the file is executable.  If the entry point
		is within the text segment, assume it is.  (This makes files
		executable even if their entry point address is 0, as long as
		their text starts at zero.).

		This test had to be changed to deal with systems where the text segment
		runs at a different location than the default.  The problem is that the
		entry address can appear to be outside the text segment, thus causing an
		erroneous conclusion that the file isn't executable.

		To fix this, we now accept any non-zero entry point as an indication of
		executability.  This will work most of the time, since only the linker
		sets the entry point, and that is likely to be non-zero for most systems.  */

	if (execp->a_entry != 0
		|| (execp->a_entry >= obj_textsec(abfd)->vma
			&& execp->a_entry < obj_textsec(abfd)->vma + obj_textsec(abfd)->_raw_size))
	abfd->flags |= EXEC_P;
#ifdef STAT_FOR_EXEC
	else {
		struct stat stat_buf;

		/* The original heuristic doesn't work in some important cases.
			The a.out file has no information about the text start
			address.  For files (like kernels) linked to non-standard
			addresses (ld -Ttext nnn) the entry point may not be between
			the default text start (obj_textsec(abfd)->vma) and
			(obj_textsec(abfd)->vma) + text size.  This is not just a mach
			issue.  Many kernels are loaded at non standard addresses.  */
		if (abfd->iostream != NULL
		&& (abfd->flags & BFD_IN_MEMORY) == 0
		&& (fstat(fileno((FILE *) (abfd->iostream)), &stat_buf) == 0)
		&& ((stat_buf.st_mode & 0111) != 0))
			abfd->flags |= EXEC_P;
	}
#endif /* STAT_FOR_EXEC */

	if (result) {
#if 0 /* These should be set correctly anyways.  */
		abfd->sections = obj_textsec (abfd);
		obj_textsec (abfd)->next = obj_datasec (abfd);
		obj_datasec (abfd)->next = obj_bsssec (abfd);
#endif
	}
	else {
		free (rawptr);
		abfd->tdata.aout_data = oldrawptr;
	}
	return result;
}

static const bfd_target *MY(object_p) (bfd *);

static const bfd_target *
MY(object_p) (abfd)
     bfd *abfd;
{
	struct external_exec exec_bytes;	/* Raw exec header from file */
	struct internal_exec exec;		/* Cleaned-up exec header */
	const bfd_target *target;

	if (bfd_read ((void *) &exec_bytes, 1, EXEC_BYTES_SIZE, abfd) != EXEC_BYTES_SIZE) {
		if (bfd_get_error () != bfd_error_system_call)
			bfd_set_error (bfd_error_wrong_format);
		return 0;
	}

	exec.a_info = bfd_h_get_32 (abfd, exec_bytes.e_info);

	if (N_BADMAG (&exec))      // added "&" based on aout-target.h
		return 0;

	NAME(aout,swap_exec_header_in) (abfd, &exec_bytes, &exec);
	if(N_MAGIC(&exec) == QMAGIC)
		target = some_plan9_object_p (abfd, &exec, MY(callback));
	else
		target = NAME(aout,some_aout_object_p)  (abfd, &exec, MY(callback));
	return target;
}

static boolean
putsym(abfd, type, prefix, name, value)
	bfd *abfd;
	int type;
	char *prefix;
	char *name;
	bfd_vma value;
{
	int n;
	char buf[5];

	if(bfd_seek (abfd, obj_sym_filepos (abfd), SEEK_SET) != 0)
		return false;

	bfd_h_put_32(abfd, value, buf);
	buf[4] = type | 0x80;
	if((int)bfd_write ((void *) buf, (bfd_size_type) sizeof(buf), (bfd_size_type) 1, abfd) != sizeof(buf))
		return false;
	obj_sym_filepos (abfd) += sizeof(buf);

	if(prefix != 0) {
		n = strlen(prefix);
		if((int)bfd_write ((void *) prefix, (bfd_size_type) n, (bfd_size_type) 1, abfd) != n)
			return false;
		obj_sym_filepos (abfd) += n;
	}

	n = strlen(name)+1;
	if((int)bfd_write ((void *) name, (bfd_size_type) n, (bfd_size_type) 1, abfd) != n)
		return false;
	obj_sym_filepos (abfd) += n;

	++obj_aout_external_sym_count (abfd);
	return true;
}

/*
 *	Totally evil hack alert!  We use MY(write_dynamic_symbol) and MY(finish_dynamic_link)
 *	to subvert aoutx.h into generating a Plan 9 symbol table instead of the a.out one.
 *	MY(add_one_symbol) is used to set the "written" flag on symbols so that externals
 *	only occur once.
 */
static boolean
MY(write_dynamic_symbol) (output_bfd, info, h)
     bfd *output_bfd;
     struct bfd_link_info *info;
     struct aout_link_hash_entry *h;
{
	int type;
	bfd_vma val;
	asection *sec;

	if (h->written)
		return true;

	h->written = true;

	/* An indx of -2 means the symbol must be written.  */
	if (h->indx != -2
		&& (info->strip == strip_all
		|| (info->strip == strip_some
		&& bfd_hash_lookup (info->keep_hash, h->root.root.string,
				false, false) == NULL)))
		return true;
	switch (h->root.type) {
	default:
		abort ();
		return true;
	case bfd_link_hash_new:
		/* This can happen for set symbols when sets are not being
			built.  */
		return true;
	case bfd_link_hash_defined:
	case bfd_link_hash_defweak:
		sec = h->root.u.def.section->output_section;
		BFD_ASSERT (bfd_is_abs_section (sec) || sec->owner == output_bfd);
		if (sec == obj_textsec (output_bfd))
			type = 'T';
		else if (sec == obj_datasec (output_bfd))
			type = 'D';
		else if (sec == obj_bsssec (output_bfd))
			type = 'B';
		else
			return true;
		val = (h->root.u.def.value + sec->vma + h->root.u.def.section->output_offset);
		break;
	case bfd_link_hash_common:
		type = N_UNDF | N_EXT;
		val = h->root.u.c.size;
//		break;
	case bfd_link_hash_undefweak:
	case bfd_link_hash_undefined:
		return true;
	case bfd_link_hash_indirect:
	case bfd_link_hash_warning:
		/* FIXME: Ignore these for now.  The circumstances under which
			they should be written out are not clear to me.  */
		return true;
	}
	if(!putsym(output_bfd, type, 0, h->root.root.string, val))
		return false;
	h->indx = obj_aout_external_sym_count (output_bfd)-1;
	return true;
}

static boolean
MY(add_one_symbol) (info, abfd, name, flags, section, value, string, copy, collect, hashp)
	struct bfd_link_info *info;
	 bfd *abfd;
	const char *name;
	flagword flags;
	asection *section;
	bfd_vma value;
	const char *string;
	boolean copy;
	boolean collect;
	struct bfd_link_hash_entry **hashp;
{
	struct aout_link_hash_entry **h;

	if(!_bfd_generic_link_add_one_symbol(info, abfd, name, flags, section, value, string, copy, collect, hashp))
		return false;
	h = (struct aout_link_hash_entry **)hashp;
	(*h)->written = true;
	return true;
}

/*
 *	BUG: this should do a  lot more; see aout_link_write_symbols()
 */
static boolean
MY(finish_dynamic_link) (abfd, info)
     bfd *abfd;
     struct bfd_link_info *info;
{
	asection *o, *isec, *osec;
	struct bfd_link_order *p;
	bfd *ibfd;
	struct external_nlist *s, *es;
	int type, other, desc, defd;
	bfd_vma value;
	char *strings, *name, prefix[64];
	struct aout_link_hash_entry **sym_hash, *h, *hresolve;

	for (o = abfd->sections; o != (asection *) NULL; o = o->next) {
		for (p = o->link_order_head; p != NULL; p = p->next) {
			if (p->type != bfd_indirect_link_order)
				continue;
			ibfd = p->u.indirect.section->owner;
			if(ibfd->output_has_begun)
				continue;
			if (bfd_get_flavour(ibfd) != bfd_target_plan9_flavour)
				continue;

			/* write a symbol for this object file XXX STRIP???*/
			isec = obj_textsec(ibfd);
			osec = isec->output_section;
			value = bfd_section_vma (osec) + isec->output_offset; /* drop _get_ and abfd */
			if(!putsym(abfd, 't', 0, ibfd->filename, value))
				return false;

			s = obj_aout_external_syms(ibfd);
			es = s + obj_aout_external_sym_count(ibfd);
			strings = obj_aout_external_strings(ibfd);
			sym_hash = obj_aout_sym_hashes(ibfd);
			for (; s < es; s++, sym_hash++) {
				name = strings + GET_WORD (ibfd, s->e_strx);
				type = bfd_h_get_8 (ibfd, s->e_type);
				value = GET_WORD (ibfd, s->e_value);
				h = *sym_hash;
				if(h != NULL)
					name = h->root.root.string;
				hresolve = h;
				if((type&N_TYPE) == N_TEXT || type == N_WEAKT || type == N_LBRAC || type == N_RBRAC)
					isec = obj_textsec(ibfd);
				else if((type&N_TYPE) == N_DATA || type == N_WEAKD)
					isec = obj_datasec(ibfd);
				else if((type&N_TYPE) == N_BSS || type == N_WEAKB)
					isec = obj_bsssec(ibfd);
				else if((type&N_TYPE) == N_ABS || type == N_WEAKA)
					isec = bfd_abs_section_ptr;
				else if(h == NULL)
					isec = NULL;	/* XXX */
				else if(hresolve->root.type == bfd_link_hash_defined
						|| hresolve->root.type == bfd_link_hash_defweak) {
					isec = hresolve->root.u.def.section;
					osec = isec->output_section;
					value = hresolve->root.u.def.value + osec->vma + isec->output_offset;
					type &=~ N_TYPE;
					defd = (hresolve->root.type == bfd_link_hash_defined);
					if(osec == obj_textsec(abfd)) {
						if(defd)
							type |= N_TEXT;
						else
							type |= N_WEAKT;
					}
					else if(osec == obj_datasec(abfd)) {
						if(defd)
							type |= N_DATA;
						else
							type |= N_WEAKD;
					}
					else if(osec == obj_bsssec(abfd)) {
						if(defd)
							type |= N_BSS;
						else
							type |= N_WEAKB;
					}
					else {
						if(defd)
							type |= N_ABS;
						else
							type |= N_WEAKA;
					}
					isec = NULL;
				}
				else
					isec = NULL;
				if(isec != NULL) {
					osec = isec->output_section;
					value += osec->vma - isec->vma + isec->output_offset;
				}
				switch(type) {
				case N_TEXT:
					if(!putsym(abfd, 't', 0, name, value))
						return false;
					break;
				case N_TEXT | N_EXT:
					if(!putsym(abfd, 'T', 0, name, value))
						return false;
					break;
				case N_DATA:
					if(!putsym(abfd, 'd', 0, name, value))
						return false;
					break;
				case N_DATA | N_EXT:
					if(!putsym(abfd, 'D', 0, name, value))
						return false;
					break;
				case N_BSS:
					if(!putsym(abfd, 'b', 0, name, value))
						return false;
					break;
				case N_BSS | N_EXT:
					if(!putsym(abfd, 'B', 0, name, value))
						return false;
					break;
				case N_UNDF | N_EXT:
					break;
				default:
					if((type&N_STAB) == 0)
						break;
					other = (int)bfd_h_get_8 (ibfd, s->e_other);
					desc = (int)bfd_h_get_16 (ibfd, s->e_desc);
					sprintf(prefix, "%2.2x%2.2x%4.4x", type, other, desc);
					if(!putsym(abfd, 'X', prefix, name, value))
						return false;
					break;
				}
			}
			ibfd->output_has_begun = true;
		}
	}

	obj_aout_external_sym_count (abfd) = 0;	/* prevent writing of an empty stringtab */
	return true;
}

static boolean
MY(slurp_symbol_table) (abfd)
     bfd *abfd;
{
	aout_symbol_type *cached;
	size_t cached_size;
	unsigned char *syms, *p, *ep;
	int i, n, nsyms;
	asection *sec;
    struct internal_exec execp;

	/* been here, done that */
	if (obj_aout_symbols (abfd) != NULL)
		return true;

	n = exec_hdr (abfd)->a_syms;
	if(n == 0)
		return true;
	syms = bfd_malloc(n);
	if (syms == NULL)
		return false;
	if (bfd_seek (abfd, obj_sym_filepos (abfd), SEEK_SET) != 0
	|| ((int)bfd_read (syms, 1, n , abfd) != n )) {
		free (syms);
		return false;
	}
	p = syms;
	ep = p+n;
	nsyms = 0;
	for(;;) {
		p += 5;
		while(p < ep && *p != '\0')
			p++;
		nsyms++;
	}
	abfd->symcount = nsyms; /* replaced bfd_get_symcount (abfd) */
	obj_aout_external_sym_count (abfd) = nsyms;

	cached_size = (nsyms * sizeof (aout_symbol_type));
	cached = (aout_symbol_type *) bfd_malloc (cached_size);
	if (cached == NULL && cached_size != 0)
		return false;
	if (cached_size != 0)
		memset (cached, 0, cached_size);

 	p = syms;
	for(i = 0; i < nsyms; i++) {
		cached[i].symbol.value = bfd_h_get_32(abfd, p);
		cached[i].symbol.name = strdup(&p[5]);
		switch(p[4] & ~0x80) {
		case 'T':
		case 'L':
			cached[i].symbol.flags = BSF_GLOBAL;
			sec = obj_textsec(abfd);
		case 't':
		case 'l':
			cached[i].symbol.flags = BSF_LOCAL;
			sec = obj_textsec(abfd);
		case 'D':
			cached[i].symbol.flags = BSF_GLOBAL;
			sec = obj_datasec(abfd);
		case 'd':
			cached[i].symbol.flags = BSF_LOCAL;
			sec = obj_datasec(abfd);
		case 'B':
			cached[i].symbol.flags = BSF_GLOBAL;
			sec = obj_bsssec(abfd);
		case 'b':
			cached[i].symbol.flags = BSF_LOCAL;
			sec = obj_bsssec(abfd);
		}
		cached[i].symbol.value -= sec->vma;
	}

	obj_aout_symbols (abfd) = cached;
	free(syms);
	return true;
}

long
MY(get_symtab) (abfd, location)
     bfd *abfd;
     asymbol **location;
{
	int i;
	aout_symbol_type *s;

	if (!MY(slurp_symbol_table)(abfd))
		return -1;

	s = obj_aout_symbols(abfd);
	for (i = 0; i < (int) bfd_get_symcount (abfd); i++)
		*(location++) = (asymbol *)(s++);
	*location++ =0;
	return bfd_get_symcount (abfd);
}

long
MY(get_symtab_upper_bound) (abfd)
     bfd *abfd;
{
	if (!MY(slurp_symbol_table)(abfd))
		return -1;

	return (bfd_get_symcount (abfd)+1) * (sizeof (aout_symbol_type *));
}

/* On Plan 9, the magic number is always in big-endian format.  */

const bfd_target MY(vec) =
{
  TARGETNAME,		/* name */
  bfd_target_plan9_flavour,
#ifdef TARGET_IS_BIG_ENDIAN_P
  BFD_ENDIAN_BIG,		/* Target byte order (big).  */
  BFD_ENDIAN_BIG,		/* Target headers byte order (big).  */
#else
  BFD_ENDIAN_LITTLE,		/* Target byte order (little).  */
  BFD_ENDIAN_LITTLE,		/* Target headers byte order (little).  */
#endif
  (HAS_RELOC | EXEC_P |		/* Object flags.  */
   HAS_LINENO | HAS_DEBUG |
   HAS_SYMS | HAS_LOCALS | DYNAMIC | WP_TEXT | D_PAGED),
  (SEC_HAS_CONTENTS | SEC_ALLOC | SEC_LOAD | SEC_RELOC | SEC_CODE | SEC_DATA),
  MY_symbol_leading_char,
  AR_PAD_CHAR,			/* AR_pad_char.  */
  15,				/* AR_max_namelen.  */
  0,				/* match priority.  */
#ifdef TARGET_IS_BIG_ENDIAN_P
  bfd_getb64, bfd_getb_signed_64, bfd_putb64,
     bfd_getb32, bfd_getb_signed_32, bfd_putb32,
     bfd_getb16, bfd_getb_signed_16, bfd_putb16, /* Data.  */
  bfd_getb64, bfd_getb_signed_64, bfd_putb64,
     bfd_getb32, bfd_getb_signed_32, bfd_putb32,
     bfd_getb16, bfd_getb_signed_16, bfd_putb16, /* Headers.  */
#else
  bfd_getl64, bfd_getl_signed_64, bfd_putl64,
     bfd_getl32, bfd_getl_signed_32, bfd_putl32,
     bfd_getl16, bfd_getl_signed_16, bfd_putl16, /* Data.  */
  bfd_getl64, bfd_getl_signed_64, bfd_putl64,
     bfd_getl32, bfd_getl_signed_32, bfd_putl32,
     bfd_getl16, bfd_getl_signed_16, bfd_putl16, /* Headers.  */
#endif
    {				/* bfd_check_format.  */
      _bfd_dummy_target,
      MY_object_p,
      bfd_generic_archive_p,
      MY_core_file_p
    },
    {				/* bfd_set_format.  */
      _bfd_bool_bfd_false_error,
      MY_mkobject,
      _bfd_generic_mkarchive,
      _bfd_bool_bfd_false_error
    },
    {				/* bfd_write_contents.  */
      _bfd_bool_bfd_false_error,
      MY_write_object_contents,
      _bfd_write_archive_contents,
      _bfd_bool_bfd_false_error
    },

     BFD_JUMP_TABLE_GENERIC (MY),
     BFD_JUMP_TABLE_COPY (MY),
     BFD_JUMP_TABLE_CORE (MY),
     BFD_JUMP_TABLE_ARCHIVE (MY),
     BFD_JUMP_TABLE_SYMBOLS (MY),
     BFD_JUMP_TABLE_RELOCS (MY),
     BFD_JUMP_TABLE_WRITE (MY),
     BFD_JUMP_TABLE_LINK (MY),
     BFD_JUMP_TABLE_DYNAMIC (MY),

  /* Alternative_target.  */
  NULL,

  MY_backend_data
};


