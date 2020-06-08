/* BFD back-end for Plan 9 386 binaries.
   Copyright (C) 1990, 91, 92, 94, 95, 96, 1998, 1999, 2000,
   2001, 2002, 2004, 2005, 2006, 2007, 2010, 2011
   Free Software Foundation, Inc.

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

#define	BYTES_IN_WORD	4
#undef TARGET_IS_BIG_ENDIAN_P

#define	TARGET_PAGE_SIZE	4096
#define	SEGMENT_SIZE	TARGET_PAGE_SIZE

#define	DEFAULT_ARCH	bfd_arch_i386
#define	DEFAULT_MID 	M_386

#define MY(OP) CONCAT2(plan9_i386_,OP)
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

#include "bfd.h"
#include "sysdep.h"
#include "libbfd.h"
#include "libaout.h"

#define MY_symbol_leading_char '\0'

#define MY_BFD_TARGET
#define MY_object_p MY(object_p)
#define MY_write_object_contents MY(write_object_contents)
#define MY_canonicalize_symtab MY(canonicalize_symtab)
#define MY_get_symtab_upper_bound MY(get_symtab_upper_bound)
#define MY_read_minisymbols _bfd_generic_read_minisymbols
#define MY_minisymbol_to_symbol _bfd_generic_minisymbol_to_symbol
#define MY_translate_symbol_table MY(translate_symbol_table)

/* static bfd_boolean MY(write_dynamic_symbol)
  (bfd *, struct bfd_link_info *, struct aout_link_hash_entry *);

static bfd_boolean MY(add_one_symbol)
  (struct bfd_link_info *, bfd *, const char *, flagword, asection *, bfd_vma, const char *, bfd_boolean,
		bfd_boolean, struct bfd_link_hash_entry **);

static bfd_boolean MY(finish_dynamic_link)
  (bfd *, struct bfd_link_info *); */

long MY (canonicalize_symtab)
  (bfd *, asymbol **);

long MY (get_symtab_upper_bound)
  (bfd *);

#define	N_BADMAG(x) (N_MAGIC(x) != QMAGIC && N_MAGIC(x) != OMAGIC)
#define	MY_backend_data &MY(backend_data)

#undef N_SYMOFF
#define N_SYMOFF(x)	( N_MAGIC(x) == QMAGIC ? N_DATOFF(x) + (x).a_data : N_DRELOFF(x) + (x).a_drsize )

#include "aout-target.h"

static const struct aout_backend_data MY(backend_data) = {
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

static bfd_boolean
MY(write_object_contents) (bfd *abfd)
{
	struct external_exec exec_bytes;
	struct internal_exec *execp = exec_hdr (abfd);
	bfd_size_type text_size;
	bfd_size_type amt = EXEC_BYTES_SIZE;
	file_ptr text_end;

	/*
		We must make certain that the magic number has been set.  This
		will normally have been done by set_section_contents, but only if
		there actually are some section contents.
	*/
	if (! abfd->output_has_begun)
		NAME (aout, adjust_sizes_and_vmas) (abfd, &text_size, &text_end);

	if(adata(abfd).magic == o_magic) {
		obj_reloc_entry_size (abfd) = RELOC_STD_SIZE;
		WRITE_HEADERS(abfd, execp);
		return TRUE;
	}

	switch (bfd_get_arch (abfd)) {
	case bfd_arch_i386:
		execp->a_info = QMAGIC;
		break;
	default:
		execp->a_info = 0;
		break;
	}

	execp->a_syms = obj_sym_filepos (abfd)-N_SYMOFF (*execp);
	execp->a_trsize = 0;
	execp->a_drsize = 0;
	execp->a_entry = bfd_get_start_address (abfd);

	/* stupid hack, because N_HEADER_IN_TEXT can't describe us exactly */
	execp->a_text -= 0x20;

	NAME (aout, swap_exec_header_out) (abfd, execp, &exec_bytes);

	if (bfd_seek (abfd, (file_ptr) 0, SEEK_SET) != 0) return FALSE;
	if (bfd_bwrite ((void *) &exec_bytes, amt, abfd) != amt)
		return FALSE;

	return TRUE;
}

/* Finish up the reading of an a.out file header */

static const bfd_target *
NAME (aout, some_plan9_object_p) (bfd *abfd,
					struct internal_exec *execp,
					const bfd_target *(*callback_to_real_object_p) (bfd *))
{
	struct aout_data_struct *rawptr, *oldrawptr;
	const bfd_target *result;
	bfd_size_type amt = sizeof (struct aout_data_struct);

	rawptr = bfd_zalloc (abfd, amt);
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
	if (N_DYNAMIC(*execp))
		abfd->flags |= DYNAMIC;

	adata (abfd).magic = z_magic;

	/* stupid hack, because N_HEADER_IN_TEXT can't describe us exactly */
	execp->a_text += 0x20;

	bfd_get_start_address (abfd) = execp->a_entry;

	obj_aout_symbols (abfd) = (aout_symbol_type *)NULL;
	bfd_get_symcount (abfd) = 0;	/* XXX */
	obj_reloc_entry_size (abfd) = 1;
	obj_symbol_entry_size (abfd) = 1;

#ifdef USE_MMAP
	bfd_init_window (&obj_aout_sym_window (abfd));
	bfd_init_window (&obj_aout_string_window (abfd));
#endif
	obj_aout_external_syms (abfd) = NULL;
	obj_aout_external_strings (abfd) = NULL;
	obj_aout_sym_hashes (abfd) = NULL;

	if (! NAME (aout, make_sections) (abfd))
		return NULL;

	obj_datasec (abfd)->size = execp->a_data;
	obj_bsssec (abfd)->size = execp->a_bss;

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
			&& execp->a_entry < obj_textsec(abfd)->vma + obj_textsec(abfd)->size))
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
MY(object_p) (bfd *abfd)
{
	struct external_exec exec_bytes;	/* Raw exec header from file */
	struct internal_exec exec;		/* Cleaned-up exec header */
	const bfd_target *target;
	bfd_size_type amt = EXEC_BYTES_SIZE;

	if (bfd_bread ((void *) &exec_bytes, amt, abfd) != amt)
		{
			if (bfd_get_error () != bfd_error_system_call)
	bfd_set_error (bfd_error_wrong_format);
		return 0;
	}

	exec.a_info = GET_MAGIC (abfd, exec_bytes.e_info);

	if (N_BADMAG (exec))
		return 0;

	NAME (aout, swap_exec_header_in) (abfd, &exec_bytes, &exec);
	if(N_MAGIC(exec) == QMAGIC)
		target = NAME (aout, some_plan9_object_p) (abfd, &exec, MY(callback));
	else
		target = NAME (aout, some_aout_object_p)  (abfd, &exec, MY(callback));
	return target;
}

static bfd_boolean
putsym (bfd *abfd, int type, char *prefix, char *name, bfd_vma value)
{
	int n;
	char buf[5];

	if(bfd_seek (abfd, obj_sym_filepos (abfd), SEEK_SET) != 0)
		return FALSE;

	bfd_h_put_32(abfd, value, buf);
	buf[4] = type | 0x80;
	if((int)bfd_bwrite ((void *) buf, (bfd_size_type) sizeof(buf) * (bfd_size_type) 1, abfd) != sizeof(buf))
		return FALSE;
	obj_sym_filepos (abfd) += sizeof(buf);

	if(prefix != 0) {
		n = strlen(prefix);
		if((int)bfd_bwrite ((void *) prefix, (bfd_size_type) n * (bfd_size_type) 1, abfd) != n)
			return FALSE;
		obj_sym_filepos (abfd) += n;
	}

	n = strlen(name)+1;
	if((int)bfd_bwrite ((void *) name, (bfd_size_type) n * (bfd_size_type) 1, abfd) != n)
		return FALSE;
	obj_sym_filepos (abfd) += n;

	++obj_aout_external_sym_count (abfd);
	return TRUE;
}



/* Read the external symbols from an a.out file.  */

static bfd_boolean
aout_get_external_symbols (bfd *abfd)
{
  if (obj_aout_external_syms (abfd) == NULL)
    {
      bfd_size_type count;
      struct external_nlist *syms;

      count = exec_hdr (abfd)->a_syms / EXTERNAL_NLIST_SIZE;
      if (count == 0)
	return TRUE;		/* Nothing to do.  */

      /* We allocate using malloc to make the values easy to free
	 later on.  If we put them on the objalloc it might not be
	 possible to free them.  */
      syms = (struct external_nlist *) bfd_malloc (count * EXTERNAL_NLIST_SIZE);
      if (syms == NULL)
		return FALSE;

      {
	bfd_size_type amt;
	amt = exec_hdr (abfd)->a_syms;
	if (bfd_seek (abfd, obj_sym_filepos (abfd), SEEK_SET) != 0
	    || bfd_bread (syms, amt, abfd) != amt)
	  {
	    free (syms);
	    return FALSE;
	  }
      }

      obj_aout_external_syms (abfd) = syms;
      obj_aout_external_sym_count (abfd) = count;
    }

  if (obj_aout_external_strings (abfd) == NULL
      && exec_hdr (abfd)->a_syms != 0)
    {
      unsigned char string_chars[BYTES_IN_WORD];
      bfd_size_type stringsize;
      char *strings;
      bfd_size_type amt = BYTES_IN_WORD;

      /* Get the size of the strings.  */
      if (bfd_seek (abfd, obj_str_filepos (abfd), SEEK_SET) != 0
	  || bfd_bread ((void *) string_chars, amt, abfd) != amt)
	return FALSE;
      stringsize = GET_WORD (abfd, string_chars);
      printf("DEBUG: aout_get_external, stringsize = %i\n", stringsize);
      strings = (char *) bfd_malloc (stringsize + 1);
      if (strings == NULL)
	return FALSE;

      /* Skip space for the string count in the buffer for convenience
	 when using indexes.  */
      amt = stringsize - BYTES_IN_WORD;
      if (bfd_bread (strings + BYTES_IN_WORD, amt, abfd) != amt)
	{
	  free (strings);
	  printf("DEBUG: aout_get_external, bfd_bread\n");
	  return FALSE;
	}

      /* Ensure that a zero index yields an empty string.  */
      strings[0] = '\0';

      strings[stringsize - 1] = 0;

      obj_aout_external_strings (abfd) = strings;
      obj_aout_external_string_size (abfd) = stringsize;
    }

  return TRUE;
}

/* Translate an a.out symbol into a BFD symbol.  The desc, other, type
   and symbol->value fields of CACHE_PTR will be set from the a.out
   nlist structure.  This function is responsible for setting
   symbol->flags and symbol->section, and adjusting symbol->value.  */

static bfd_boolean
translate_from_native_sym_flags (bfd *abfd, aout_symbol_type *cache_ptr)
{
  flagword visible;

  if ((cache_ptr->type & N_STAB) != 0
      || cache_ptr->type == N_FN)
    {
      asection *sec;

      /* This is a debugging symbol.  */
      cache_ptr->symbol.flags = BSF_DEBUGGING;

      /* Work out the symbol section.  */
      switch (cache_ptr->type & N_TYPE)
	{
	case N_TEXT:
	case N_FN:
	  sec = obj_textsec (abfd);
	  break;
	case N_DATA:
	  sec = obj_datasec (abfd);
	  break;
	case N_BSS:
	  sec = obj_bsssec (abfd);
	  break;
	default:
	case N_ABS:
	  sec = bfd_abs_section_ptr;
	  break;
	}

      cache_ptr->symbol.section = sec;
      cache_ptr->symbol.value -= sec->vma;

      return TRUE;
    }

  /* Get the default visibility.  This does not apply to all types, so
     we just hold it in a local variable to use if wanted.  */
  if ((cache_ptr->type & N_EXT) == 0)
    visible = BSF_LOCAL;
  else
    visible = BSF_GLOBAL;

  switch (cache_ptr->type)
    {
    default:
    case N_ABS: case N_ABS | N_EXT:
      cache_ptr->symbol.section = bfd_abs_section_ptr;
      cache_ptr->symbol.flags = visible;
      break;

    case N_UNDF | N_EXT:
      if (cache_ptr->symbol.value != 0)
	{
	  /* This is a common symbol.  */
	  cache_ptr->symbol.flags = BSF_GLOBAL;
	  cache_ptr->symbol.section = bfd_com_section_ptr;
	}
      else
	{
	  cache_ptr->symbol.flags = 0;
	  cache_ptr->symbol.section = bfd_und_section_ptr;
	}
      break;

    case N_TEXT: case N_TEXT | N_EXT:
      cache_ptr->symbol.section = obj_textsec (abfd);
      cache_ptr->symbol.value -= cache_ptr->symbol.section->vma;
      cache_ptr->symbol.flags = visible;
      break;

      /* N_SETV symbols used to represent set vectors placed in the
	 data section.  They are no longer generated.  Theoretically,
	 it was possible to extract the entries and combine them with
	 new ones, although I don't know if that was ever actually
	 done.  Unless that feature is restored, treat them as data
	 symbols.  */
    case N_SETV: case N_SETV | N_EXT:
    case N_DATA: case N_DATA | N_EXT:
      cache_ptr->symbol.section = obj_datasec (abfd);
      cache_ptr->symbol.value -= cache_ptr->symbol.section->vma;
      cache_ptr->symbol.flags = visible;
      break;

    case N_BSS: case N_BSS | N_EXT:
      cache_ptr->symbol.section = obj_bsssec (abfd);
      cache_ptr->symbol.value -= cache_ptr->symbol.section->vma;
      cache_ptr->symbol.flags = visible;
      break;

    case N_SETA: case N_SETA | N_EXT:
    case N_SETT: case N_SETT | N_EXT:
    case N_SETD: case N_SETD | N_EXT:
    case N_SETB: case N_SETB | N_EXT:
      {
	/* This code is no longer needed.  It used to be used to make
           the linker handle set symbols, but they are now handled in
           the add_symbols routine instead.  */
	switch (cache_ptr->type & N_TYPE)
	  {
	  case N_SETA:
	    cache_ptr->symbol.section = bfd_abs_section_ptr;
	    break;
	  case N_SETT:
	    cache_ptr->symbol.section = obj_textsec (abfd);
	    break;
	  case N_SETD:
	    cache_ptr->symbol.section = obj_datasec (abfd);
	    break;
	  case N_SETB:
	    cache_ptr->symbol.section = obj_bsssec (abfd);
	    break;
	  }

	cache_ptr->symbol.flags |= BSF_CONSTRUCTOR;
      }
      break;

    case N_WARNING:
      /* This symbol is the text of a warning message.  The next
	 symbol is the symbol to associate the warning with.  If a
	 reference is made to that symbol, a warning is issued.  */
      cache_ptr->symbol.flags = BSF_DEBUGGING | BSF_WARNING;
      cache_ptr->symbol.section = bfd_abs_section_ptr;
      break;

    case N_INDR: case N_INDR | N_EXT:
      /* An indirect symbol.  This consists of two symbols in a row.
	 The first symbol is the name of the indirection.  The second
	 symbol is the name of the target.  A reference to the first
	 symbol becomes a reference to the second.  */
      cache_ptr->symbol.flags = BSF_DEBUGGING | BSF_INDIRECT | visible;
      cache_ptr->symbol.section = bfd_ind_section_ptr;
      break;

    case N_WEAKU:
      cache_ptr->symbol.section = bfd_und_section_ptr;
      cache_ptr->symbol.flags = BSF_WEAK;
      break;

    case N_WEAKA:
      cache_ptr->symbol.section = bfd_abs_section_ptr;
      cache_ptr->symbol.flags = BSF_WEAK;
      break;

    case N_WEAKT:
      cache_ptr->symbol.section = obj_textsec (abfd);
      cache_ptr->symbol.value -= cache_ptr->symbol.section->vma;
      cache_ptr->symbol.flags = BSF_WEAK;
      break;

    case N_WEAKD:
      cache_ptr->symbol.section = obj_datasec (abfd);
      cache_ptr->symbol.value -= cache_ptr->symbol.section->vma;
      cache_ptr->symbol.flags = BSF_WEAK;
      break;

    case N_WEAKB:
      cache_ptr->symbol.section = obj_bsssec (abfd);
      cache_ptr->symbol.value -= cache_ptr->symbol.section->vma;
      cache_ptr->symbol.flags = BSF_WEAK;
      break;
    }

  return TRUE;
}

/* Translate a set of internal symbols into external symbols.  */

static bfd_boolean
MY (translate_symbol_table) (bfd *abfd,
				     aout_symbol_type *in,
				     struct external_nlist *ext,
				     bfd_size_type count,
				     char *str,
				     bfd_size_type strsize,
				     bfd_boolean dynamic)
{
  struct external_nlist *ext_end;

  ext_end = ext + count;
  for (; ext < ext_end; ext++, in++)
    {
      bfd_vma x;

      x = GET_WORD (abfd, ext->e_strx);
      in->symbol.the_bfd = abfd;

      /* For the normal symbols, the zero index points at the number
	 of bytes in the string table but is to be interpreted as the
	 null string.  For the dynamic symbols, the number of bytes in
	 the string table is stored in the __DYNAMIC structure and the
	 zero index points at an actual string.  */
      if (x == 0 && ! dynamic)
	in->symbol.name = "";
      else if (x < strsize)
	in->symbol.name = str + x;
      else
	return FALSE;

      in->symbol.value = GET_SWORD (abfd,  ext->e_value);
      in->desc = H_GET_16 (abfd, ext->e_desc);
      in->other = H_GET_8 (abfd, ext->e_other);
      in->type = H_GET_8 (abfd,  ext->e_type);
      in->symbol.udata.p = NULL;

      if (! translate_from_native_sym_flags (abfd, in))
	return FALSE;

      if (dynamic)
	in->symbol.flags |= BSF_DYNAMIC;
    }

  return TRUE;
}

/*
static bfd_boolean
MY(slurp_symbol_table) (bfd *abfd)
{
	aout_symbol_type *cached;
	size_t cached_size;
	unsigned char *syms, *p, *ep;
	int i, n, nsyms;
	asection *sec;

	// been here, done that *
	if (obj_aout_symbols (abfd) != NULL)
		return TRUE;

	n = exec_hdr (abfd)->a_syms;
	if(n == 0)
		return TRUE;
	syms = bfd_zmalloc(n);
	if (syms == NULL)
		return FALSE;
	if (bfd_seek (abfd, obj_sym_filepos (abfd), SEEK_SET) != 0
	|| ((int)bfd_bread (syms, 1 * n, abfd) != n )) {
		free (syms);
		return FALSE;
	}
	p = syms;
	ep = p+n;
	nsyms = 0;
	for (p += 5; p < ep && *p != '\0'; p++)
			nsyms++;
	bfd_get_symcount (abfd) = nsyms;
	obj_aout_external_sym_count (abfd) = nsyms;

	cached_size = (nsyms * sizeof (aout_symbol_type));
	cached = (aout_symbol_type *) bfd_zmalloc (cached_size);
	if (cached == NULL && cached_size != 0)
		return FALSE;
	if (cached_size != 0)
		memset (cached, 0, cached_size);

	p = syms;
	for(i = 0; i < nsyms; i++) {
		cached[i].symbol.value = GET_MAGIC (abfd, p);
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
	return TRUE;
}
*/

/* We read the symbols into a buffer, which is discarded when this
   function exits.  We read the strings into a buffer large enough to
   hold them all plus all the cached symbol entries.  */

static bfd_boolean
MY (slurp_symbol_table) (bfd *abfd)
{
  struct external_nlist *old_external_syms;
  aout_symbol_type *cached;
  bfd_size_type cached_size;

  /* If there's no work to be done, don't do any.  */
  if (obj_aout_symbols (abfd) != NULL)
    return TRUE;

  old_external_syms = obj_aout_external_syms (abfd);

  if (! aout_get_external_symbols (abfd))
  {
	  printf("DEBUG: slurp: !aout_get_external\n");
    return FALSE;
  }

  cached_size = obj_aout_external_sym_count (abfd);
  if (cached_size == 0)
    return TRUE;		/* Nothing to do.  */

  cached_size *= sizeof (aout_symbol_type);
  cached = (aout_symbol_type *) bfd_zmalloc (cached_size);
  if (cached == NULL)
    return FALSE;

  /* Convert from external symbol information to internal.  */
  if (! (MY (translate_symbol_table)
	 (abfd, cached,
	  obj_aout_external_syms (abfd),
	  obj_aout_external_sym_count (abfd),
	  obj_aout_external_strings (abfd),
	  obj_aout_external_string_size (abfd),
	  FALSE)))
    {
      free (cached);
      return FALSE;
    }

  bfd_get_symcount (abfd) = obj_aout_external_sym_count (abfd);

  obj_aout_symbols (abfd) = cached;

  /* It is very likely that anybody who calls this function will not
     want the external symbol information, so if it was allocated
     because of our call to aout_get_external_symbols, we free it up
     right away to save space.  */
  if (old_external_syms == NULL
      && obj_aout_external_syms (abfd) != NULL)
    {
      free (obj_aout_external_syms (abfd));
      obj_aout_external_syms (abfd) = NULL;
    }

  return TRUE;
}

long
MY(canonicalize_symtab) (bfd *abfd, asymbol **location)
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
MY(get_symtab_upper_bound) (bfd *abfd)
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
  BFD_ENDIAN_LITTLE,            /* target byte order (little) */
  BFD_ENDIAN_BIG,		/* target headers byte order (big) */
  (HAS_RELOC | EXEC_P |		/* object flags */
   HAS_LINENO | HAS_DEBUG |
   HAS_SYMS | HAS_LOCALS | DYNAMIC | WP_TEXT | D_PAGED),
  (SEC_HAS_CONTENTS | SEC_ALLOC | SEC_LOAD | SEC_RELOC | SEC_CODE | SEC_DATA),
  MY_symbol_leading_char,
  AR_PAD_CHAR,			/* AR_pad_char.  */
  15,				/* AR_max_namelen.  */
  0,				/* match priority.  */
  bfd_getl64, bfd_getl_signed_64, bfd_putl64,
     bfd_getl32, bfd_getl_signed_32, bfd_putl32,
     bfd_getl16, bfd_getl_signed_16, bfd_putl16, /* Data */
  // Plan9 headers are always Big Endian
  bfd_getb64, bfd_getb_signed_64, bfd_putb64,
     bfd_getb32, bfd_getb_signed_32, bfd_putb32,
     bfd_getb16, bfd_getb_signed_16, bfd_putb16, /* Headers.  */
    {_bfd_dummy_target, MY_object_p, /* bfd_check_format */
       bfd_generic_archive_p, MY_core_file_p},
    {bfd_false, MY_mkobject,	/* bfd_set_format */
       _bfd_generic_mkarchive, bfd_false},
    {bfd_false, MY_write_object_contents, /* bfd_write_contents */
       _bfd_write_archive_contents, bfd_false},

     BFD_JUMP_TABLE_GENERIC (MY),
     BFD_JUMP_TABLE_COPY (MY),			/* _bfd_generic */
     BFD_JUMP_TABLE_CORE (MY),			/* _bfd_nocore */
     BFD_JUMP_TABLE_ARCHIVE (MY),		/* _bfd_noarchive */
     BFD_JUMP_TABLE_SYMBOLS (MY),
     BFD_JUMP_TABLE_RELOCS (MY),			/* _bfd_norelocs */
     BFD_JUMP_TABLE_WRITE (MY),
     BFD_JUMP_TABLE_LINK (MY),
     BFD_JUMP_TABLE_DYNAMIC (MY),		/* _bfd_nodynamic */

  /* Alternative_target */
  NULL,

  (void *) MY_backend_data
};
