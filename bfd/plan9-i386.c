/* BFD back-end for Plan 9 386 binaries.
   Copyright 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997, 1998, 1999,
   2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011
   Free Software Foundation, Inc.
   Written by Cygnus Support.

   This file is part of BFD, the Binary File Descriptor library.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

#undef TARGET_IS_BIG_ENDIAN_P
#define	TARGET_PAGE_SIZE	4096
#define	DEFAULT_ARCH	bfd_arch_i386
#define MY(OP) CONCAT2(plan9_i386_,OP)
#define TARGETNAME "plan9-i386"

/* This is the normal load address for executables.  */
#define TEXT_START_ADDR		TARGET_PAGE_SIZE

/* see include/aout/aout64.h; neither value describes Plan 9 exactly  */
#define N_HEADER_IN_TEXT(x)	1

/* Determine if this is a shared library (no!).  */
#define N_SHARED_LIB(x) 	0

#define	_MAGIC(b)	((((4*b)+0)*b)+7)
#define	I_MAGIC		_MAGIC(11)	/* intel 386 */
#define	QMAGIC I_MAGIC	/* fake out aout macros */

#include "sysdep.h"
#include "bfd.h"
#include "libbfd.h"
#include "libaout.h"

#define MY_symbol_leading_char '\0'

#define MY_BFD_TARGET
#define MY_write_object_contents MY(write_object_contents)
#define MY_object_p MY (object_p)

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
	0,	/* add_one_symbol */
	0,	/* link_dynamic_object */
	0,	/* write_dynamic_symbol */
	0,	/* check_dynamic_reloc */
	0,	/* finish_dynamic_link */
};

/* Write an object file.
   Section contents have already been written.  We write the
   file header only. */

static bfd_boolean
MY(write_object_contents) (bfd *abfd)
{
	struct external_exec exec_bytes;
	struct internal_exec *execp = exec_hdr (abfd);
	bfd_size_type amt = EXEC_BYTES_SIZE;

	/*
		We must make certain that the magic number has been set.  This
		will normally have been done by set_section_contents, but only if
		there actually are some section contents.
	*/
	if (! abfd->output_has_begun) {
		bfd_size_type text_size;
		file_ptr text_end;
		NAME (aout, adjust_sizes_and_vmas) (abfd, &text_size, &text_end);
	}

	/* Writing header for *.o file */
	if(adata(abfd).magic == o_magic) {
		obj_reloc_entry_size (abfd) = RELOC_STD_SIZE;
		WRITE_HEADERS(abfd, execp);
		return TRUE;
	}

	/* Now subverting WRITE_HEADERS from libaout.h 
	 * ------------------------------------------- */

	/* Writing header for binary and default/undecided magic */
	N_SET_MACHTYPE (*execp, M_386);
	switch (bfd_get_arch (abfd)) {
	case bfd_arch_i386:
		execp->a_info = QMAGIC;
		break;
	default:
		execp->a_info = 0;
		break;
	}

	/* Writing struct for binary */
	obj_reloc_entry_size (abfd) = RELOC_STD_SIZE; /* reloc before write_headers */
	
	/* From DHog's original port
	 * execp->a_syms = obj_sym_filepos (abfd) - N_SYMOFF (*execp);
	 * He deleted all symbols from a_syms ¿? because
	 * obj_sym_filepos (abfd) = N_SYMOFF (*execp) in aout-target.h.
	 * Only God knows why...
	 */
	execp->a_syms = bfd_get_symcount (abfd) * EXTERNAL_NLIST_SIZE;
	execp->a_entry = bfd_get_start_address (abfd);

	/* Those must be 0 for executable */
	execp->a_trsize = 0;
	execp->a_drsize = 0;

	/* stupid hack, because N_HEADER_IN_TEXT can't describe us exactly */
	execp->a_text -= 0x20;

	/* Compositing header with all of written before*/
	NAME (aout, swap_exec_header_out) (abfd, execp, &exec_bytes);

	/* Check for operation failed */
	if (bfd_seek (abfd, (file_ptr) 0, SEEK_SET) != 0)
		return FALSE;
	if (bfd_bwrite ((void *) &exec_bytes, amt, abfd) != amt)
		return FALSE;

	/* Now write out reloc info, followed by syms and strings.  */
	if (bfd_get_outsymbols (abfd) != NULL
		&& bfd_get_symcount (abfd) != 0)
	{
		if (bfd_seek (abfd, (file_ptr) (N_SYMOFF(*execp)), SEEK_SET) != 0)
			return FALSE;

		if (! NAME (aout, write_syms) (abfd))
			return FALSE;
	}

	if (bfd_seek (abfd, (file_ptr) (N_TRELOFF (*execp)), SEEK_SET) != 0)
		return FALSE;
	if (!NAME (aout, squirt_out_relocs) (abfd, obj_textsec (abfd)))
		return FALSE;

	if (bfd_seek (abfd, (file_ptr) (N_DRELOFF (*execp)), SEEK_SET) != 0)
		return FALSE;
	if (!NAME (aout, squirt_out_relocs) (abfd, obj_datasec (abfd)))
		return FALSE;

	return TRUE;

}

static const bfd_target *
some_plan9_object_p (bfd *abfd,
				 struct internal_exec *execp,
				 const bfd_target *(*callback_to_real_object_p) (bfd *))
{
	struct aout_data_struct *rawptr, *oldrawptr;
	const bfd_target *result;
	bfd_size_type amt = sizeof (* rawptr);

	rawptr = (struct aout_data_struct *) bfd_zalloc (abfd, amt);
	if (rawptr == NULL)
		return NULL;

	oldrawptr = abfd->tdata.aout_data;
	abfd->tdata.aout_data = rawptr;

	/* Copy the contents of the old tdata struct.
	   In particular, we want the subformat, since for hpux it was set in
	   hp300hpux.c:swap_exec_header_in and will be used in
	   hp300hpux.c:callback.  */
	if (oldrawptr != NULL)
		*abfd->tdata.aout_data = *oldrawptr;

	abfd->tdata.aout_data->a.hdr = &rawptr->e;
	/* Copy in the internal_exec struct.  */
	*(abfd->tdata.aout_data->a.hdr) = *execp;
	execp = abfd->tdata.aout_data->a.hdr;

	/* Set the file flags.  */
	abfd->flags = BFD_NO_FLAGS;
	if (execp->a_drsize || execp->a_trsize)
		abfd->flags |= HAS_RELOC;
	/* Setting of EXEC_P has been deferred to the bottom of this function.  */
	if (execp->a_syms)
		abfd->flags |= HAS_LINENO | HAS_DEBUG | HAS_SYMS | HAS_LOCALS;
	if (N_DYNAMIC (*execp))
		abfd->flags |= DYNAMIC;

	/* We are here in Plan 9 for this and the stupid hack following */
	adata (abfd).magic = z_magic;

	/* stupid hack, because N_HEADER_IN_TEXT can't describe us exactly */
	execp->a_text += 0x20;
	/* End of Plan 9 part */

	bfd_get_start_address (abfd) = execp->a_entry;

	obj_aout_symbols (abfd) = NULL;
	bfd_get_symcount (abfd) = execp->a_syms / sizeof (struct external_nlist);

	/* The default relocation entry size is that of traditional V7 Unix.  */
	obj_reloc_entry_size (abfd) = RELOC_STD_SIZE;

	/* The default symbol entry size is that of traditional Unix.  */
	obj_symbol_entry_size (abfd) = EXTERNAL_NLIST_SIZE;

#ifdef USE_MMAP
	bfd_init_window (&obj_aout_sym_window (abfd));
	bfd_init_window (&obj_aout_string_window (abfd));
#endif
	obj_aout_external_syms (abfd) = NULL;
	obj_aout_external_strings (abfd) = NULL;
	obj_aout_sym_hashes (abfd) = NULL;

	if (! NAME (aout, make_sections) (abfd))
		goto error_ret;

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
		|| (execp->a_entry >= obj_textsec (abfd)->vma
		&& execp->a_entry < (obj_textsec (abfd)->vma
			+ obj_textsec (abfd)->size)
		&& execp->a_trsize == 0
		&& execp->a_drsize == 0))
	abfd->flags |= EXEC_P;
#ifdef STAT_FOR_EXEC
	else
	{
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
		&& (fstat (fileno ((FILE *) (abfd->iostream)), &stat_buf) == 0)
		&& ((stat_buf.st_mode & 0111) != 0))
			abfd->flags |= EXEC_P;
	}
#endif /* STAT_FOR_EXEC */

	if (result)
		return result;

	error_ret:
		bfd_release (abfd, rawptr);
		abfd->tdata.aout_data = oldrawptr;
		return NULL;
}

/* Finish up the reading of an a.out file header.  */

static const bfd_target *
MY (object_p) (bfd *abfd)
{
	struct external_exec exec_bytes;	/* Raw exec header from file.  */
	struct internal_exec exec;		/* Cleaned-up exec header.  */
	const bfd_target *target;
	bfd_size_type amt = EXEC_BYTES_SIZE;

	if (bfd_bread ((void *) &exec_bytes, amt, abfd) != amt)
	{
		if (bfd_get_error () != bfd_error_system_call)
			bfd_set_error (bfd_error_wrong_format);
		return 0;
	}

#ifdef SWAP_MAGIC
	exec.a_info = SWAP_MAGIC (exec_bytes.e_info);
#else
	exec.a_info = GET_MAGIC (abfd, exec_bytes.e_info);
#endif

	if (N_BADMAG (exec))
		return 0;

#ifdef MACHTYPE_OK
	if (!(MACHTYPE_OK (N_MACHTYPE (exec))))
		return 0;
#endif

	NAME (aout, swap_exec_header_in) (abfd, &exec_bytes, &exec);

#ifdef SWAP_MAGIC
	/* Swap_exec_header_in read in a_info with the wrong byte order.  */
	exec.a_info = SWAP_MAGIC (exec_bytes.e_info);
#endif

	/* We are here in Plan 9 just for this. We separeted header file
	 * generation for binary in MY (write_object_contents). Now
	 * checking for binary to use our function or if is object file
	 * use standard aout from aoutx.h */
 
	if(N_MAGIC(exec) == QMAGIC)
		target = some_plan9_object_p (abfd, &exec, MY(callback));
	else
		target = NAME(aout,some_aout_object_p)  (abfd, &exec, MY(callback));

#ifdef ENTRY_CAN_BE_ZERO
  /* The NEWSOS3 entry-point is/was 0, which (amongst other lossage)
     means that it isn't obvious if EXEC_P should be set.
     All of the following must be true for an executable:
     There must be no relocations, the bfd can be neither an
     archive nor an archive element, and the file must be executable.  */

	if (exec.a_trsize + exec.a_drsize == 0
		&& bfd_get_format(abfd) == bfd_object && abfd->my_archive == NULL)
	{
		struct stat buf;
#ifndef S_IXUSR
#define S_IXUSR 0100	/* Execute by owner.  */
#endif
		if (stat(abfd->filename, &buf) == 0 && (buf.st_mode & S_IXUSR))
			abfd->flags |= EXEC_P;
	}
#endif /* ENTRY_CAN_BE_ZERO */

	return target;
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

  MY_backend_data
};
