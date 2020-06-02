/* Plan 9 object file format.
	- Like a.out format, but always use big endian for headers, symbols etc.

   Copyright (C) 1989, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 2000
   Free Software Foundation, Inc.

This file is part of GAS, the GNU Assembler.

GAS is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as
published by the Free Software Foundation; either version 2,
or (at your option) any later version.

GAS is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
the GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with GAS; see the file COPYING.  If not, write to the Free
Software Foundation, 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.  */

/* TODO: this code is ~20 years old from binutils 2.11.2 and shoe-horned
 * into a modern binutils. Lots of style changes have happened in that time
 * and we should try to make the code specific for the plan9 target as small
 * as possible and leverage common aout code as much as possible. This version 
 * of the file is however as close as possible to the original port */

/* old style stuff that are now replaced */
// PARAMS ((x)) --> (x) /* manually edited */
// get_symbol_end () --> get_symbol_name (&name) /* manually edited */
// assert --> gas_assert
// bfd_section_size (stdoutput, data_section) --> bfd_section_size (data_section)
// same for text_section
// sec == &bfd_und_section --> bfd_is_und_section (sec)
// same for bfd_abs_section

/* back to old original code ...*/


#define BFD_ASSEMBLER 1
#define OBJ_HEADER "obj-plan9.h"

#include "as.h"
#undef NO_RELOC
#include "aout/aout64.h"

#include "obstack.h"

#ifndef BFD_ASSEMBLER
/* in: segT   out: N_TYPE bits */
const short seg_N_TYPE[] =
{
  N_ABS,
  N_TEXT,
  N_DATA,
  N_BSS,
  N_UNDF,			/* unknown */
  N_UNDF,			/* error */
  N_UNDF,			/* expression */
  N_UNDF,			/* debug */
  N_UNDF,			/* ntv */
  N_UNDF,			/* ptv */
  N_REGISTER,			/* register */
};

const segT N_TYPE_seg[N_TYPE + 2] =
{				/* N_TYPE == 0x1E = 32-2 */
  SEG_UNKNOWN,			/* N_UNDF == 0 */
  SEG_GOOF,
  SEG_ABSOLUTE,			/* N_ABS == 2 */
  SEG_GOOF,
  SEG_TEXT,			/* N_TEXT == 4 */
  SEG_GOOF,
  SEG_DATA,			/* N_DATA == 6 */
  SEG_GOOF,
  SEG_BSS,			/* N_BSS == 8 */
  SEG_GOOF,
  SEG_GOOF, SEG_GOOF, SEG_GOOF, SEG_GOOF, SEG_GOOF, SEG_GOOF, SEG_GOOF, SEG_GOOF,
  SEG_GOOF, SEG_GOOF, SEG_GOOF, SEG_GOOF, SEG_GOOF, SEG_GOOF, SEG_GOOF, SEG_GOOF,
  SEG_GOOF, SEG_GOOF, SEG_GOOF, SEG_GOOF,
  SEG_REGISTER,			/* dummy N_REGISTER for regs = 30 */
  SEG_GOOF,
};
#endif

static void obj_plan9_line (int);
static void obj_plan9_weak (int);
static void obj_plan9_type (int);

const pseudo_typeS aout_pseudo_table[] =
{
  {"line", obj_plan9_line, 0},	/* source code line number */
  {"ln", obj_plan9_line, 0},	/* coff line number that we use anyway */

  {"weak", obj_plan9_weak, 0},	/* mark symbol as weak.  */

  {"type", obj_plan9_type, 0},

  /* coff debug pseudos (ignored) */
  {"def", s_ignore, 0},
  {"dim", s_ignore, 0},
  {"endef", s_ignore, 0},
  {"ident", s_ignore, 0},
  {"line", s_ignore, 0},
  {"ln", s_ignore, 0},
  {"scl", s_ignore, 0},
  {"size", s_ignore, 0},
  {"tag", s_ignore, 0},
  {"val", s_ignore, 0},
  {"version", s_ignore, 0},

  {"optim", s_ignore, 0},	/* For sun386i cc (?) */

  /* other stuff */
  {"ABORT", s_abort, 0},

  {NULL, NULL, 0}		/* end sentinel */
};				/* aout_pseudo_table */

#ifdef BFD_ASSEMBLER

void
obj_plan9_frob_symbol (sym, punt)
     symbolS *sym;
     int *punt ATTRIBUTE_UNUSED;
{
  flagword flags;
  asection *sec;
  int desc, type, other;

  flags = symbol_get_bfdsym (sym)->flags;
  desc = aout_symbol (symbol_get_bfdsym (sym))->desc;
  type = aout_symbol (symbol_get_bfdsym (sym))->type;
  other = aout_symbol (symbol_get_bfdsym (sym))->other;
  sec = S_GET_SEGMENT (sym);

  /* Only frob simple symbols this way right now.  */
  if (! (type & ~ (N_TYPE | N_EXT)))
    {
      if (type == (N_UNDF | N_EXT)
	  && bfd_is_abs_section (sec) )
	{
	  sec = bfd_und_section_ptr;
	  S_SET_SEGMENT (sym, sec);
	}

      if ((type & N_TYPE) != N_INDR
	  && (type & N_TYPE) != N_SETA
	  && (type & N_TYPE) != N_SETT
	  && (type & N_TYPE) != N_SETD
	  && (type & N_TYPE) != N_SETB
	  && type != N_WARNING
	  && (bfd_is_abs_section (sec)
	      || bfd_is_und_section (sec) ))
	return;
      if (flags & BSF_EXPORT)
	type |= N_EXT;

      switch (type & N_TYPE)
	{
	case N_SETA:
	case N_SETT:
	case N_SETD:
	case N_SETB:
	  /* Set the debugging flag for constructor symbols so that
	     BFD leaves them alone.  */
	  symbol_get_bfdsym (sym)->flags |= BSF_DEBUGGING;

	  /* You can't put a common symbol in a set.  The way a set
	     element works is that the symbol has a definition and a
	     name, and the linker adds the definition to the set of
	     that name.  That does not work for a common symbol,
	     because the linker can't tell which common symbol the
	     user means.  FIXME: Using as_bad here may be
	     inappropriate, since the user may want to force a
	     particular type without regard to the semantics of sets;
	     on the other hand, we certainly don't want anybody to be
	     mislead into thinking that their code will work.  */
	  if (S_IS_COMMON (sym))
	    as_bad (_("Attempt to put a common symbol into set %s"),
		    S_GET_NAME (sym));
	  /* Similarly, you can't put an undefined symbol in a set.  */
	  else if (! S_IS_DEFINED (sym))
	    as_bad (_("Attempt to put an undefined symbol into set %s"),
		    S_GET_NAME (sym));

	  break;
	case N_INDR:
	  /* Put indirect symbols in the indirect section.  */
	  S_SET_SEGMENT (sym, bfd_ind_section_ptr);
	  symbol_get_bfdsym (sym)->flags |= BSF_INDIRECT;
	  if (type & N_EXT)
	    {
	      symbol_get_bfdsym (sym)->flags |= BSF_EXPORT;
	      symbol_get_bfdsym (sym)->flags &=~ BSF_LOCAL;
	    }
	  break;
	case N_WARNING:
	  /* Mark warning symbols.  */
	  symbol_get_bfdsym (sym)->flags |= BSF_WARNING;
	  break;
	}
    }
  else
    {
      symbol_get_bfdsym (sym)->flags |= BSF_DEBUGGING;
    }

  aout_symbol (symbol_get_bfdsym (sym))->type = type;

  /* Double check weak symbols.  */
  if (S_IS_WEAK (sym))
    {
      if (S_IS_COMMON (sym))
	as_bad (_("Symbol `%s' can not be both weak and common"),
		S_GET_NAME (sym));
    }
}

void
obj_plan9_frob_file ()
{
  /* Relocation processing may require knowing the VMAs of the sections.
     Since writing to a section will cause the BFD back end to compute the
     VMAs, fake it out here....  */
  bfd_byte b = 0;
  bfd_boolean x = TRUE;
  if (bfd_section_size (text_section) != 0)
    {
      x = bfd_set_section_contents (stdoutput, text_section, &b, (file_ptr) 0,
				    (bfd_size_type) 1);
    }
  else if (bfd_section_size (data_section) != 0)
    {
      x = bfd_set_section_contents (stdoutput, data_section, &b, (file_ptr) 0,
				    (bfd_size_type) 1);
    }
  gas_assert (x == TRUE);
}

#else /* ! BFD_ASSEMBLER */

/* Relocation.  */

/*
 *		emit_relocations()
 *
 * Crawl along a fixS chain. Emit the segment's relocations.
 */
void
obj_emit_relocations (where, fixP, segment_address_in_file)
     char **where;
     fixS *fixP;		/* Fixup chain for this segment.  */
     relax_addressT segment_address_in_file;
{
  for (; fixP; fixP = fixP->fx_next)
    if (fixP->fx_done == 0)
      {
	symbolS *sym;

	sym = fixP->fx_addsy;
	while (sym->sy_value.X_op == O_symbol
	       && (! S_IS_DEFINED (sym) || S_IS_COMMON (sym)))
	  sym = sym->sy_value.X_add_symbol;
	fixP->fx_addsy = sym;

	if (! sym->sy_resolved && ! S_IS_DEFINED (sym))
	  {
	    char *file;
	    unsigned int line;

	    if (expr_symbol_where (sym, &file, &line))
	      as_bad_where (file, line, _("unresolved relocation"));
	    else
	      as_bad (_("bad relocation: symbol `%s' not in symbol table"),
		      S_GET_NAME (sym));
	  }

	tc_plan9_fix_to_chars (*where, fixP, segment_address_in_file);
	*where += md_reloc_size;
      }
}

void
tc_plan9_fix_to_chars (where, fixP, segment_address_in_file)
     char *where;
     fixS *fixP;
     relax_addressT segment_address_in_file;
{
  /* In:  length of relocation (or of address) in chars: 1, 2 or 4.
     Out: GNU LD relocation length code: 0, 1, or 2.  */

  static const unsigned char nbytes_r_length[] = { 42, 0, 1, 42, 2 };
  long r_symbolnum;

  know (fixP->fx_addsy != NULL);

  number_to_chars_bigendian (where,
		      (valueT) (fixP->fx_frag->fr_address
				+ fixP->fx_where - segment_address_in_file),
		      4);

  r_symbolnum = (S_IS_DEFINED (fixP->fx_addsy)
		 ? S_GET_TYPE (fixP->fx_addsy)
		 : fixP->fx_addsy->sy_number);

  where[4] = (r_symbolnum >> 16) & 0x0ff;
  where[5] = (r_symbolnum >> 8) & 0x0ff;
  where[6] = r_symbolnum & 0x0ff;
  where[7] = ((((!S_IS_DEFINED (fixP->fx_addsy)) << 4) & 0x10)
	      | ((nbytes_r_length[fixP->fx_size] << 5) & 0x60)
	      | ((fixP->fx_pcrel << 7) & 0x80));
}

#ifndef obj_header_append
/* Aout file generation & utilities */
void
obj_header_append (where, headers)
     char **where;
     object_headers *headers;
{
  tc_headers_hook (headers);

  number_to_chars_bigendian (*where, headers->header.a_info, sizeof (headers->header.a_info));
  *where += sizeof (headers->header.a_info);
  number_to_chars_bigendian (*where, headers->header.a_text, sizeof (headers->header.a_text));
  *where += sizeof (headers->header.a_text);
  number_to_chars_bigendian (*where, headers->header.a_data, sizeof (headers->header.a_data));
  *where += sizeof (headers->header.a_data);
  number_to_chars_bigendian (*where, headers->header.a_bss, sizeof (headers->header.a_bss));
  *where += sizeof (headers->header.a_bss);
  number_to_chars_bigendian (*where, headers->header.a_syms, sizeof (headers->header.a_syms));
  *where += sizeof (headers->header.a_syms);
  number_to_chars_bigendian (*where, headers->header.a_entry, sizeof (headers->header.a_entry));
  *where += sizeof (headers->header.a_entry);
  number_to_chars_bigendian (*where, headers->header.a_trsize, sizeof (headers->header.a_trsize));
  *where += sizeof (headers->header.a_trsize);
  number_to_chars_bigendian (*where, headers->header.a_drsize, sizeof (headers->header.a_drsize));
  *where += sizeof (headers->header.a_drsize);

}
#endif /* ! defined (obj_header_append) */

void
obj_emit_symbols (where, symbol_rootP)
     char **where;
     symbolS *symbol_rootP;
{
  symbolS *symbolP;
  obj_symbol_type osym;

  /* Emit all symbols left in the symbol chain.  */
  for (symbolP = symbol_rootP; symbolP; symbolP = symbol_next (symbolP))
    {
      /* Any symbol still undefined and is not a dbg symbol is made N_EXT.  */
      if (!S_IS_DEBUG (symbolP) && !S_IS_DEFINED (symbolP))
	S_SET_EXTERNAL (symbolP);

      /* Adjust the type of a weak symbol.  */
      if (S_GET_WEAK (symbolP))
	{
	  switch (S_GET_TYPE (symbolP))
	    {
	    case N_UNDF: S_SET_TYPE (symbolP, N_WEAKU); break;
	    case N_ABS:	 S_SET_TYPE (symbolP, N_WEAKA); break;
	    case N_TEXT: S_SET_TYPE (symbolP, N_WEAKT); break;
	    case N_DATA: S_SET_TYPE (symbolP, N_WEAKD); break;
	    case N_BSS:  S_SET_TYPE (symbolP, N_WEAKB); break;
	    default: as_bad (_("%s: bad type for weak symbol"), S_GET_NAME (symbolP)); break;
	    }
	}

      osym = symbolP->sy_symbol;
      osym.n_un.n_strx = symbolP->sy_name_offset;
      number_to_chars_bigendian ((char *) &(osym.n_un.n_strx), osym.n_un.n_strx, sizeof (osym.n_un.n_strx));
      number_to_chars_bigendian ((char *) &(osym.n_desc), S_GET_DESC (symbolP), sizeof (osym.n_desc));
      number_to_chars_bigendian ((char *) &(osym.n_value), S_GET_VALUE (symbolP), sizeof (osym.n_value));

      append (where, (char *) &osym, sizeof (osym));
    }
}

#endif /* ! BFD_ASSEMBLER */

static void
obj_plan9_line (ignore)
     int ignore ATTRIBUTE_UNUSED;
{
  /* Assume delimiter is part of expression.
     BSD4.2 as fails with delightful bug, so we
     are not being incompatible here.  */
  new_logical_line ((char *) NULL, (int) (get_absolute_expression ()));
  demand_empty_rest_of_line ();
}				/* obj_plan9_line() */

/* Handle .weak.  This is a GNU extension.  */

static void
obj_plan9_weak (ignore)
     int ignore ATTRIBUTE_UNUSED;
{
  char *name;
  int c;
  symbolS *symbolP;

  do
    {
      name = input_line_pointer;
      c = get_symbol_name (&name);
      symbolP = symbol_find_or_make (name);
      *input_line_pointer = c;
      SKIP_WHITESPACE ();
      S_SET_WEAK (symbolP);
      if (c == ',')
	{
	  input_line_pointer++;
	  SKIP_WHITESPACE ();
	  if (*input_line_pointer == '\n')
	    c = '\n';
	}
    }
  while (c == ',');
  demand_empty_rest_of_line ();
}

/* Handle .type.  On {Net,Open}BSD, this is used to set the n_other field,
   which is then apparently used when doing dynamic linking.  Older
   versions of gas ignored the .type pseudo-op, so we also ignore it if
   we can't parse it.  */

static void
obj_plan9_type (ignore)
     int ignore ATTRIBUTE_UNUSED;
{
  char *name;
  int c;
  symbolS *sym;

  name = input_line_pointer;
  c = get_symbol_name (&name);
  sym = symbol_find_or_make (name);
  *input_line_pointer = c;
  SKIP_WHITESPACE ();
  if (*input_line_pointer == ',')
    {
      ++input_line_pointer;
      SKIP_WHITESPACE ();
      if (*input_line_pointer == '@')
	{
	  ++input_line_pointer;
	  if (strncmp (input_line_pointer, "object", 6) == 0)
#ifdef BFD_ASSEMBLER
	    aout_symbol (symbol_get_bfdsym (sym))->other = 1;
#else
	  S_SET_OTHER (sym, 1);
#endif
	  else if (strncmp (input_line_pointer, "function", 8) == 0)
#ifdef BFD_ASSEMBLER
	    aout_symbol (symbol_get_bfdsym (sym))->other = 2;
#else
	  S_SET_OTHER (sym, 2);
#endif
	}
    }

  /* Ignore everything else on the line.  */
  s_ignore (0);
}

#ifndef BFD_ASSEMBLER

void
obj_crawl_symbol_chain (headers)
     object_headers *headers;
{
  symbolS *symbolP;
  symbolS **symbolPP;
  int symbol_number = 0;

  tc_crawl_symbol_chain (headers);

  symbolPP = &symbol_rootP;	/*->last symbol chain link.  */
  while ((symbolP = *symbolPP) != NULL)
    {
      if (symbolP->sy_mri_common)
	{
	  if (S_IS_EXTERNAL (symbolP))
	    as_bad (_("%s: global symbols not supported in common sections"),
		    S_GET_NAME (symbolP));
	  *symbolPP = symbol_next (symbolP);
	  continue;
	}

      if (flag_readonly_data_in_text && (S_GET_SEGMENT (symbolP) == SEG_DATA))
	{
	  S_SET_SEGMENT (symbolP, SEG_TEXT);
	}			/* if pusing data into text */

      resolve_symbol_value (symbolP, 1);

      /* These are causing trouble, so delete them until we have the chance to investigate further */
      if (symbolP->sy_symbol.n_type == 0x20)
	{
	  *symbolPP = symbol_next (symbolP);
	  continue;
	}

      /* Skip symbols which were equated to undefined or common
	 symbols.  */
      if (symbolP->sy_value.X_op == O_symbol
	  && (! S_IS_DEFINED (symbolP) || S_IS_COMMON (symbolP)))
	{
	  *symbolPP = symbol_next (symbolP);
	  continue;
	}

      /* OK, here is how we decide which symbols go out into the brave
	 new symtab.  Symbols that do are:

	 * symbols with no name (stabd's?)
	 * symbols with debug info in their N_TYPE

	 Symbols that don't are:
	 * symbols that are registers
	 * symbols with \1 as their 3rd character (numeric labels)
	 * "local labels" as defined by S_LOCAL_NAME(name) if the -L
	 switch was passed to gas.

	 All other symbols are output.  We complain if a deleted
	 symbol was marked external.  */

      if (!S_IS_REGISTER (symbolP)
	  && (!S_GET_NAME (symbolP)
	      || S_IS_DEBUG (symbolP)
	      || !S_IS_DEFINED (symbolP)
	      || S_IS_EXTERNAL (symbolP)
	      || (S_GET_NAME (symbolP)[0] != '\001'
		  && (flag_keep_locals || !S_LOCAL_NAME (symbolP)))))
	{
	  symbolP->sy_number = symbol_number++;

	  /* The + 1 after strlen account for the \0 at the
			   end of each string */
	  if (!S_IS_STABD (symbolP))
	    {
	      /* Ordinary case.  */
	      symbolP->sy_name_offset = string_byte_count;
	      string_byte_count += strlen (S_GET_NAME (symbolP)) + 1;
	    }
	  else			/* .Stabd case.  */
	    symbolP->sy_name_offset = 0;
	  symbolPP = &symbolP->sy_next;
	}
      else
	{
	  if (S_IS_EXTERNAL (symbolP) || !S_IS_DEFINED (symbolP))
	    /* This warning should never get triggered any more.
	       Well, maybe if you're doing twisted things with
	       register names...  */
	    {
	      as_bad (_("Local symbol %s never defined."), decode_local_label_name (S_GET_NAME (symbolP)));
	    }			/* oops.  */

	  /* Unhook it from the chain */
	  *symbolPP = symbol_next (symbolP);
	}			/* if this symbol should be in the output */
    }				/* for each symbol */

  H_SET_SYMBOL_TABLE_SIZE (headers, symbol_number);
}

/*
 * Find strings by crawling along symbol table chain.
 */

void
obj_emit_strings (where)
     char **where;
{
  symbolS *symbolP;

  /* Gotta do md_ byte-ordering stuff for string_byte_count first - KWK */
  number_to_chars_bigendian (*where, string_byte_count, sizeof (string_byte_count));
  *where += sizeof (string_byte_count);

  for (symbolP = symbol_rootP; symbolP; symbolP = symbol_next (symbolP))
    {
      if (S_GET_NAME (symbolP))
	append (&next_object_file_charP, S_GET_NAME (symbolP),
		(unsigned long) (strlen (S_GET_NAME (symbolP)) + 1));
    }				/* walk symbol chain */
}

#ifndef AOUT_VERSION
#define AOUT_VERSION 0
#endif

void
obj_pre_write_hook (headers)
     object_headers *headers;
{
  H_SET_DYNAMIC (headers, 0);
  H_SET_VERSION (headers, AOUT_VERSION);
  H_SET_MACHTYPE (headers, AOUT_MACHTYPE);
//  tc_plan9_pre_write_hook (headers);
}

void
s_sect ()
{
  /* Strip out the section name */
  char *section_name;
  char *section_name_end;
  char c;

  unsigned int len;
  unsigned int exp;
  char *save;

  section_name = input_line_pointer;
  c = get_symbol_name (&name);
  section_name_end = input_line_pointer;

  len = section_name_end - section_name;
  input_line_pointer++;
  save = input_line_pointer;

  SKIP_WHITESPACE ();
  if (c == ',')
    {
      exp = get_absolute_expression ();
    }
  else if (*input_line_pointer == ',')
    {
      input_line_pointer++;
      exp = get_absolute_expression ();
    }
  else
    {
      input_line_pointer = save;
      exp = 0;
    }
  if (exp >= 1000)
    {
      as_bad (_("subsegment index too high"));
    }

  if (strcmp (section_name, ".text") == 0)
    {
      subseg_set (SEG_TEXT, (subsegT) exp);
    }

  if (strcmp (section_name, ".data") == 0)
    {
      if (flag_readonly_data_in_text)
	subseg_set (SEG_TEXT, (subsegT) exp + 1000);
      else
	subseg_set (SEG_DATA, (subsegT) exp);
    }

  *section_name_end = c;
}

#endif /* ! BFD_ASSEMBLER */

#ifdef BFD_ASSEMBLER

/* Support for an AOUT emulation.  */

static void plan9_pop_insert (void);
static int obj_plan9_s_get_other (symbolS *);
static void obj_plan9_s_set_other (symbolS *, int);
static int obj_plan9_s_get_desc (symbolS *);
static void obj_plan9_s_set_desc (symbolS *, int);
static int obj_plan9_s_get_type (symbolS *);
static void obj_plan9_s_set_type (symbolS *, int);
static int obj_plan9_separate_stab_sections (void);
static int obj_plan9_sec_sym_ok_for_reloc (asection *);
static void obj_plan9_process_stab (segT, int, const char *, int, int, int);

static void
plan9_pop_insert ()
{
  pop_insert (aout_pseudo_table);
}

static int
obj_plan9_s_get_other (sym)
     symbolS *sym;
{
  return aout_symbol (symbol_get_bfdsym (sym))->other;
}

static void
obj_plan9_s_set_other (sym, o)
     symbolS *sym;
     int o;
{
  aout_symbol (symbol_get_bfdsym (sym))->other = o;
}

static int
obj_plan9_sec_sym_ok_for_reloc (sec)
     asection *sec ATTRIBUTE_UNUSED;
{
  return obj_sec_sym_ok_for_reloc (sec);
}

static void
obj_plan9_process_stab (seg, w, s, t, o, d)
     segT seg ATTRIBUTE_UNUSED;
     int w;
     const char *s;
     int t;
     int o;
     int d;
{
  aout_process_stab (w, s, t, o, d);
}

static int
obj_plan9_s_get_desc (sym)
     symbolS *sym;
{
  return aout_symbol (symbol_get_bfdsym (sym))->desc;
}

static void
obj_plan9_s_set_desc (sym, d)
     symbolS *sym;
     int d;
{
  aout_symbol (symbol_get_bfdsym (sym))->desc = d;
}

static int
obj_plan9_s_get_type (sym)
     symbolS *sym;
{
  return aout_symbol (symbol_get_bfdsym (sym))->type;
}

static void
obj_plan9_s_set_type (sym, t)
     symbolS *sym;
     int t;
{
  aout_symbol (symbol_get_bfdsym (sym))->type = t;
}

static int
obj_plan9_separate_stab_sections ()
{
  return 0;
}

/* When changed, make sure these table entries match the single-format
   definitions in obj-plan9.h.  */
const struct format_ops plan9_format_ops =
{
  bfd_target_plan9_flavour,
  1,	/* dfl_leading_underscore */
  0,	/* emit_section_symbols */
  0,	/* begin */
  0,	/* app_file */
  obj_plan9_frob_symbol,
  obj_plan9_frob_file,
  0,	/* frob_file_before_adjust */
  0,	/* frob_file_after_relocs */
  0,	/* s_get_size */
  0,	/* s_set_size */
  0,	/* s_get_align */
  0,	/* s_set_align */
  obj_plan9_s_get_other,
  obj_plan9_s_set_other,
  obj_plan9_s_get_desc,
  obj_plan9_s_set_desc,
  obj_plan9_s_get_type,
  obj_plan9_s_set_type,
  0,	/* copy_symbol_attributes */
  0,	/* generate_asm_lineno */
  obj_plan9_process_stab,
  obj_plan9_separate_stab_sections,
  0,	/* init_stab_section */
  obj_plan9_sec_sym_ok_for_reloc,
  plan9_pop_insert,
  0,	/* ecoff_set_ext */
  0,	/* read_begin_hook */
  0 	/* symbol_new_hook */
};
#endif /* BFD_ASSEMBLER */
