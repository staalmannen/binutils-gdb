/* Definitions for frame address handler, for GDB, the GNU debugger.

   Copyright 2003 Free Software Foundation, Inc.

   This file is part of GDB.

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
   Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

#include "defs.h"
#include "frame-base.h"
#include "frame.h"

/* A default frame base implementations.  If it wasn't for the old
   DEPRECATED_FRAME_LOCALS_ADDRESS and DEPRECATED_FRAME_ARGS_ADDRESS,
   these could be combined into a single function.  All architectures
   really need to override this.  */

static CORE_ADDR
default_frame_base_address (struct frame_info *next_frame, void **this_cache)
{
  struct frame_info *this_frame = get_prev_frame (next_frame);
  return get_frame_base (this_frame); /* sigh! */
}

static CORE_ADDR
default_frame_locals_address (struct frame_info *next_frame, void **this_cache)
{
  if (DEPRECATED_FRAME_LOCALS_ADDRESS_P ())
    {
      /* This is bad.  The computation of per-frame locals address
	 should use a per-frame frame-base.  */
      struct frame_info *this_frame = get_prev_frame (next_frame);
      return DEPRECATED_FRAME_LOCALS_ADDRESS (this_frame);
    }
  return default_frame_base_address (next_frame, this_cache);
}

static CORE_ADDR
default_frame_args_address (struct frame_info *next_frame, void **this_cache)
{
  if (DEPRECATED_FRAME_ARGS_ADDRESS_P ())
    {
      struct frame_info *this_frame = get_prev_frame (next_frame);
      return DEPRECATED_FRAME_ARGS_ADDRESS (this_frame);
    }
  return default_frame_base_address (next_frame, this_cache);
}

const struct frame_base default_frame_base = {
  NULL, /* No parent.  */
  default_frame_base_address,
  default_frame_locals_address,
  default_frame_args_address
};

static struct gdbarch_data *frame_base_data;

struct frame_base_table
{
  frame_base_p_ftype **p;
  const struct frame_base *default_base;
  int nr;
};

static void *
frame_base_init (struct gdbarch *gdbarch)
{
  struct frame_base_table *table = XCALLOC (1, struct frame_base_table);
  table->default_base = &default_frame_base;
  return table;
}

static void
frame_base_free (struct gdbarch *gdbarch, void *data)
{
  struct frame_base_table *table =
    gdbarch_data (gdbarch, frame_base_data);
  xfree (table->p);
  xfree (table);
}

static struct frame_base_table *
frame_base_table (struct gdbarch *gdbarch)
{
  struct frame_base_table *table = gdbarch_data (gdbarch, frame_base_data);
  if (table == NULL)
    {
      /* ULGH, called during architecture initialization.  Patch
         things up.  */
      table = frame_base_init (gdbarch);
      set_gdbarch_data (gdbarch, frame_base_data, table);
    }
  return table;
}

/* Append a predicate to the end of the table.  */
static void
append_predicate (struct frame_base_table *table, frame_base_p_ftype *p)
{
  table->p = xrealloc (table->p, ((table->nr + 1)
				  * sizeof (frame_base_p_ftype *)));
  table->p[table->nr] = p;
  table->nr++;
}

void
frame_base_append_predicate (struct gdbarch *gdbarch,
			     frame_base_p_ftype *p)
{
  struct frame_base_table *table = frame_base_table (gdbarch);
  append_predicate (table, p);
}

void
frame_base_set_default (struct gdbarch *gdbarch,
			const struct frame_base *default_base)
{
  struct frame_base_table *table = frame_base_table (gdbarch);
  table->default_base = default_base;
}

const struct frame_base *
frame_base_find_by_pc (struct gdbarch *gdbarch, CORE_ADDR pc)
{
  int i;
  struct frame_base_table *table = frame_base_table (gdbarch);
  for (i = 0; i < table->nr; i++)
    {
      const struct frame_base *desc = table->p[i] (pc);
      if (desc != NULL)
	return desc;
    }
  return table->default_base;
}

extern initialize_file_ftype _initialize_frame_base; /* -Wmissing-prototypes */

void
_initialize_frame_base (void)
{
  frame_base_data = register_gdbarch_data (frame_base_init,
					   frame_base_free);
}
