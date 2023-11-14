/* Map in a shared object's segments.  Generic version.
   Copyright (C) 1995-2023 Free Software Foundation, Inc.
   Copyright The GNU Toolchain Authors.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <https://www.gnu.org/licenses/>.  */

#include <dl-load.h>
// #include <stdlib.h>
#include <ldsodefs.h>

/* Map a segment and align it properly.  */

static __always_inline ElfW(Addr)
_dl_map_segment (const struct loadcmd *c, ElfW(Addr) mappref,
		 const size_t maplength, int fd)
{
  if (__glibc_likely (c->mapalign <= GLRO(dl_pagesize)))
    return (ElfW(Addr)) __mmap ((void *) mappref, maplength, c->prot,
				MAP_COPY|MAP_FILE, fd, c->mapoff);

  /* If the segment alignment > the page size, allocate enough space to
     ensure that the segment can be properly aligned.  */
  ElfW(Addr) maplen = (maplength >= c->mapalign
		       ? (maplength + c->mapalign)
		       : (2 * c->mapalign));
  ElfW(Addr) map_start = (ElfW(Addr)) __mmap ((void *) mappref, maplen,
					      PROT_NONE,
					      MAP_ANONYMOUS|MAP_PRIVATE,
					      -1, 0);
  if (__glibc_unlikely ((void *) map_start == MAP_FAILED))
    return map_start;

  ElfW(Addr) map_start_aligned = ALIGN_UP (map_start, c->mapalign);
  map_start_aligned = (ElfW(Addr)) __mmap ((void *) map_start_aligned,
					   maplength, c->prot,
					   MAP_COPY|MAP_FILE|MAP_FIXED,
					   fd, c->mapoff);
  if (__glibc_unlikely ((void *) map_start_aligned == MAP_FAILED))
    __munmap ((void *) map_start, maplen);
  else
    {
      /* Unmap the unused regions.  */
      ElfW(Addr) delta = map_start_aligned - map_start;
      if (delta)
	__munmap ((void *) map_start, delta);
      ElfW(Addr) map_end = map_start_aligned + maplength;
      map_end = ALIGN_UP (map_end, GLRO(dl_pagesize));
      delta = map_start + maplen - map_end;
      if (delta)
	__munmap ((void *) map_end, delta);
    }

  return map_start_aligned;
}

/* This implementation assumes (as does the corresponding implementation
   of _dl_unmap_segments, in dl-unmap-segments.h) that shared objects
   are always laid out with all segments contiguous (or with gaps
   between them small enough that it's preferable to reserve all whole
   pages inside the gaps with PROT_NONE mappings rather than permitting
   other use of those parts of the address space).  */

static __always_inline const char *
_dl_map_segments (struct link_map *l, int fd,
                  const ElfW(Ehdr) *header, int type,
                  const struct loadcmd loadcmds[], size_t nloadcmds,
                  const size_t maplength, bool has_holes,
                  struct link_map *loader)
{
#if 1
  #define __dprintf(fmt, ...) do { } while (0)
#else
  #define __dprintf(fmt, ...) do { _dl_error_printf("dlphx: " fmt, ##__VA_ARGS__); } while (0)
#endif
  struct phx_range skip_ranges[64];
  unsigned int phx_len = 64;

  phx_get_skipped(skip_ranges, &phx_len);
  __dprintf("phx_len = %u\n", phx_len);
  __dprintf("link name = %s\n", l->l_name);
  __dprintf("initial link addr = %lx\n", l->l_addr);
  __dprintf("link type is DYN = %d\n", type == ET_DYN);

  const struct saved_link_map *oldmap = phx_get_saved_map();

  const struct loadcmd *c = loadcmds;

  if (oldmap) {
    for (unsigned int i = 0; i < oldmap->count; ++i) {
      if (oldmap->links[i].filename && l->l_name
              && !strcmp(oldmap->links[i].filename, l->l_name)) {
        l->l_map_start = oldmap->links[i].map_start;
        l->l_map_end = l->l_map_start + maplength;
        l->l_addr = l->l_map_start - c->mapstart;
        l->l_contiguous = !has_holes;
        __dprintf("found link name %s, start addr = %lx\n", l->l_name, l->l_map_start);
        goto phx_map;
      }
    }
    __dprintf("skip not found\n");
  }

  if (__glibc_likely (type == ET_DYN))
    {
      /* This is a position-independent shared object.  We can let the
         kernel map it anywhere it likes, but we must have space for all
         the segments in their specified positions relative to the first.
         So we map the first segment without MAP_FIXED, but with its
         extent increased to cover all the segments.  Then we remove
         access from excess portion, and there is known sufficient space
         there to remap from the later segments.

         As a refinement, sometimes we have an address that we would
         prefer to map such objects at; but this is only a preference,
         the OS can do whatever it likes. */
      ElfW(Addr) mappref
        = (ELF_PREFERRED_ADDRESS (loader, maplength, c->mapstart)
           - MAP_BASE_ADDR (l));

      /* Remember which part of the address space this object uses.  */
      l->l_map_start = _dl_map_segment (c, mappref, maplength, fd);
      if (__glibc_unlikely ((void *) l->l_map_start == MAP_FAILED))
        return DL_MAP_SEGMENTS_ERROR_MAP_SEGMENT;

      l->l_map_end = l->l_map_start + maplength;
      l->l_addr = l->l_map_start - c->mapstart;

      if (has_holes)
        {
          /* Change protection on the excess portion to disallow all access;
             the portions we do not remap later will be inaccessible as if
             unallocated.  Then jump into the normal segment-mapping loop to
             handle the portion of the segment past the end of the file
             mapping.  */
	  if (__glibc_unlikely (loadcmds[nloadcmds - 1].mapstart <
				c->mapend))
	    return N_("ELF load command address/offset not page-aligned");
          if (__glibc_unlikely
              (__mprotect ((caddr_t) (l->l_addr + c->mapend),
                           loadcmds[nloadcmds - 1].mapstart - c->mapend,
                           PROT_NONE) < 0))
            return DL_MAP_SEGMENTS_ERROR_MPROTECT;
        }

      l->l_contiguous = 1;

      goto postmap;
    }

  /* Remember which part of the address space this object uses.  */
  l->l_map_start = c->mapstart + l->l_addr;
  l->l_map_end = l->l_map_start + maplength;
  l->l_contiguous = !has_holes;

phx_map:

  while (c < &loadcmds[nloadcmds])
    {
      if (c->mapend > c->mapstart) {
          /* Map the segment contents from the file.  */

        /* if (__mmap ((void *) (l->l_addr + c->mapstart),
                      c->mapend - c->mapstart, c->prot,
                      MAP_FIXED|MAP_COPY|MAP_FILE,
                      fd, c->mapoff)
              == MAP_FAILED) */

        struct phx_range subranges[phx_len + 1];
        size_t subrange_cnt = 0;

        ElfW(Addr) cmd_start = l->l_addr + c->mapstart;
        ElfW(Addr) cmd_end = l->l_addr + c->mapend;

        __dprintf("cmd start = %lx, end=%lx\n", cmd_start, cmd_end);

        // FIXME: non page-aligned subrange
        // TODO: assumption: ranges given by kernel does not overlap

        for (size_t i = 0; i < phx_len; ++i) {
          unsigned long skip_start = skip_ranges[i].start;
          unsigned long skip_end = skip_start + skip_ranges[i].length;
          __dprintf("skip start = %lx, end=%lx\n", skip_start, skip_end);

          /* Skip skip_range with no intersection */
          if (!(cmd_start < skip_end && skip_start < cmd_end)) {
            __dprintf("skip range do not intersect with cmd range\n");
            continue;
          }
          __dprintf("skip range has intersection with cmd range\n");
          /* The intersection start is within the cmd range, then there is a
           * chunk of splitted range that still need to be loaded. */
          if (cmd_start <= skip_start) {
            subranges[subrange_cnt++] =
              (struct phx_range) { cmd_start, skip_start - cmd_start };
            __dprintf("add cut range %lx size %lx\n",
                    subranges[subrange_cnt-1].start, subranges[subrange_cnt-1].length);
          }
          /* Eat the skipped part from the cmd range */
          cmd_start = skip_end;
          __dprintf("update cmd_start to %lx\n", cmd_start);
        }
        /* Add the remaining chunk if exists */
        if (cmd_start < cmd_end)
          subranges[subrange_cnt++] =
            (struct phx_range) { cmd_start, cmd_end - cmd_start };
        __dprintf("add last range %lx size %lx\n",
                subranges[subrange_cnt-1].start, subranges[subrange_cnt-1].length);

        for (size_t i = 0; i < subrange_cnt; ++i) {
          if (__mmap ((void *) (subranges[i].start),
                      subranges[i].length, c->prot,
                      MAP_FIXED|MAP_COPY|MAP_FILE,
                      fd, c->mapoff)
                  == MAP_FAILED)
            return DL_MAP_SEGMENTS_ERROR_MAP_SEGMENT;
        }
      }

    postmap:
      _dl_postprocess_loadcmd (l, header, c);

      if (c->allocend > c->dataend)
        {
          /* Extra zero pages should appear at the end of this segment,
             after the data mapped from the file.   */
          ElfW(Addr) zero, zeroend, zeropage;

          zero = l->l_addr + c->dataend;
          zeroend = l->l_addr + c->allocend;
          zeropage = ((zero + GLRO(dl_pagesize) - 1)
                      & ~(GLRO(dl_pagesize) - 1));

          if (zeroend < zeropage)
            /* All the extra data is in the last page of the segment.
               We can just zero it.  */
            zeropage = zeroend;

          if (zeropage > zero)
            {
              /* Zero the final part of the last page of the segment.  */
              if (__glibc_unlikely ((c->prot & PROT_WRITE) == 0))
                {
                  /* Dag nab it.  */
                  if (__mprotect ((caddr_t) (zero
                                             & ~(GLRO(dl_pagesize) - 1)),
                                  GLRO(dl_pagesize), c->prot|PROT_WRITE) < 0)
                    return DL_MAP_SEGMENTS_ERROR_MPROTECT;
                }
              memset ((void *) zero, '\0', zeropage - zero);
              if (__glibc_unlikely ((c->prot & PROT_WRITE) == 0))
                __mprotect ((caddr_t) (zero & ~(GLRO(dl_pagesize) - 1)),
                            GLRO(dl_pagesize), c->prot);
            }

          if (zeroend > zeropage)
            {
              /* Map the remaining zero pages in from the zero fill FD.  */
              caddr_t mapat;
              mapat = __mmap ((caddr_t) zeropage, zeroend - zeropage,
                              c->prot, MAP_ANON|MAP_PRIVATE|MAP_FIXED,
                              -1, 0);
              if (__glibc_unlikely (mapat == MAP_FAILED))
                return DL_MAP_SEGMENTS_ERROR_MAP_ZERO_FILL;
            }
        }

      ++c;
    }

  /* Notify ELF_PREFERRED_ADDRESS that we have to load this one
     fixed.  */
  ELF_FIXED_ADDRESS (loader, c->mapstart);

  return NULL;
}
#undef __dprintf
