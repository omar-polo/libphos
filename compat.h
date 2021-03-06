/*
 * Copyright (c) 2021 Omar Polo <op@omarpolo.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef COMPAT_H
#define COMPAT_H

#include "config.h"

#include <stddef.h>

#ifndef HAVE_EXPLICIT_BZERO
void		 explicit_bzero(void*, size_t);
#endif

#ifndef HAVE_MEMMEM
void		*memmem(const void*, size_t, const void*, size_t);
#endif

#ifndef HAVE_RECALLOCARRAY
void		*recallocarray(void*, size_t, size_t, size_t);
#endif

#ifndef HAVE_STRLCPY
size_t		 strlcpy(char*, const char*, size_t);
#endif

#ifndef HAVE_STRLCAT
size_t		 strlcat(char*, const char*, size_t);
#endif

#endif /* COMPAT_H */
