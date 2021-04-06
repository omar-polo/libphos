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

/*
 * TODOs:
 * - distinguish between an empty component and a undefined one
 * - ...
 */

#include "phos.h"

#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static const char	*sub_ip_literal(const char*);
static const char	*sub_host_dummy(const char*);
static const char	*sub_pchar(const char*);
static const char	*sub_segment(const char*);
static const char	*sub_segment_nz(const char*);
static const char	*sub_segment_nz_nc(const char*);
static const char	*sub_path_common(const char*);

static const char	*parse_scheme(const char*, struct phos_uri*);
static const char	*parse_host(const char*, struct phos_uri*);
static const char	*parse_port(const char*, struct phos_uri*);
static const char	*parse_authority(const char*, struct phos_uri*);
static const char	*parse_path_abempty(const char*, struct phos_uri*);
static const char	*parse_path_absolute(const char*, struct phos_uri*);
static const char	*parse_path_noscheme(const char*, struct phos_uri*);
static const char	*parse_path_rootless(const char*, struct phos_uri*);
static const char	*parse_path_empty(const char*, struct phos_uri*);
static const char	*parse_hier_part(const char*, struct phos_uri*);
static const char	*parse_query(const char*, struct phos_uri*);
static const char	*parse_fragment(const char*, struct phos_uri*);
static const char	*parse_uri(const char*, struct phos_uri*);
static const char	*parse_relative_part(const char*, struct phos_uri*);
static const char	*parse_relative_ref(const char*, struct phos_uri*);
static const char	*parse_uri_reference(const char*, struct phos_uri*);

static int		 path_elide_dotdot(char*, char*, int);
static int		 gmid_path_clean(char *path);


/* common defs */

static inline int
gen_delims(int c)
{
	return c == ':'
		|| c == '/'
		|| c == '?'
		|| c == '#'
		|| c == '['
		|| c == ']'
		|| c == '@';
}

static inline int
sub_delims(int c)
{
	return c == '!'
		|| c == '$'
		|| c == '&'
		|| c == '\''
		|| c == '('
		|| c == ')'
		|| c == '*'
		|| c == '+'
		|| c == ','
		|| c == ';'
		|| c == '=';
}

static inline int
reserved(int c)
{
	return gen_delims(c) || sub_delims(c);
}

static inline int
unreserved(int c)
{
	return isalpha(c)
		|| isdigit(c)
		|| c == '-'
		|| c == '.'
		|| c == '_'
		|| c == '~';
}


/* subs */

/*
 * IP-literal = "[" ( IPv6address / IPvFuture ) "]"
 *
 * in reality, we parse [.*]
 */
static const char *
sub_ip_literal(const char *s)
{
	if (*s != '[')
		return NULL;

	while (*s != '\0' && *s != ']')
		s++;

	if (*s == '\0')
		return NULL;
	return ++s;
}

/*
 * parse everything until : or / (or \0).
 * NB: empty hosts are technically valid!
 */
static const char *
sub_host_dummy(const char *s)
{
	while (*s != '\0' && *s != ':' && *s != '/')
		s++;
	return s;
}

/*
 * pchar = unreserved / pct-encoded / sub-delims / ":" / "@"
 */
static const char *
sub_pchar(const char *s)
{
	if (*s == '\0')
		return NULL;

	if (unreserved(*s))
		return ++s;

	if (*s == '%') {
		if (isxdigit(s[1]) && isxdigit(s[2]))
			return s + 3;
	}

	if (sub_delims(*s))
		return ++s;

	if (*s == ':' || *s == '@')
		return ++s;

	return NULL;
}

/*
 * segment = *pchar
 */
static const char *
sub_segment(const char *s)
{
	const char *t;

	while ((t = sub_pchar(s)) != NULL)
		s = t;
	return s;
}

/* segment-nz = 1*pchar */
static const char *
sub_segment_nz(const char *s)
{
	if ((s = sub_pchar(s)) == NULL)
		return NULL;
	return sub_segment(s);
}

/*
 * segment-nz-nc = 1*( unreserved / pct-encoded / sub-delims / "@" )
 *
 * so, 1*pchar excluding ":"
 */
static const char *
sub_segment_nz_nc(const char *s)
{
	const char *t;

	if (*s == ':')
		return NULL;

        while (*s != ':' && (t = sub_pchar(s)) != NULL)
		s = t;
	return s;
}

/* *( "/" segment ) */
static const char *
sub_path_common(const char *s)
{
	for (;;) {
		if (*s != '/')
			return s;
		s++;
		s = sub_segment(s);
	}
}


/* parse fns */

/*
 * scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
 */
static const char *
parse_scheme(const char *s, struct phos_uri *parsed)
{
	const char *start = s;

	if (!isalpha(*s))
		return NULL;

	while (*s != '\0') {
		if (isalpha(*s) ||
		    isdigit(*s) ||
		    *s == '+' ||
		    *s == '-' ||
		    *s == '.')
			s++;
		else
			break;
	}

	if (*s == '\0')
                return NULL;

        if (s - start >= sizeof(parsed->scheme))
		return NULL;

	memcpy(parsed->scheme, start, s - start);
	return s;
}

/*
 * host = IP-literal / IPv4address / reg-name
 *
 * rules IPv4address and reg-name are relaxed into parse_host_dummy.
 */
static const char *
parse_host(const char *s, struct phos_uri *parsed)
{
	const char *t;

	if ((t = sub_ip_literal(s)) != NULL ||
	    (t = sub_host_dummy(s)) != NULL) {
		if (t - s >= sizeof(parsed->scheme))
			return NULL;
		memcpy(parsed->host, s, t - s);
		return t;
	}

	return NULL;
}

/*
 * port = *digit
 */
static const char *
parse_port(const char *s, struct phos_uri *parsed)
{
	const char *errstr, *start = s;

	while (isdigit(*s))
		s++;

	if (s == start)
		return NULL;

	if (s - start >= sizeof(parsed->port))
		return NULL;

	memcpy(parsed->port, start, s - start);

        parsed->dec_port = strtonum(parsed->port, 0, 65535, &errstr);
	if (errstr != NULL)
		return NULL;

	return s;
}

/*
 * authority = host [ ":" port ]
 * (yep, blatantly ignore the userinfo stuff -- not relevant for Gemini)
 */
static const char *
parse_authority(const char *s, struct phos_uri *parsed)
{
	if ((s = parse_host(s, parsed)) == NULL)
		return NULL;

	if (*s == ':') {
		s++;
		return parse_port(s, parsed);
	}

	return s;
}

static inline const char *
set_path(const char *start, const char *end, struct phos_uri *parsed)
{
	if (end == NULL)
		return NULL;
	if (end - start >= sizeof(parsed->path))
		return NULL;
	memcpy(parsed->path, start, end - start);
	return end;
}

/*
 * path-abempty = *( "/" segment )
 */
static const char *
parse_path_abempty(const char *s, struct phos_uri *parsed)
{
	const char *t;

	t = sub_path_common(s);
	return set_path(s, t, parsed);
}

/*
 * path-absolute = "/" [ segment-nz *( "/" segment ) ]
 */
static const char *
parse_path_absolute(const char *s, struct phos_uri *parsed)
{
	const char *t, *start = s;

	if (*s != '/')
		return NULL;

	s++;
	if ((t = sub_segment_nz(s)) == NULL)
		return set_path(start, s, parsed);

	s = sub_path_common(t);
	return set_path(start, s, parsed);
}

/*
 * path-noscheme = segment-nz-nc *( "/" segment )
 */
static const char *
parse_path_noscheme(const char *s, struct phos_uri *parsed)
{
	const char *start = s;

	if ((s = sub_segment_nz_nc(s)) == NULL)
		return NULL;
	s = sub_path_common(s);
	return set_path(start, s, parsed);
}

/*
 * path-rootless = segment-nz *( "/" segment )
 */
static const char *
parse_path_rootless(const char *s, struct phos_uri *parsed)
{
	const char *start = s;

	if ((s = sub_segment_nz(s)) == NULL)
		return NULL;
	s = sub_path_common(s);
	return set_path(start, s, parsed);
}

/*
 * path-empty = 0<pchar>
 */
static const char *
parse_path_empty(const char *s, struct phos_uri *parsed)
{
	return s;
}

/*
 * hier-part = "//" authority path-abempty
 *           / path-absolute
 *           / path-rootless
 *           / path-empty
 */
static const char *
parse_hier_part(const char *s, struct phos_uri *parsed)
{
	const char *t;

	if (s[0] == '/' && s[1] == '/') {
		s += 2;
		if ((s = parse_authority(s, parsed)) == NULL)
			return NULL;
		return parse_path_abempty(s, parsed);
	}

	if ((t = parse_path_absolute(s, parsed)) != NULL)
		return t;

	if ((t = parse_path_rootless(s, parsed)) != NULL)
		return t;

	return parse_path_empty(s, parsed);
}

/*
 * query = *( pchar / "/" / "?" )
 */
static const char *
parse_query(const char *s, struct phos_uri *parsed)
{
	const char *t, *start = s;

	while (*s != '\0') {
		if (*s == '/' || *s == '?') {
			s++;
			continue;
		}

		if ((t = sub_pchar(s)) == NULL)
                        break;
		s = t;
	}

	if (s - start >= sizeof(parsed->query))
		return NULL;

	memcpy(parsed->query, start, s - start);
	return s;
}

/*
 * fragment = *( pchar / "/" / "?" )
 */
static const char *
parse_fragment(const char *s, struct phos_uri *parsed)
{
	const char *start = s;

	while (*s != '\0' &&
	    (*s == '/' || *s == '?' || (s = sub_pchar(s)) != NULL)) {
		s++;
	}

	if (s == NULL)
		return NULL;

	if (s - start >= sizeof(parsed->fragment))
		return NULL;

	memcpy(parsed->fragment, start, s - start);
	return s;
}

/*
 * URI = scheme ":" hier-part [ "?" query ] [ "#" fragment ]
 */
static const char *
parse_uri(const char *s, struct phos_uri *parsed)
{
	if ((s = parse_scheme(s, parsed)) == NULL)
		return NULL;

	if (*s != ':')
		return NULL;

	s++;
	if ((s = parse_hier_part(s, parsed)) == NULL)
		return NULL;

	if (*s == '?') {
		s++;
		if ((s = parse_query(s, parsed)) == NULL)
			return NULL;
	}

	if (*s == '#') {
		s++;
		if ((s = parse_fragment(s, parsed)) == NULL)
			return NULL;
	}

	return s;
}

/*
 * relative-part = "//" authority path-abempty
 *               / path-absolute
 *               / path-noscheme
 *               / path-empty
 */
static const char *
parse_relative_part(const char *s, struct phos_uri *parsed)
{
	const char *t;

	if (s[0] == '/' && s[1] == '/') {
		s += 2;
		if ((s = parse_authority(s, parsed)) == NULL)
			return NULL;
		return parse_path_abempty(s, parsed);
	}

	if ((t = parse_path_absolute(s, parsed)) != NULL)
		return t;

	if ((t = parse_path_noscheme(s, parsed)) != NULL)
		return t;

	return parse_path_empty(s, parsed);
}

/*
 * relative-ref = relative-part [ "?" query ] [ "#" fragment ]
 */
static const char *
parse_relative_ref(const char *s, struct phos_uri *parsed)
{
	if ((s = parse_relative_part(s, parsed)) == NULL)
		return NULL;

	if (*s == '?') {
		s++;
		if ((s = parse_query(s, parsed)) == NULL)
			return NULL;
	}

	if (*s == '#') {
		s++;
		if ((s = parse_fragment(s, parsed)) == NULL)
			return NULL;
	}

	return s;
}

/*
 * URI-reference = URI / relative-ref
 */
static const char *
parse_uri_reference(const char *s, struct phos_uri *parsed)
{
	const char *t;

	if ((t = parse_uri(s, parsed)) != NULL)
		return t;
	memset(parsed, 0, sizeof(*parsed));
	return parse_relative_ref(s, parsed);
}


/*
 * absolute-URI = scheme ":" hier-part [ "?" query ]
 */
static const char *
parse_absolute_uri(const char *s, struct phos_uri *parsed)
{
	if ((s = parse_scheme(s, parsed)) == NULL)
		return NULL;

	if (*s != ':')
		return NULL;

	s++;
	if ((s = parse_hier_part(s, parsed)) == NULL)
		return NULL;

	if (*s == '?') {
		s++;
		if ((s = parse_query(s, parsed)) == NULL)
			return NULL;
	}

	return s;
}


/* normalizing fns */

/* Routine for path_clean.  Elide the pointed .. with the preceding
 * element.  Return 0 if it's not possible.  incr is the length of
 * the increment, 3 for ../ and 2 for .. */
static int
path_elide_dotdot(char *path, char *i, int incr)
{
	char *j;

	if (i == path)
		return 0;
	for (j = i-2; j != path && *j != '/'; j--)
                /* noop */ ;
	if (*j == '/')
		j++;
	i += incr;
	memmove(j, i, strlen(i)+1);
	return 1;
}

/*
 * Use an algorithm similar to the one implemented in go' path.Clean:
 *
 * 1. Replace multiple slashes with a single slash
 * 2. Eliminate each . path name element
 * 3. Eliminate each inner .. along with the non-.. element that precedes it
 * 4. Eliminate trailing .. if possible or error (go would only discard)
 * 5. Eliminate trailing .
 *
 * Unlike path.Clean, this function return the empty string if the
 * original path is equivalent to "/".
 */
static int
gmid_path_clean(char *path)
{
	char *i;

	/* 1. replace multiple slashes with a single one */
	for (i = path; *i; ++i) {
		if (*i == '/' && *(i+1) == '/') {
			memmove(i, i+1, strlen(i)); /* move also the \0 */
			i--;
		}
	}

	/* 2. eliminate each . path name element */
	for (i = path; *i; ++i) {
		if ((i == path || *i == '/') &&
		    *i != '.' && i[1] == '.' && i[2] == '/') {
			/* move also the \0 */
			memmove(i, i+2, strlen(i)-1);
			i--;
		}
	}
	if (!strcmp(path, ".") || !strcmp(path, "/.")) {
		*path = '\0';
		return 1;
	}

	/* 3. eliminate each inner .. along with the preceding non-.. */
	for (i = strstr(path, "../"); i != NULL; i = strstr(path, ".."))
		if (!path_elide_dotdot(path, i, 3))
			return 0;

	/* 4. eliminate trailing ..*/
	if ((i = strstr(path, "..")) != NULL)
		if (!path_elide_dotdot(path, i, 2))
			return 0;

	if ((i = strrchr(path, '/')) != NULL && i[1] == '.' && i[2] == '\0')
		i[1] = '\0';

	return 1;
}

/*
 * RFC3986 suggest a simple and interesting path cleaning algorithm.
 * They call it "Remove Dot Segments", see section 5.2.4.
 *
 * For the time being, instead of that I'm reusing the path_clean
 * routine from gmid IRI implementation.  It's akin to the go'
 * path.Clean algorithm, and should be equal to the one proposed in
 * the RFC, at least in the more common scenarious.
 */
static inline int
path_clean(struct phos_uri *uri)
{
	return gmid_path_clean(uri->path);
}

/*
 * see RFC3986 5.3.3 "Merge Paths".
 */
static inline int
merge_path(struct phos_uri *ret, const struct phos_uri *base,
    const struct phos_uri *ref)
{
	const char *s;
	size_t len;

	len = sizeof(ret->path);

	s = strrchr(base->path, '/');
	if ((*base->host != '\0' && *base->path == '\0') || s == NULL) {
		strlcpy(ret->path, "/", len);
	} else {
		/* copy the / too */
                memcpy(ret->path, base->path, s - base->path + 1);
	}

	return strlcat(ret->path, ref->path, len) < len;
}


/* public interface */

int
phos_parse_absolute_uri(const char *s, struct phos_uri *uri)
{
	memset(uri, 0, sizeof(*uri));

	if ((s = parse_absolute_uri(s, uri)) == NULL)
		return 0;
	if (*s != '\0')
		return 0;
	return path_clean(uri);
}

int
phos_parse_uri_reference(const char *s, struct phos_uri *uri)
{
	memset(uri, 0, sizeof(*uri));

	if ((s = parse_uri_reference(s, uri)) == NULL)
		return 0;
	if (*s != '\0')
		return 0;
	return path_clean(uri);
}

/*
 * Implementation of the "transform references" algorithm from
 * RFC3986, see 5.2.2.
 *
 * We expect base and ref to be URIs constructed by this library
 * (because we emit only normalized URIs).
 *
 * ATM this is marked as private because:
 * - let's say the URI is "."
 * - one calls phos_parse_uri_references
 * - it exists with success, but the path becomes ""
 * - this routine does the right thing, but the outcome is not what expected.
 *
 * so users for now have to user resolve_uri_from_str, which parses
 * the URI but not normalize it, and then call into us.
 */
static int
phos_resolve_uri_from(const struct phos_uri *base, const struct phos_uri *ref,
    struct phos_uri *ret)
{
	memset(ret, 0, sizeof(*ret));

	if (*ref->scheme != '\0') {
		strlcpy(ret->scheme, ref->scheme, sizeof(ret->scheme));
		strlcpy(ret->host, ref->host, sizeof(ret->host));
		strlcpy(ret->port, ref->port, sizeof(ret->port));
		ret->dec_port = ret->dec_port;
		strlcpy(ret->path, ref->path, sizeof(ret->path));
		strlcpy(ret->query, ref->query, sizeof(ret->query));
	} else {
		if (*ref->host != '\0') {
			strlcpy(ret->host, ref->host, sizeof(ret->host));
			strlcpy(ret->port, ref->port, sizeof(ret->port));
			ret->dec_port = ret->dec_port;
			strlcpy(ret->path, ref->path, sizeof(ret->path));
			strlcpy(ret->query, ref->query, sizeof(ret->query));
		} else {
			if (*ref->path == '\0') {
				strlcpy(ret->path, base->path, sizeof(ret->path));
				if (*ref->query != '\0')
					strlcpy(ret->query, ref->query, sizeof(ret->query));
				else
					strlcpy(ret->query, base->query, sizeof(ret->query));
			} else {
				if (*ref->path == '/')
					strlcpy(ret->path, ref->path, sizeof(ret->path));
				else {
					if (!merge_path(ret, base, ref))
						return 0;
					if (!path_clean(ret))
						return 0;
				}

				strlcpy(ret->query, ref->query, sizeof(ret->query));
			}

			strlcpy(ret->host, base->host, sizeof(ret->host));
			strlcpy(ret->port, base->port, sizeof(ret->port));
			ret->dec_port = base->dec_port;
		}

		strlcpy(ret->scheme, base->scheme, sizeof(ret->scheme));
	}

	strlcpy(ret->fragment, ref->fragment, sizeof(ret->fragment));

	return 1;
}

int
phos_resolve_uri_from_str(const struct phos_uri *base, const char *refstr,
    struct phos_uri *ret)
{
	struct phos_uri ref;

	memset(&ref, 0, sizeof(ref));

	if ((refstr = parse_uri_reference(refstr, &ref)) == NULL)
		return 0;

	if (*refstr != '\0')
		return 0;

	return phos_resolve_uri_from(base, &ref, ret);
}

int
phos_serialize_uri(const struct phos_uri *uri, char *buf, size_t len)
{
#define CAT(s)					\
	if (strlcat(buf, s, len) >= len)	\
		return 0;

	strlcpy(buf, "", len);

	if (*uri->scheme != '\0') {
                CAT(uri->scheme);
		CAT(":");
	}

	if (*uri->host != '\0') {
		CAT("//");
		CAT(uri->host);
	}

	CAT(uri->path);

	if (*uri->query != '\0') {
		CAT("?");
		CAT(uri->query);
	}

	if (*uri->fragment) {
		CAT("#");
		CAT(uri->fragment);
	}

	return 1;

#undef CAT
}
