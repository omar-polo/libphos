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

#include <phos.h>

#include <stdio.h>
#include <string.h>

#define PASS 0
#define FAIL 1

#define URI(s) s

#define TEST(descr, fail, raw, s, h, po, pa, q, f)			\
        do {								\
		const char *err;					\
		int res;						\
		struct phos_uri uri;					\
		res = do_test(&uri, raw, s, h, po, pa,			\
		    q, f, &err);					\
		if (fail && !res || res)				\
			break;						\
		printf("FAIL: cannot %s\n", descr);			\
		printf("%s: %s\n", raw, err);				\
		printf("\tgot\twanted\n");				\
		printf("scheme:\t%s\t%s\n", uri.scheme, s);		\
		printf("host:\t%s\t%s\n", uri.host, h);			\
		printf("port:\t%s\t%s\n", uri.port, po);		\
		printf("path:\t%s\t%s\n", uri.path, pa);		\
		printf("query:\t%s\t%s\n", uri.query, q);		\
		printf("frag:\t%s\t%s\n", uri.fragment, f);		\
		return 99;						\
	} while(0)

#define fail(reason) { *err = reason; return 0; }

int
do_test(struct phos_uri *uri, const char *rawstr, const char *schema,
    const char *host, const char *port, const char *path,
    const char *query, const char *frag, const char **err)
{
	if (!phos_parse_uri_reference(rawstr, uri))
                fail("couldn't parse the URI");
	if (strcmp(uri->scheme, schema))
                fail("the scheme is not what expected");
	if (strcmp(uri->host, host))
                fail("the host is not what expected");
	if (strcmp(uri->port, port))
                fail("the port is not what expected");
	if (strcmp(uri->path, path))
                fail("the path is not what expected");
	if (strcmp(uri->query, query))
                fail("the query is not what expected");
	if (strcmp(uri->fragment, frag))
                fail("the fragment is not what expected");
	return 1;
}


	/* TEST("absolute URIs with / as path", PASS, */
	/*     "gemini://example.com/", */
	/*     "gemini", "example.com", "", "", "", ""); */

int
main(void)
{
	TEST("absolute URIs with empty path", PASS,
	    URI("gemini://example.com"),
	    "gemini", "example.com", "", "", "", "");

	TEST("absolute URIs with port and empty path", PASS,
	    URI("gemini://example.com:1965"),
	    "gemini", "example.com", "1965", "", "", "");

	TEST("absolute URIs with a non-empty path", PASS,
	    URI("gemini://example.com/foo"),
	    "gemini", "example.com", "", "/foo", "", "");

	TEST("absolute URIs with a non-empty path", PASS,
	    URI("gemini://example.com/foo/bar/baz/"),
	    "gemini", "example.com", "", "/foo/bar/baz/", "", "");

	TEST("absolute URIs with a non-empty path and query", PASS,
	    URI("gemini://example.com/foo/bar/baz/?foo"),
	    "gemini", "example.com", "", "/foo/bar/baz/", "foo", "");

	TEST("absolute URIs with a non-empty path, query and fragment", PASS,
	    URI("gemini://example.com/foo/bar/baz/?foo#quux"),
	    "gemini", "example.com", "", "/foo/bar/baz/", "foo", "quux");

	TEST("relative ref with a non-empty path", PASS,
	    URI("/foo"),
	    "", "", "", "/foo", "", "");

	TEST("relative ref with a non-empty path and query", PASS,
	    URI("/foo?bar"),
	    "", "", "", "/foo", "bar", "");

	TEST("relative ref with a non-empty path, query and fragment", PASS,
	    URI("/foo?bar#quux"),
	    "", "", "", "/foo", "bar", "quux");

	TEST("relative ref with a non-empty path that doesn't start with /", PASS,
	    URI("foo"),
	    "", "", "", "foo", "", "");

	TEST("relative ref with a query", PASS,
	    URI("?bar"),
	    "", "", "", "", "bar", "");

	TEST("relative ref with a query and fragment", PASS,
	    URI("?bar#quux"),
	    "", "", "", "", "bar", "quux");

	TEST("relative ref with a fragment alone", PASS,
	    URI("#quux"),
	    "", "", "", "", "", "quux");

	TEST("the empty URI", PASS,
	    URI(""),
	    "", "", "", "", "", "");

	TEST("schema-less relative ref", PASS,
	    URI("//example.com"),
	    "", "example.com", "", "", "", "");

	TEST("schema-less relative ref and path", PASS,
	    URI("//example.com/foo/bar/"),
	    "", "example.com", "", "/foo/bar/", "", "");

	TEST("schema-less relative ref, path and query", PASS,
	    URI("//example.com/foo/bar/?foo"),
	    "", "example.com", "", "/foo/bar/", "foo", "");

	TEST("schema-less relative ref, path, query and fragment", PASS,
	    URI("//example.com/foo/bar/?foo#quux"),
	    "", "example.com", "", "/foo/bar/", "foo", "quux");

	TEST("schema-less relative ref, port, path, query and fragment", PASS,
	    URI("//example.com:1/foo/bar/?foo#quux"),
	    "", "example.com", "1", "/foo/bar/", "foo", "quux");

	TEST("mailto: URI", PASS,
	    URI("mailto:foo@bar.com"),
	    "mailto", "", "", "foo@bar.com", "", "");

	TEST("mailto: URI with a query", PASS,
	    URI("mailto:foo@bar.com?subject=foo%20bar"),
	    "mailto", "", "", "foo@bar.com", "subject=foo%20bar", "");

	return 0;
}
