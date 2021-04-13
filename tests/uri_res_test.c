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

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST(ref, exp) do_test(BASE_URI, ref, exp, __LINE__)

static void
do_test(const char *base, const char *ref, const char *exp, int lineno)
{
	struct phos_uri base_uri, ret_uri;
	char buf[1025];

	if (!phos_parse_uri_reference(base, &base_uri))
		errx(1, __FILE__ ":%d failed to parse base URI: %s",
		    lineno, base);

	if (!phos_resolve_uri_from_str(&base_uri, ref, &ret_uri))
		errx(1, __FILE__ ":%d failed to resolve %s from %s",
		    lineno, ref, base);

	if (!phos_serialize_uri(&ret_uri, buf, sizeof(buf)))
		errx(1, __FILE__ ":%d failed to serialize ret_uri",
		    lineno);

	if (strcmp(exp, buf)) {
		printf(__FILE__ ":%d test failed\n", lineno);
		printf("base=%s ref=%s\n", base, ref);
		printf("got: %s\n", buf);
		printf("want: %s\n", exp);
		exit(99);
	}
}

int
main(void)
{
	/* examples taken from the RFC 3986 */

#define BASE_URI "http://a/b/c/d;p?q"
	TEST("g:h", "g:h");
	TEST("g", "http://a/b/c/g");
	TEST("./g", "http://a/b/c/g");
	TEST("g/", "http://a/b/c/g/");
	TEST("/g", "http://a/g");
	TEST("//g", "http://g");
	TEST("?y", "http://a/b/c/d;p?y");
	TEST("g?y", "http://a/b/c/g?y");
	TEST("#s", "http://a/b/c/d;p?q#s");
	TEST("g#s", "http://a/b/c/g#s");
	TEST("g?y#s", "http://a/b/c/g?y#s");
	TEST(";x", "http://a/b/c/;x");
	TEST("g;x", "http://a/b/c/g;x");
	TEST("g;x?y#s", "http://a/b/c/g;x?y#s");
	TEST("", "http://a/b/c/d;p?q");
	TEST(".", "http://a/b/c/");
	TEST("./", "http://a/b/c/");
	TEST("..", "http://a/b/");
	TEST("../", "http://a/b/");
	TEST("../g", "http://a/b/g");
	TEST("../..", "http://a/");
	TEST("../../", "http://a/");
	TEST("../../g", "http://a/g");
}
