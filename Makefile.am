ACLOCAL_AMFLAGS =	-I m4

include_HEADERS =	phos.h

lib_LTLIBRARIES =	libphos.la

libphos_la_SOURCES =	libtls.c phos_client.c phos_server.c phos_uri.c
libphos_la_LDFLAGS =	-version-info 0:0:0

dist_man3_MANS =	phos_client.3 phos_server.3 phos_req.3 phos_uri.3

# tests

TESTS =			uri_parse_test uri_res_test
check_PROGRAMS =	uri_parse_test uri_res_test fuzzy_uri_parser

uri_parse_test_SOURCES=	tests/uri_parse_test.c
uri_parse_test_LDADD =	libphos.la

uri_res_test_SOURCES =	tests/uri_res_test.c
uri_res_test_LDADD =	libphos.la

# fuzzy

fuzzy_uri_parser_SOURCES =	tests/fuzzy_uri_parser.c
fuzzy_uri_parser_LDADD =	libphos.la

clean-local:
	-rm -rf afl

afl: tests/uri_parse_test.c
	mkdir -p afl/in afl/out
	./gen-afl-data.sh

.PHONY: fuzzy
fuzzy: afl fuzzy_uri_parser
	afl-fuzz -i afl/in -o afl/out ./fuzzy_uri_parser
