#!/bin/sh

set -e

i=0

grep -e '[^e].URI(' tests/uri_parse_test.c | \
	awk -F '"' '{ print $2 }' | \
	while read line; do
		printf "%s\n" "$line" > afl/in.orig/${i}
		i=$((i+1))
	done

afl-cmin -i afl/in.orig -o afl/in -- ./fuzzy_uri_parser
