#!/bin/sh

set -e

rm -rf afl
mkdir -p afl/{server,uri}/{raw,in,out}

i=0

grep -e '[^e].URI(' tests/uri_parse_test.c | \
	awk -F '"' '{ print $2 }' | \
	while read line; do
		printf "%s\n" "$line" > afl/uri/raw/${i}
		printf "%s\r\n" "$line" > afl/server/raw/${i}
		i=$((i+1))
	done

afl-cmin -i afl/uri/raw    -o afl/uri/in    -- ./fuzzy_uri_parser
afl-cmin -i afl/server/raw -o afl/server/in -- ./fuzzy_server
