#!/bin/sh

i=0

grep -e '[^e].URI(' tests/uri_parse_test.c | \
	awk -F '"' '{ print $2 }' | \
	while read line; do
		printf "%s\n" "$line" > afl/in/${i}
		i=$((i+1))
	done
