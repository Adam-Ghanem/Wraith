#!/usr/bin/env sh

set -eu

review_file="docs/dependency-review.md"

if [ ! -f "$review_file" ]; then
	echo "missing $review_file" >&2
	exit 1
fi

go list -m -f '{{if not .Main}}{{.Path}} {{.Version}}{{end}}' all | while IFS=' ' read -r module version; do
	[ -n "$module" ] || continue
	if ! grep -Fq "| \`$module\` | \`$version\` |" "$review_file"; then
		echo "dependency review is missing Go module $module $version" >&2
		exit 1
	fi
done

node scripts/check-web-dependency-review.mjs "$review_file"
