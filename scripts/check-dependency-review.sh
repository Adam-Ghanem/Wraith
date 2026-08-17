#!/usr/bin/env sh

set -eu

review_file="docs/dependency-review.md"
target="${1:-all}"

if [ ! -f "$review_file" ]; then
	echo "missing $review_file" >&2
	exit 1
fi

if [ "$target" = "go" ] || [ "$target" = "all" ]; then
	go list -m -f '{{if not .Main}}{{.Path}} {{.Version}}{{end}}' all | while IFS=' ' read -r module version; do
		[ -n "$module" ] || continue
		if ! grep -Fq "| \`$module\` | \`$version\` |" "$review_file"; then
			echo "dependency review is missing Go module $module $version" >&2
			exit 1
		fi
	done
fi

if [ "$target" = "web" ] || [ "$target" = "all" ]; then
	node scripts/check-web-dependency-review.mjs "$review_file"
fi

if [ "$target" != "go" ] && [ "$target" != "web" ] && [ "$target" != "all" ]; then
	echo "usage: $0 [go|web|all]" >&2
		exit 1
fi
