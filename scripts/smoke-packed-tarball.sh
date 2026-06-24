#!/bin/sh
set -eu

repo=$(pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

npm pack --pack-destination "$tmp" >/dev/null
tarball=$(find "$tmp" -name '*.tgz' -maxdepth 1 -print | head -n 1)

sh "$repo/scripts/smoke-npm-tarball.sh" "$tarball"
