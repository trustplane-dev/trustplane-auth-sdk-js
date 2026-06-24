#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 path/to/package.tgz"
  exit 2
fi

tarball=$1
case "$tarball" in
  /*) ;;
  *) tarball="$(pwd)/$tarball" ;;
esac

if [ ! -f "$tarball" ]; then
  echo "tarball not found: $tarball"
  exit 1
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

cd "$tmp"
npm init -y >/dev/null
npm install "$tarball" >/dev/null
cat > smoke.mjs <<'JS'
import { HeaderAuthorization, bodySHA256 } from "@trustplane/auth-sdk";

if (HeaderAuthorization !== "Authorization") {
  throw new Error("unexpected header export");
}
if (bodySHA256("trustplane").length !== 64) {
  throw new Error("unexpected digest export");
}
JS
node smoke.mjs
