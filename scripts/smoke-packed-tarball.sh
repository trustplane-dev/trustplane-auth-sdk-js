#!/bin/sh
set -eu

repo=$(pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

npm pack --pack-destination "$tmp" >/dev/null
tarball=$(find "$tmp" -name '*.tgz' -maxdepth 1 -print | head -n 1)

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

cd "$repo"
