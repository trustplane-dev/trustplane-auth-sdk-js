#!/bin/sh
set -eu

if git grep -n -i -E 'OSS|open[- ]source|source is public|generally available|production ready|available on npm|released now|latest tag' -- . ':!.git' ':!scripts/scan-wording.sh'; then
  echo "premature wording scan failed"
  exit 1
fi
