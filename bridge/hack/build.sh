#!/usr/bin/env bash
# Builds the bridge image in-cluster from the local working tree.
set -euo pipefail
source "$(dirname "$0")/env.sh"
cd "$BRIDGE_ROOT"
COPYFILE_DISABLE=1 tar --no-mac-metadata --no-xattrs --exclude=./bin --exclude=./.secrets.env --exclude=./.git -czf /tmp/bridge-src.tgz .
oc --context="$KCTX" -n "$MTA_NS" start-build mta-rhtpa-bridge --from-archive=/tmp/bridge-src.tgz --follow --wait
