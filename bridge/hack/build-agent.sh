#!/usr/bin/env bash
# Builds the CVE agent image (images/agent-cve) in-cluster. When HARNESS_SRC
# points at an agentic-controller harness/ checkout (default: the
# harness-push-url worktree, which adds HARNESS_PUSH_URL), its
# migration-harness replaces the base image's.
set -euo pipefail
source "$(dirname "$0")/env.sh"
HARNESS_SRC="${HARNESS_SRC-$HOME/git/agentic-controller-push-url/harness}"
cd "$BRIDGE_ROOT/images/agent-cve"
rm -f bin/migration-harness
if [ -n "$HARNESS_SRC" ] && [ -d "$HARNESS_SRC" ]; then
  (cd "$HARNESS_SRC" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$BRIDGE_ROOT/images/agent-cve/bin/migration-harness" ./cmd/migration-harness)
  echo "migration-harness from $HARNESS_SRC ($(git -C "$HARNESS_SRC" rev-parse --short HEAD))"
fi
COPYFILE_DISABLE=1 tar --no-mac-metadata --no-xattrs -czf /tmp/agent-src.tgz .
oc --context="$KCTX" -n "$MTA_NS" start-build agent-cve --from-archive=/tmp/agent-src.tgz --follow --wait
