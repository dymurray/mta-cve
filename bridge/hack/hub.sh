#!/usr/bin/env bash
# curl wrapper for the MTA Hub via a local port-forward (svc/mta-hub -> :18080).
# Usage: hack/hub.sh <METHOD> <path> [curl args...]
m="$1"; p="$2"; shift 2
exec curl -s -X "$m" -u "${HUB_USER:-admin}:${HUB_PASSWORD:-admin}" -H 'Content-Type: application/json' "${HUB_URL:-http://localhost:18080}$p" "$@"
