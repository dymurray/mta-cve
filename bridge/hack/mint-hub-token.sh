#!/usr/bin/env bash
# Creates (or reuses) the hub service account used by the bridge/addons and
# mints an API token, saving it as HUB_BRIDGE_TOKEN in .secrets.env.
# The hub 'addon' role cannot create AgentRuns, so the account uses 'architect'.
#
# Bootstrap credentials: the hub's initial admin user (HUB_USER/HUB_PASSWORD,
# default admin/admin on a fresh install).
set -euo pipefail
source "$(dirname "$0")/env.sh"

HUB_USER="${HUB_USER:-admin}"
HUB_PASSWORD="${HUB_PASSWORD:-admin}"
SA_NAME="${HUB_BRIDGE_SA:-rhtpa.cve-bridge}"
LOCAL_PORT="${HUB_LOCAL_PORT:-18080}"

command -v jq >/dev/null || { echo "jq is required"; exit 1; }

echo "Port-forwarding svc/mta-hub -> :$LOCAL_PORT ..."
kubectl --context "$KCTX" -n "$MTA_NS" port-forward svc/mta-hub "$LOCAL_PORT:8080" >/dev/null 2>&1 &
PF_PID=$!
trap 'kill $PF_PID 2>/dev/null || true' EXIT
for _ in $(seq 1 30); do
  curl -s -o /dev/null "http://localhost:$LOCAL_PORT/hub/health" && break
  sleep 2
done

hub() { # hub METHOD PATH [data]
  local m="$1" p="$2" d="${3:-}"
  if [ -n "$d" ]; then
    curl -s -u "$HUB_USER:$HUB_PASSWORD" -H 'Content-Type: application/json' -X "$m" -d "$d" "http://localhost:$LOCAL_PORT/hub$p"
  else
    curl -s -u "$HUB_USER:$HUB_PASSWORD" -H 'Content-Type: application/json' -X "$m" "http://localhost:$LOCAL_PORT/hub$p"
  fi
}

# Reuse an existing service account of this name.
SA_ID=$(hub GET "/serviceaccounts" | jq -r --arg n "$SA_NAME" '.[] | select(.name==$n) | .id' | head -1)
if [ -z "$SA_ID" ]; then
  SA_ID=$(hub POST /serviceaccounts "{\"name\":\"$SA_NAME\",\"userName\":\"$SA_NAME\",\"role\":\"architect\"}" | jq -r .id)
  echo "Created service account $SA_NAME (id $SA_ID)"
else
  echo "Reusing service account $SA_NAME (id $SA_ID)"
fi

TOKEN=$(hub POST "/serviceaccounts/$SA_ID/tokens" '{}' | jq -r .token)
[ "$TOKEN" != "null" ] && [ -n "$TOKEN" ] || { echo "Failed to mint token"; exit 1; }

if grep -q '^HUB_BRIDGE_TOKEN=' "$BRIDGE_ROOT/.secrets.env" 2>/dev/null; then
  tmp=$(mktemp)
  awk -v t="$TOKEN" '/^HUB_BRIDGE_TOKEN=/{print "HUB_BRIDGE_TOKEN=" t; next} 1' "$BRIDGE_ROOT/.secrets.env" > "$tmp" && mv "$tmp" "$BRIDGE_ROOT/.secrets.env"
else
  echo "HUB_BRIDGE_TOKEN=$TOKEN" >> "$BRIDGE_ROOT/.secrets.env"
fi
chmod 600 "$BRIDGE_ROOT/.secrets.env"
echo "HUB_BRIDGE_TOKEN saved to .secrets.env"
