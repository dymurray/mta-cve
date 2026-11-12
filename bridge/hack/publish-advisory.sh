#!/usr/bin/env bash
# Publishes an advisory document into RHTPA, simulating a newly released
# advisory arriving through an importer feed. The cve-watcher picks it up on
# its next poll for every application whose SBOM it affects.
# Usage: hack/publish-advisory.sh [advisory.json]  (default: CVE-2025-48924 / commons-lang3)
set -euo pipefail
source "$(dirname "$0")/env.sh"
doc="${1:-$BRIDGE_ROOT/hack/advisories/GHSA-j288-q9x7-2f5v.json}"
token="$("$BRIDGE_ROOT/hack/tpa-token.sh")"
curl -sk -X POST -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
  --data-binary @"$doc" "https://$TPA_HOST/api/v3/advisory?labels.source=demo-publish" -w '\nHTTP %{http_code}\n'
