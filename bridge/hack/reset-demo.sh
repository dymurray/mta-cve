#!/usr/bin/env bash
# Resets the demo: deletes the MTA application (and its facts/tasks), its
# SBOMs in RHTPA, and the konveyor/cve-* branches in the demo repo.
# Usage: hack/reset-demo.sh <app-id> [owner/repo]
set -euo pipefail
source "$(dirname "$0")/env.sh"
app="${1:?app id}"; repo="${2:-dymurray/mta-cve-demo}"
read -r -p "Delete MTA app $app, its RHTPA SBOMs and konveyor/cve-* branches in $repo? [y/N] " ok
[[ "$ok" == y ]] || exit 1
token="$("$BRIDGE_ROOT/hack/tpa-token.sh")"
sbom=$("$BRIDGE_ROOT/hack/hub.sh" GET "/applications/$app/facts/rhtpa:sbom" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("id",""))' 2>/dev/null || true)
[[ -n "$sbom" ]] && curl -sk -X DELETE -H "Authorization: Bearer $token" "https://$TPA_HOST/api/v3/sbom/$sbom" -o /dev/null -w "sbom delete %{http_code}\n"
"$BRIDGE_ROOT/hack/hub.sh" DELETE "/applications/$app" -o /dev/null -w "app delete %{http_code}\n"
for b in $(git ls-remote --heads "https://github.com/$repo.git" 'konveyor/cve-*' | awk '{print $2}' | sed 's#refs/heads/##'); do
  gh api -X DELETE "repos/$repo/git/refs/heads/$b" && echo "deleted branch $b"
done
