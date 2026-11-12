#!/usr/bin/env bash
# Prints an RHTPA access token for the `cli` service account.
source "$(dirname "$0")/env.sh"
curl -sk -d grant_type=client_credentials -d client_id=cli -d client_secret="$CLI_CLIENT_SECRET" \
  "https://$SSO_HOST/realms/trustify/protocol/openid-connect/token" |
  python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])'
