#!/usr/bin/env bash
# Configures MTA for the RHTPA bridge: secrets, egress policy, Task/Addon CRs,
# the cve-watcher and the Java CVE agent. Requires the bridge image (hack/build.sh).
set -euo pipefail
source "$(dirname "$0")/env.sh"
cd "$BRIDGE_ROOT"
: "${HUB_BRIDGE_TOKEN:?HUB_BRIDGE_TOKEN missing from .secrets.env (see README: hub service account)}"
k -n "$MTA_NS" create secret generic rhtpa-bridge \
  --from-literal=RHTPA_URL="https://server.${TPA_NS}.svc" \
  --from-literal=RHTPA_CONSOLE_URL="https://${TPA_HOST}" \
  --from-literal=RHTPA_TOKEN_URL="http://sso-service.${TPA_NS}.svc:8080/realms/trustify/protocol/openid-connect/token" \
  --from-literal=RHTPA_CLIENT_ID=cli \
  --from-literal=RHTPA_CLIENT_SECRET="$CLI_CLIENT_SECRET" \
  --from-literal=RHTPA_CA_FILE=/var/run/secrets/kubernetes.io/serviceaccount/service-ca.crt \
  --dry-run=client -o yaml | k apply -f -
k -n "$MTA_NS" create secret generic hub-bridge-token \
  --from-literal=HUB_BRIDGE_TOKEN="$HUB_BRIDGE_TOKEN" \
  --dry-run=client -o yaml | k apply -f -
# JIRA CVE source (jira-watcher): an API token from
# https://id.atlassian.com/manage-profile/security/api-tokens
: "${JIRA_URL:?JIRA_URL missing from .secrets.env (e.g. https://redhat.atlassian.net)}"
: "${JIRA_EMAIL:?JIRA_EMAIL missing from .secrets.env}"
: "${JIRA_TOKEN:?JIRA_TOKEN missing from .secrets.env}"
k -n "$MTA_NS" create secret generic jira-credentials \
  --from-literal=JIRA_URL="$JIRA_URL" \
  --from-literal=JIRA_EMAIL="$JIRA_EMAIL" \
  --from-literal=JIRA_TOKEN="$JIRA_TOKEN" \
  --dry-run=client -o yaml | k apply -f -
# LLM gateway key (deploy/mta/05-gateway.yaml references secret 'enmaas-key').
: "${LLM_API_KEY:?LLM_API_KEY missing from .secrets.env (the LLM endpoint key for the agents)}"
k -n "$MTA_NS" create secret generic enmaas-key \
  --from-literal=api-key="$LLM_API_KEY" \
  --dry-run=client -o yaml | k apply -f -
k apply -f deploy/networkpolicy.yaml
k apply -f deploy/mta/
k -n "$MTA_NS" rollout restart deploy/cve-watcher deploy/jira-watcher
