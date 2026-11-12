#!/usr/bin/env bash
# One-shot installer for the MTA <-> RHTPA automated CVE remediation
# environment. Brings up, on an OpenShift cluster you are cluster-admin on:
#
#   1. the public MTA operator (channel 8.3) + Tackle CR with agentic enabled
#   2. RHTPA 3.1 (RHBK + PostgreSQL + Helm chart + importers)
#   3. the bridge, agent, skills and custom-UI images (in-cluster builds)
#   4. the hub service account + token the bridge needs
#   5. all Tasks/Addons/watchers/Agents/SkillCards/Gateway CRs
#
# Result matches the demo environment described in SYSTEM-OVERVIEW.md.
# The watchers start with DRY_RUN=true; flip it when the logs look right.
#
# Prerequisites: oc (logged in), helm, jq, go 1.2x, git.
# Credentials are generated/kept in bridge/.secrets.env (gitignored, 600).
#
# Usage: ./install-mta.sh
#   MTA_CHANNEL=8.3        operator channel (default 8.3)
#   UI_DIR=...             custom-UI checkout (auto-cloned if missing)
#   HARNESS_SRC=...        harness checkout (auto-cloned if missing)
#   SKIP_UI=1              keep the stock MTA UI
#   STEP=n                 resume from step n (steps: 1 2 3 4 5)
set -euo pipefail
cd "$(dirname "$0")"
ROOT="$PWD"
source bridge/hack/env.sh

step="${STEP:-1}"

# ---------------------------------------------------------------- preflight
for c in oc helm jq go git; do
  command -v "$c" >/dev/null || { echo "missing prerequisite: $c"; exit 1; }
done
k auth can-i create namespaces >/dev/null 2>&1 || { echo "not cluster-admin on context $KCTX"; exit 1; }

SECRETS="$BRIDGE_ROOT/.secrets.env"
touch "$SECRETS"; chmod 600 "$SECRETS"
missing=()
for v in JIRA_URL JIRA_EMAIL JIRA_TOKEN LLM_API_KEY; do
  grep -q "^$v=" "$SECRETS" || missing+=("$v")
done
if [ "${#missing[@]}" -gt 0 ]; then
  cat <<EOF
Add the following to $SECRETS before continuing:

  JIRA_URL=https://your.atlassian.net     # JIRA CVE source (prodsec tickets)
  JIRA_EMAIL=you@example.com              # Atlassian API-token owner
  JIRA_TOKEN=<api token>                  # https://id.atlassian.com/manage-profile/security/api-tokens
  LLM_API_KEY=<key>                       # key for the agents' LLM endpoint
                                          # (deploy/mta/05-gateway.yaml)
EOF
  exit 1
fi

run_step() { # run_step <n> <description> <cmd...>
  local n="$1" desc="$2"; shift 2
  if [ "$step" -le "$n" ]; then
    echo; echo "=== step $n: $desc ==="
    "$@"
  else
    echo "=== step $n: $desc (skipped, STEP=$step) ==="
  fi
}

# ------------------------------------------------- step 1: MTA operator+hub
run_step 1 "MTA operator + Tackle CR" bridge/hack/install-mta-operator.sh

# ------------------------------------------------------- step 2: RHTPA 3.1
run_step 2 "RHTPA (RHBK, PostgreSQL, Helm chart, importers)" bridge/hack/install-rhtpa.sh

# -------------------------------------------------------- step 3: images
# Source checkouts for the custom UI and the agent harness, cloned from the
# forks if not present. See README.md for the branch map.
UI_DIR="${UI_DIR:-$ROOT/checkouts/mta-tackle2-ui}"
HARNESS_CHECKOUT="${HARNESS_CHECKOUT:-$ROOT/checkouts/agentic-controller}"
if [ "${SKIP_UI:-0}" != "1" ] && [ ! -d "$UI_DIR" ]; then
  git clone --branch agentic-observability --depth 1 \
    https://github.com/dymurray/tackle2-ui.git "$UI_DIR"
fi
if [ ! -d "$HARNESS_CHECKOUT" ]; then
  git clone --branch harness-push-url --depth 1 \
    https://github.com/dymurray/agentic-controller.git "$HARNESS_CHECKOUT"
fi

image_builds() {
  k -n "$MTA_NS" apply -f "$BRIDGE_ROOT/deploy/build/buildconfigs.yaml"
  bridge/hack/build.sh
  bridge/hack/build-skills.sh
  HARNESS_SRC="$HARNESS_CHECKOUT/harness" bridge/hack/build-agent.sh
  if [ "${SKIP_UI:-0}" != "1" ]; then
    UI_DIR="$UI_DIR" bridge/hack/build-ui.sh
  else
    echo "SKIP_UI=1: keeping the stock MTA UI"
  fi
}
run_step 3 "images (bridge, skills, agent, UI)" image_builds

# --------------------------------------------- step 4: hub service account
run_step 4 "hub bridge token" bridge/hack/mint-hub-token.sh

# ------------------------------------------------------- step 5: wiring
run_step 5 "secrets, CRs, watchers, agents" bridge/hack/setup-mta.sh

cat <<EOF

Install complete.

  MTA UI:      https://mta-$MTA_NS.$(k -n $MTA_NS get ingress.config.openshift.io cluster -o jsonpath='{.spec.domain}' 2>/dev/null || echo '<apps-domain>')
  RHTPA:       https://$TPA_HOST  (admin / \$TPA_ADMIN_PASSWORD in bridge/.secrets.env)
  Watchers:    DRY_RUN=true — verify then:
               oc -n $MTA_NS set env deploy/cve-watcher DRY_RUN=false
               oc -n $MTA_NS set env deploy/jira-watcher DRY_RUN=false

Next: add https://github.com/dymurray/mta-cve-demo.git as an application in
the MTA UI (with a git source credential) and tag it into the konveyor-cves
archetype — see SYSTEM-OVERVIEW.md §2.7.
EOF
