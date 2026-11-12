# Driving agentic CVE remediation from an external service (no MTA inventory)

This document is for a user who wants **MTA as an agent execution platform only**:
install a stock, **public MTA 8.3.3** (no internal ART build), seed it with a CVE
remediation agent and its skills, and then drive remediation **AgentRuns directly from
a pipeline or script** — no UI, no discovery pipeline, no RHTPA, no inventory beyond a
repository reference.

Everything below uses only:

- `oc` (OpenShift CLI)
- `curl` + `jq`
- the public MTA operator (OperatorHub, channel `8.3` → 8.3.3)

---

## 0. What you get

```
your pipeline ──POST /hub/agentic/agentruns──▶ MTA hub ──▶ AgentRun CR ──▶ agentic-controller
                                                                                │ pod (agent image:
                                                                                │ harness + JDK/Maven/Go/Python
                                                                                │ + rgctl + cve-remediation skill)
              ◀──GET status.phase Succeeded/Failed──── MTA hub ◀────────────────┘
                              agent clones the repo, fixes the CVE, pushes a branch
```

The only thing the runtime needs from the hub is **the repository to work on**. The
harness inside the run pod resolves the repo URL, credentials and branch from a hub
*application* record referenced by `APP_ID`. You never touch the MTA UI or the
discovery/analysis addons — creating that one application record is a single API call
(documented below, §4.1).

---

## 1. Install public MTA 8.3.3

```bash
oc new-project openshift-mta

oc apply -f - <<'EOF'
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: mta-operator
  namespace: openshift-mta
spec:
  channel: "8.3"                     # resolves to the latest 8.3.x public build
  name: mta-operator
  source: redhat-operators
  sourceNamespace: openshift-marketplace
EOF

oc apply -f - <<'EOF'
apiVersion: konveyor.tackle.io/v1alpha1
kind: Tackle
metadata:
  name: mta
  namespace: openshift-mta
spec:
  agentic_enabled: true              # REQUIRED: hub /hub/agentic API + agentic-controller
EOF

oc -n openshift-mta rollout status deploy/mta-hub
oc -n openshift-mta rollout status deploy/agentic-controller
```

`agentic_enabled: true` is the one non-default field. It gives you:

- the `konveyor.io/v1alpha1` CRDs: `Agent`, `AgentRun`, `AgentWorkflow`, `Gateway`,
  `SkillCard`, and the `agentic-controller` deployment that runs them;
- the hub REST routes under `/hub/agentic/*` (scope-gated, see §3).

Verify:

```bash
oc get crd agentruns.konveyor.io gateways.konveyor.io agents.konveyor.io
```

## 2. Build the agent image (once, on any machine with podman)

The demo agent image is **not public** on quay (only its base,
`quay.io/dymurray/agent-migiq`, is). Build it yourself and push to a registry your
cluster can pull:

```bash
git clone -b jira-cve-source https://github.com/dymurray/mta-rhtpa-bridge.git
cd mta-rhtpa-bridge

podman build -t quay.io/<you>/agent-cve:latest -f images/agent-cve/Containerfile .
podman push quay.io/<you>/agent-cve:latest
```

Contents: `agent-migiq` goose harness + JDK 21 + Maven + Go 1.26 + Python 3
(pip/uv/Poetry/pytest) + rgctl 0.4.21 + bazelisk. It must be a RHEL10/UBC10-style base
(rgctl needs glibc ≥ 2.39) — the Containerfile already is.

(The same repo's `hack/build-agent.sh` does this as an in-cluster BuildConfig if you
prefer; it targets the demo cluster's internal registry. The full demo environment —
including this image build — is automated by [`install-mta.sh`](install-mta.sh) in
[dymurray/mta-cve](https://github.com/dymurray/mta-cve); see
[README.md](README.md) for the complete component/branch map.)

## 3. Seed the platform (Gateway → skills → agent)

### 3.1 Gateway (LLM access)

The agent talks to an LLM through a Gateway CR. Any Anthropic- or OpenAI-compatible
endpoint works.

```bash
oc -n openshift-mta create secret generic llm-key \
  --from-literal=api-key='<YOUR_LLM_API_KEY>'

oc apply -f - <<'EOF'
apiVersion: konveyor.io/v1alpha1
kind: Gateway
metadata:
  name: llm
  namespace: openshift-mta
spec:
  provider: anthropic
  endpoint: https://api.anthropic.com            # or api.enmaas.devshift.net, etc.
  model:
    name: claude-sonnet-4-6
    contextWindow: 200000
  credentialRef:
    secretName: llm-key
    key: api-key
EOF
```

### 3.2 The remediation skill (inline SkillCard)

The full CVE-remediation procedure ships as an inline SkillCard in the bridge repo
(`deploy/mta/30-agent.yaml`, SkillCard `cve-remediation`). Apply it directly:

```bash
oc apply -f - <<'EOF'
apiVersion: konveyor.io/v1alpha1
kind: SkillCard
metadata:
  name: cve-remediation
  namespace: openshift-mta
  labels:
    konveyor.io/managed: "true"
spec:
  displayName: CVE Remediation
  description: >-
    Remediate one CVE in a Java/Maven, Go module or Python project: upgrade the
    dependency, adapt call sites, verify build/tests, and record a summarized
    remediation report in the commit message.
  type: skill
  version: 2.5.0
  tags: [security, cve, java, go, python]
  inline: |
    ---
    name: cve-remediation
    ...full skill text from deploy/mta/30-agent.yaml...
EOF
```

> Copy the `inline:` body verbatim from `deploy/mta/30-agent.yaml` (SkillCard
> `cve-remediation`). The optional `rgctl-osv` SkillCard from the same file adds
> rgctl reachability analysis; it needs the `mta-cve-skills` image
> (`images/skills/` in the same repo, also a podman build+push) and is not required
> for pipeline-driven remediation.

### 3.3 The agent

```bash
oc apply -f - <<'EOF'
apiVersion: konveyor.io/v1alpha1
kind: Agent
metadata:
  name: cve-remediator-java
  namespace: openshift-mta
  labels:
    konveyor.io/managed: "true"     # without this label the hub will NOT list it
spec:
  image: quay.io/<you>/agent-cve:latest
  gitConfig:
    userName: Your Name
    userEmail: you@example.com
  gateways:
    - ref: llm
  skillCards:
    - ref: cve-remediation
  execution:
    maxTurns: 150
  prompt: |
    You are a Java security remediation agent working in a Maven project.
    Each run targets ONE vulnerability (CVE). Follow the cve-remediation skill
    exactly. The run instructions carry the CVE details and build errors.

    Hard rules:
    - Upgrade to the required fixed version; never downgrade, exclude, or
      remove the dependency to make the build pass.
    - Do not delete, skip, or weaken tests.
    - Commit with `git commit -s` (DCO) and put the summarized remediation
      report in the commit message only.
EOF
```

Repeat with `cve-remediator-go` / `cve-remediator-python` (prompts in
`deploy/mta/30-agent.yaml`) if you need other ecosystems — the same image serves all
three.

Wait until ready:

```bash
oc -n openshift-mta wait --for=condition=Ready agent/cve-remediator-java --timeout=120s
```

## 4. Mint a pipeline token

The hub's agentic routes are scope-gated (`agentic.agentruns`). Create a hub service
account with the `architect` role and mint a token. Bootstrap with the hub's local
admin (fresh installs: `admin`/`admin` — change it after first login):

```bash
oc -n openshift-mta port-forward svc/mta-hub 18080:8080 &

# service account (id is in the response)
curl -s -u admin:admin -H 'Content-Type: application/json' \
  -X POST http://localhost:18080/hub/serviceaccounts \
  -d '{"name":"pipeline","userName":"pipeline","role":"architect"}'

# token (save the value from .token)
curl -s -u admin:admin -H 'Content-Type: application/json' \
  -X POST http://localhost:18080/hub/serviceaccounts/<ID>/tokens -d '{}'
```

Export for the scripts below:

```bash
HUB=http://localhost:18080          # or https://mta-openshift-mta.<apps-domain>/hub
TOKEN=<minted token>
```

(Outside the cluster use the route: `oc -n openshift-mta get route mta` →
`https://<host>/hub`. The demo cluster's URL is
`https://mta-openshift-mta.apps.mta-cve.mg.dog8code.com/hub`.)

## 5. Drive remediation from your pipeline

### 5.1 Register the repository (one application record)

The harness inside the run pod resolves the repo and its credentials from the hub
application named by `APP_ID`. This is the *only* inventory record you need, and you
create it by API — never through the UI:

```bash
# public repo — no credential needed
APP_ID=$(curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -X POST $HUB/applications \
  -d '{
        "name": "my-service",
        "repository": {"kind": "git", "url": "https://github.com/you/my-service.git", "branch": "main"}
      }' | jq -r .id)
echo "APP_ID=$APP_ID"
```

For a **private repo**, first create an identity and attach it:

```bash
IDENTITY_ID=$(curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -X POST $HUB/identities \
  -d '{"name":"my-service-git","kind":"source","settings":{"user":"you","password":"<ghp_token>"}}' \
  | jq -r .id)

APP_ID=$(curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -X POST $HUB/applications \
  -d "{
        \"name\": \"my-service\",
        \"repository\": {\"kind\": \"git\", \"url\": \"https://github.com/you/my-service.git\", \"branch\": \"main\"},
        \"identities\": [{\"id\": $IDENTITY_ID, \"name\": \"my-service-git\", \"kind\": \"source\"}]
      }" | jq -r .id)
```

### 5.2 Create an AgentRun

This is the payload contract (identical to what the bridge's
`internal/agentic/agentrun.go` submits and what the MTA UI submits):

```bash
RUN_NAME="cve-my-service-2022-1471-$(date +%s)"

curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -X POST $HUB/agentic/agentruns \
  -d @- <<EOF | jq .
{
  "apiVersion": "konveyor.io/v1alpha1",
  "kind": "AgentRun",
  "metadata": {
    "name": "$RUN_NAME",
    "labels": {
      "konveyor.io/application": "$APP_ID",
      "konveyor.io/cve": "cve-2022-1471"
    }
  },
  "spec": {
    "agentRef": "cve-remediator-java",
    "gateway": "llm",
    "instructions": "Remediate CVE-2022-1471 (critical, CVSS 9.8) in this Maven project. Follow the cve-remediation skill.\n\nVulnerability: SnakeYaml Constructor Deserialization Remote Code Execution.\nUpdate org.yaml:snakeyaml from 1.33 to 2.0. The API changed: Constructor and Representer moved/changed signatures; adapt all call sites (see src/main/java/.../Config.java). Do not downgrade or exclude the dependency. Verify with mvn clean verify; only new failures compared to the baseline are yours to fix. Commit with git commit -s and a summarized report in the commit message.",
    "execution": {"maxTurns": 150},
    "env": [
      {"name": "APP_ID",         "value": "$APP_ID"},
      {"name": "TARGET_BRANCH",  "value": "konveyor/cve-2022-1471-fix"},
      {"name": "HARNESS_PUSH_URL", "value": "https://github.com/you/my-service.git"}
    ]
  }
}
EOF
```

Field notes:

| Field | Meaning |
|---|---|
| `spec.agentRef` | name of the Agent CR (§3.3) |
| `spec.gateway` | name of the Gateway CR (§3.1); may be omitted if the Agent names one |
| `spec.instructions` | the task brief. The demo agents expect: the CVE id + severity, the dependency change (old → fixed version), what breaks (build errors / API changes), and the verification command. Richer briefs (OSV document, failing tests) improve results. |
| `spec.execution.maxTurns` | agent turn budget |
| `spec.env.APP_ID` | **required** — the harness resolves the repository from this hub application |
| `spec.env.TARGET_BRANCH` | **required** — the branch the harness clones and works on |
| `spec.env.HARNESS_PUSH_URL` | optional — push target when it should differ from the clone URL (e.g. push to a fork while cloning upstream) |
| `metadata.labels` | optional, free-form; used for your own bookkeeping and by `GET /agentic/agentruns` filtering |
| `metadata.name` | must be a DNS-1123 subdomain; you can instead pass `generateName: "cve-"` and read the generated name from the response |

Always create runs through the **hub API** (not `oc apply` on the AgentRun CR): the hub
mints the scoped `HUB_TOKEN` secret the harness needs.

### 5.3 Wait for completion

```bash
until PHASE=$(curl -s -H "Authorization: Bearer $TOKEN" \
    $HUB/agentic/agentruns/$RUN_NAME | jq -r .status.phase); \
    [ "$PHASE" = "Succeeded" ] || [ "$PHASE" = "Failed" ]; do
  echo "phase: $PHASE"; sleep 15
done
echo "final: $PHASE"
```

Phases: `Pending` → `Running` → `Succeeded` | `Failed`. On success the fix commit is on
`TARGET_BRANCH` (pushed to `HARNESS_PUSH_URL` if set), DCO-signed, with the remediation
report in the commit message. Open the PR from your pipeline with your normal tooling
(the bridge's flow, for comparison, opens it via a `cve-remediation` addon task).

Logs while running:

```bash
oc -n openshift-mta get pods | grep $RUN_NAME
oc -n openshift-mta logs -f pod/<run-pod>
```

### 5.4 List / inspect / clean up

```bash
# all runs
curl -s -H "Authorization: Bearer $TOKEN" $HUB/agentic/agentruns | jq \
  '.[] | {name: .metadata.name, phase: .status.phase, agent: .spec.agentRef}'

# one run (full spec/status)
curl -s -H "Authorization: Bearer $TOKEN" $HUB/agentic/agentruns/$RUN_NAME | jq .

# delete a finished run (also removes its sandbox objects)
curl -s -X DELETE -H "Authorization: Bearer $TOKEN" $HUB/agentic/agentruns/$RUN_NAME
```

### 5.5 Ready-made pipeline script

Save as `remediate-cve.sh`:

```bash
#!/usr/bin/env bash
# Usage: remediate-cve.sh <repo-url> <branch> <agent-name> <CVE> <old> <new> <notes>
# Env: HUB, TOKEN, PUSH_URL (optional)
set -euo pipefail
repo="$1"; branch="$2"; agent="$3"; cve="$4"; old="$5"; new="$6"; notes="$7"
: "${HUB:?}" "${TOKEN:?}"

# 1. register (idempotent: reuse existing app with this name)
name=$(basename "$repo" .git)
app_id=$(curl -s -H "Authorization: Bearer $TOKEN" "$HUB/applications?name=$name" | jq -r 'if length>0 then .[0].id else empty')
if [ -z "$app_id" ]; then
  app_id=$(curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -X POST "$HUB/applications" \
    -d "{\"name\":\"$name\",\"repository\":{\"kind\":\"git\",\"url\":\"$repo\",\"branch\":\"$branch\"}}" \
    | jq -r .id)
fi

# 2. run
run="cve-${name}-$(echo "$cve" | tr 'A-Z' 'a-z')-$(date +%s)"
cat <<JSON | curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -X POST "$HUB/agentic/agentruns" -d @- | jq .
{
  "apiVersion": "konveyor.io/v1alpha1", "kind": "AgentRun",
  "metadata": {"name": "$run", "labels": {"konveyor.io/cve": "$(echo "$cve"|tr 'A-Z' 'a-z')"}},
  "spec": {
    "agentRef": "$agent", "gateway": "llm",
    "instructions": "Remediate $cve in this project. Follow the cve-remediation skill. Upgrade the affected dependency from $old to $new. $notes Verify the build/tests; only new failures are yours to fix. Commit with git commit -s, report in the commit message.",
    "execution": {"maxTurns": 150},
    "env": [
      {"name": "APP_ID", "value": "$app_id"},
      {"name": "TARGET_BRANCH", "value": "konveyor/$(echo "$cve"|tr 'A-Z' 'a-z')-fix"}
      ${PUSH_URL:+,{"name": "HARNESS_PUSH_URL", "value": "$PUSH_URL"}}
    ]
  }
}
JSON

# 3. wait
while :; do
  phase=$(curl -s -H "Authorization: Bearer $TOKEN" "$HUB/agentic/agentruns/$run" | jq -r .status.phase)
  echo "phase: $phase" >&2
  case "$phase" in Succeeded|Failed) break;; esac
  sleep 15
done
[ "$phase" = Succeeded ]
```

Example:

```bash
HUB=https://mta-openshift-mta.apps.example.com/hub TOKEN=... \
PUSH_URL=git@github.com:you/my-service.git \
./remediate-cve.sh https://github.com/you/my-service.git main \
  cve-remediator-java CVE-2022-1471 1.33 2.0 \
  "SnakeYaml Constructor/Representer API changed; adapt call sites in Config.java."
```

## 6. Differences from the full demo environment

| Full demo (see SYSTEM-OVERVIEW.md) | This setup |
|---|---|
| MTA 8.3.4 internal ART build + custom hub/UI images | public MTA 8.3.3, stock hub and UI |
| CVEs discovered by RHTPA watchers / JIRA watcher; MTA inventory + discovery pipeline | CVEs supplied by *your* pipeline in `spec.instructions` |
| Auto-bump first, agent only on new build failures | agent always runs (your pipeline decides when) |
| PR opened by the bridge (addon task) | branch pushed; PR opened by your pipeline |
| rgctl reachability + OpenVEX facts in the UI | not provisioned (optional: add the `rgctl-osv` SkillCard + `mta-cve-skills` image) |

What is shared: the Agent/SkillCard/Gateway CRs, the agent image (harness +
toolchains + skill), the AgentRun payload contract, and the hub API. Runs created here
also show up in the MTA UI's Agent Runs page (that list is not label-filtered), with
live logs and ACP terminal access.
