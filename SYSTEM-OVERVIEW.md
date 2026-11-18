# MTA ⇄ RHTPA Automated CVE Remediation — System Overview & Provisioning Guide

This document explains how the automated CVE remediation environment works end to end,
and how to provision a working environment for a new user from scratch. The companion
document, [`EXTERNAL-AGENTRUN-DRIVER.md`](EXTERNAL-AGENTRUN-DRIVER.md), covers driving
the same agentic remediation from an external service (pipeline) on a **public** MTA
install without the MTA inventory.

Source repositories (all code lives on public branches of Dylan's forks — the full
map with links is in [README.md](README.md)):

| Repo | Branch | Contents |
|---|---|---|
| [dymurray/mta-rhtpa-bridge](https://github.com/dymurray/mta-rhtpa-bridge/tree/jira-cve-source) | [`jira-cve-source`](https://github.com/dymurray/mta-rhtpa-bridge/tree/jira-cve-source) | Bridge: addons, watchers, deploy manifests, hack scripts — vendored here as `bridge/` |
| [dymurray/tackle2-ui](https://github.com/dymurray/tackle2-ui/tree/agentic-observability) | [`agentic-observability`](https://github.com/dymurray/tackle2-ui/tree/agentic-observability) | Custom MTA UI (Vulnerabilities tab, CVE config panel) |
| [dymurray/tackle2-hub](https://github.com/dymurray/tackle2-hub/tree/agentic-observability) | [`agentic-observability`](https://github.com/dymurray/tackle2-hub/tree/agentic-observability) | Custom hub build (only needed for the custom UI pairing; the stock 8.3.x hub has the agentic API) |
| [dymurray/tackle2-addon-discovery](https://github.com/dymurray/tackle2-addon-discovery/tree/language-weight-threshold) | [`language-weight-threshold`](https://github.com/dymurray/tackle2-addon-discovery/tree/language-weight-threshold) → [PR konveyor/tackle2-addon-discovery#48](https://github.com/konveyor/tackle2-addon-discovery/pull/48) | Discovery language-weight fix |
| [dymurray/agentic-controller](https://github.com/dymurray/agentic-controller/tree/harness-push-url) | [`harness-push-url`](https://github.com/dymurray/agentic-controller/tree/harness-push-url) | Harness that runs inside AgentRun pods (adds `HARNESS_PUSH_URL`; built into the agent image) |

---

## 1. How the system works

### 1.1 The flow

```
 MTA UI ──add app──▶ Hub ──discovery pipeline──▶ language → tech → sbom-discovery (addon)
                                                                     │ CycloneDX SBOM
                                                                     ▼
  Red Hat CSAF / GitHub OSV / Go vulndb / CVE importers ──▶ RHTPA 3.1 (trustify) ◀── POST /api/v3/sbom
                                                   ▲  GET /api/v3/sbom/{id}/advisory
                                                   │
                 ┌─────────────────┬───────────────┤
                 │                 │               │
        cve-watcher (30s)   jira-watcher (60s)  nightly-refresh (02:00 UTC CronJob)
                 │ new CVEs → fact cve:<id> each + one Task per affected dependency
                 ▼
        cve-remediation (addon pod per affected dependency)
          1. enrich from RHTPA (severity, advisories, fixed versions);
             pick the lowest version that fixes every CVE in the dependency
          2. rgctl vuln analyze on the advisory's OSV doc (+ method catalog)
             → verdict, call sites, taint paths, OpenVEX
             vulnerable methods never called → NotAffected, stop
          3. bump dependency → build/test
             ├─ passes → push konveyor/<cve>-fix-<timestamp> branch   (auto-bump)
             └─ fails  → AgentRun cve-remediator-<lang>               (agentic)
                          (rgctl + cve-remediation skills, LLM via Gateway)
 MTA UI ◀── application drawer "Vulnerabilities" tab reads facts cve: / rhtpa:sbom
```

### 1.2 CVE sources (three)

1. **RHTPA advisories** — `cve-watcher` (Deployment) polls RHTPA every 30s per app SBOM.
2. **JIRA prodsec tickets** — `jira-watcher` (Deployment) finds open tickets in the MTA
   JIRA project by `pscomponent` label, maps the image to source repositories via the
   `cve-component-map` hub fact (seeded from the `cve-component-map` ConfigMap), ensures
   them as MTA applications, and dispatches the same `cve-remediation` tasks. Ticket
   title suffix `[stream]` selects branch/fixVersion/owner per stream; dead ends assign
   the ticket to the stream owner. Falls back to api.osv.dev when RHTPA doesn't know a CVE.
3. **Nightly refresh** — CronJob re-submits `sbom-discovery` for archetype members whose
   default-branch HEAD moved, retries failed findings (max 3 attempts, then `Exhausted`),
   and tracks PRs.

### 1.3 Components (all under `bridge/` in this repo)

| Path | What |
|---|---|
| `cmd/sbom-discovery` | Discovery addon (Task CR `konveyor.io/discovery: sbom`, priority 2). CycloneDX Maven plugin, syft for Go/Python, cleanup (purl subpaths, Go `v` prefix), POSTs the SBOM to RHTPA, writes fact `rhtpa:sbom`. |
| `cmd/cve-watcher` | Polls RHTPA per app SBOM, dedupes CVEs by affected package, dispatches one `cve-remediation` task per dependency, resolves findings, tracks AgentRun phase, submits PR tasks for agent branches. Env: `DRY_RUN`. |
| `cmd/jira-watcher` | Second CVE source from JIRA (see above). Env: `JIRA_POLL`, `DRY_RUN`, `JIRA_AUTOCLOSE_TRANSITION`, … |
| `cmd/cve-remediation` | The worker: enrich → rgctl reachability → classify → auto-bump or AgentRun (via hub `/hub/agentic/agentruns`) → commit/branch/PR. |
| `cmd/nightly-refresh` | Nightly SBOM refresh + finding reset (`reset --app <id> --cve <CVE-ID>`). |
| `internal/agentic` | AgentRun creation/inspection through the hub API (payload contract; see the companion doc). |
| `internal/osv` | OSV preparation (RHTPA download, `catalog.yaml` method merge, synthesis) and rgctl verdict interpretation. |
| `internal/finding` | The `Finding` schema stored in facts `cve:<CVE-ID>`. |
| `images/agent-cve` | Agent image: `quay.io/dymurray/agent-migiq` runtime + JDK 21 + Maven + Go 1.26 + Python 3 (pip/uv/Poetry/pytest) + rgctl 0.4.21 + bazelisk. |
| `images/skills` | `FROM scratch` image holding the vendored rgctl skill. |
| `deploy/rhtpa` | RHTPA install (RHBK realm, PostgreSQL, Helm values, importers). |
| `deploy/mta` | Task/Addon CRs, watcher Deployments, Agents/SkillCards/Gateway, ConfigMap component map, nightly CronJob. |
| `deploy/networkpolicy.yaml` | Egress the operator's `mta-egress` blocks (internal registry :5000, RHTPA, JIRA/OSV 443). |
| `third_party/hub-shared` | Hub SDK vendored from `migtools/mta-tackle2-hub@release-0.11` (MTA 8.3.x). |

### 1.4 Key runtime contracts

- **Facts are the backend/UI contract.** `rhtpa:sbom` (SBOM id, package count, console
  URL) and one `cve:<CVE-ID>` fact per finding (`internal/finding` schema: severity,
  verdict, OpenVEX, strategy, status, PR/branch/AgentRun links, JIRA key, group).
- **`bridge:component-map`** on the marker application `cve-remediation-config` is the
  writable source of truth for the JIRA source's product/stream/image map; the ConfigMap
  only seeds it. The UI's CVE config panel (scope `applications.facts:put`) edits it.
- **Archetype gate.** Everything is scoped to applications in archetype `konveyor-cves`
  (`CVE_ARCHETYPE`); non-members are no-ops.
- **AgentRuns are created through the hub API** (not the k8s API) so the hub mints the
  scoped `HUB_TOKEN` the harness needs. The hub's agents/workflows list endpoints filter
  on label `konveyor.io/managed=true` — every bridge-deployed Agent/Workflow CR carries it
  (this is why they appear in the UI).
- **Escalation policy.** An agent runs only when the dependency update causes *new*
  build/test failures (baseline-compared). Update failures and pre-existing failures
  don't escalate.
- **Commits/PRs.** One commit per remediation with the report in the commit message, DCO
  `Signed-off-by`, branch `konveyor/<cve>-fix-<UTC timestamp>`, PR opened with the app's
  GitHub identity; Konveyor repos use verify-pr gitmoji titles.

### 1.5 Demo repositories

| Repo | Contents |
|---|---|
| `dymurray/mta-cve-demo` | Java: commons-text 1.9 (auto-bump), snakeyaml 1.33 (agent — API break) |
| `dymurray/mta-cve-demo-go` | Go: x/text v0.3.7 (auto-bump), golang-jwt/jwt v3 (agent — major migration) |

---

## 2. Provisioning a new environment

All scripts live in `bridge/hack/` and read `bridge/hack/env.sh`. Defaults: the
ambient `KUBECONFIG` (override `KUBECONFIG_DYLAN`), context `admin` (override
`KCTX`), namespace `openshift-mta` (`MTA_NS`), RHTPA namespace
`trusted-profile-analyzer` (`TPA_NS`). Generated credentials go into the gitignored,
mode-600 `bridge/.secrets.env` (auto-created on first run).

### 2.1 Prerequisites

- OpenShift 4.x cluster, `oc` logged in as cluster admin, `helm` (Homebrew) on PATH.
- The cluster must be **amd64** (in-cluster image builds; the workstation may be arm64).
- A GitHub personal access token (push rights to your forks) — for app source credentials.
- A JIRA API token + email (for the JIRA CVE source; optional).
- An LLM API key for the agent Gateway (e.g. Anthropic-compatible endpoint).

The bridge is vendored in this repo as `bridge/` (a snapshot of
[dymurray/mta-rhtpa-bridge@`jira-cve-source`](https://github.com/dymurray/mta-rhtpa-bridge/tree/jira-cve-source)).
All `hack/...` paths below are under `bridge/`. Everything in §2 is automated by the
top-level [`install-mta.sh`](install-mta.sh); this section is what it does, step by
step. All scripts read `bridge/hack/env.sh`:

```bash
git clone https://github.com/dymurray/mta-cve.git && cd mta-cve
source bridge/hack/env.sh     # creates bridge/.secrets.env on first run
```

### 2.2 Install MTA (the platform)

The demo cluster runs the internal ART MTA operator (CSV `mta-operator.v8.3.4`,
`agentic_enabled: true`). For a new environment, install the **Migration Toolkit for
Applications Operator** from OperatorHub (public 8.3.x) and create the Tackle CR:

```bash
oc new-project openshift-mta
oc apply -f - <<'EOF'
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: mta-operator
  namespace: openshift-mta
spec:
  channel: "8.3"                # picks the latest 8.3.x (e.g. 8.3.3)
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
  agentic_enabled: true          # hub /hub/agentic API + agentic-controller
EOF
```

`agentic_enabled: true` deploys the `agentic-controller` (which reconciles
`AgentRun`/`Agent`/`Gateway` CRs) and enables the hub's `/hub/agentic` routes.
Wait for the hub: `oc -n openshift-mta rollout status deploy/mta-hub`.

### 2.3 Install RHTPA (the vulnerability source)

```bash
bridge/hack/install-rhtpa.sh
```

Installs the RHBK operator + Keycloak realm `trustify`, PostgreSQL, and Helm chart
`redhat-trusted-profile-analyzer` 3.1.1 with the importers from
`deploy/rhtpa/values-importers.yaml` (`redhat-csaf` hourly limited to demo patterns —
remove `onlyPatterns` for the full feed; `osv-github`; added `go-vulndb`; `cve`).
Credentials land in `.secrets.env`.

Known chart gotcha (handled by the script): with `storage.type: filesystem` the chart's
migrate hook mounts PVC `storage` before Helm creates it — pre-create the PVC with Helm
ownership metadata.

### 2.4 Images

By default the custom images are pulled prebuilt from `quay.io/dymurray`
(`mta-rhtpa-bridge`, `agent-cve`, `mta-cve-skills`, `mta-ui-cve`) — the deploy
manifests under `deploy/mta/` reference them directly, so nothing is built
on-cluster. `install-mta.sh` step 3 only patches the Tackle CR `ui_image_fqin`
to the quay UI image. `IMAGE_REPO` (default `quay.io/dymurray`, set in
`hack/env.sh`) selects the registry; `setup-mta.sh` rewrites the manifests
through it at apply time.

To build from source instead, run `install-mta.sh` with `BUILD_IMAGES=1` (which
sets `IMAGE_REPO` to the internal registry) or run the build scripts directly:

```bash
bridge/hack/build.sh         # mta-rhtpa-bridge: sbom-discovery, cve-remediation, cve-watcher, jira-watcher, nightly-refresh
bridge/hack/build-agent.sh   # agent-cve: harness + JDK/Maven/Go/Python/rgctl/bazelisk
bridge/hack/build-ui.sh      # mta-ui-cve: custom UI, pins the Tackle CR by digest
```

Each creates an ImageStream + BuildConfig in `openshift-mta` and tags the result.
`bridge/hack/build-ui.sh` also sets `ui_image_fqin` on the Tackle CR (and the deployment
directly if the operator is scaled to 0). To revert to the stock UI, remove
`ui_image_fqin`. Skills image: `bridge/hack/vendor-rgctl-skill.sh <tag>` refreshes
`images/skills` (rgctl skill @ v0.4.21, frontmatter fixed).

### 2.5 Wire the bridge into MTA

1. Create a hub service account with the architect role and mint a token (the addon
   role cannot create AgentRuns):

   ```bash
   bridge/hack/mint-hub-token.sh
   ```

   It port-forwards the hub, creates (or reuses) service account `rhtpa.cve-bridge`,
   mints a token, and saves `HUB_BRIDGE_TOKEN` into `bridge/.secrets.env`. The manual
   equivalent is `bridge/hack/hub.sh` (`POST /serviceaccounts`, then
   `POST /serviceaccounts/<id>/tokens`).

2. Add the other credentials to `bridge/.secrets.env`: `JIRA_URL`/`JIRA_EMAIL`/`JIRA_TOKEN`
   (Atlassian API token) and `LLM_API_KEY` (the key for the agents' LLM endpoint,
   referenced by `deploy/mta/05-gateway.yaml`). A GitHub token is needed later for the
   applications' source credentials.

3. Run the wiring:

   ```bash
   bridge/hack/setup-mta.sh
   ```

   Creates: secrets (`rhtpa-bridge`, `hub-bridge-token`, `jira-credentials`,
   `enmaas-key`), the `mta-rhtpa-bridge-egress` NetworkPolicy, and applies
   `deploy/mta/`:

   | Manifest | Creates |
   |---|---|
   | `10-tasks-addons.yaml` | Task/Addon CRs `sbom-discovery` + `cve-remediation` |
   | `20-watcher.yaml` | Deployment `cve-watcher` |
   | `30-agent.yaml` | SkillCards `rgctl-osv`, `cve-remediation`; Gateway; Agents `cve-remediator-{java,go,python}` (all labeled `konveyor.io/managed: "true"` so the UI lists them) |
   | `40-nightly-refresh.yaml` | CronJob `nightly-refresh` |
   | `50-jira-watcher.yaml` | Deployment `jira-watcher` |
   | `51-component-map.yaml` | ConfigMap `cve-component-map` (seeds the `bridge:component-map` fact) |
   | `52-migiq.yaml` | migiq agents + `migiq-migration-multistage` workflow + skills |

   The Gateway CR points the agents at your LLM:

   ```yaml
   apiVersion: konveyor.io/v1alpha1
   kind: Gateway
   metadata: {name: enmaas, namespace: openshift-mta}
   spec:
     provider: anthropic                    # or openai-compatible
     endpoint: https://api.enmaas.devshift.net
     model: {name: claude-sonnet-4-6, contextWindow: 200000}
     credentialRef: {secretName: enmaas-key, key: api-key}
   ```

4. The watchers start with `DRY_RUN=true`. Watch the logs until the decisions look
   right, then flip:

   ```bash
   oc -n openshift-mta set env deploy/cve-watcher DRY_RUN=false
   oc -n openshift-mta set env deploy/jira-watcher DRY_RUN=false
   ```

### 2.6 Resource tuning (small clusters)

If task pods sit `Pending` (Insufficient cpu/memory), lower the *requests* on the
Extension/Addon CRs (overcommit-safe; actual usage is 12–28%):

```bash
oc -n openshift-mta patch extension python --type merge -p \
  '{"spec":{"container":{"requests":{"cpu":"100m","memory":"256Mi"}}}}'
# same for go / nodejs (256Mi), java (512Mi), addon/analyzer (256Mi)
oc -n openshift-mta delete pod <pending-task-pod>   # hub recreates it with new values
```

Note: if the MTA operator is scaled to 0 (as on the demo cluster), patch the CRs
directly — the hub watches them live. If it runs, keep the values in the Tackle CR.

### 2.7 Run the demo

1. In the MTA UI, create an application with repository
   `https://github.com/dymurray/mta-cve-demo.git` (plus the git source credential),
   and tag it into the `konveyor-cves` archetype.
2. Discovery runs language → tech → **sbom-discovery**; the SBOM appears in the RHTPA
   console.
3. Within ~30s the watcher dispatches: commons-text auto-bumps (branch
   `konveyor/cve-2022-42889-fix-<ts>`); snakeyaml breaks the build, so AgentRun
   `cve-<app>-2022-1471-t<task>` rewrites the call sites and pushes its own branch.
   The app drawer's **Vulnerabilities** tab shows findings, reachability, OpenVEX,
   PR/AgentRun/JIRA links.
4. Go demo: add `dymurray/mta-cve-demo-go.git` the same way.
5. Live publication: `bridge/hack/publish-advisory.sh` (uploads GHSA-j288-q9x7-2f5v,
   CVE-2025-48924 commons-lang3 — fixed via `dependencyManagement` override).
6. Start over: `bridge/hack/reset-demo.sh <app-id> [owner/repo]`.

### 2.8 Day-2 operations

```bash
# manual nightly refresh
kubectl -n openshift-mta create job nightly-manual-$(date +%s) --from=cronjob/nightly-refresh

# reset one finding (retried after the next nightly refresh)
kubectl -n openshift-mta run reset-$(date +%s) --rm -i --restart=Never \
  --image=quay.io/dymurray/mta-rhtpa-bridge:latest \
  --overrides='{"spec":{"containers":[{"name":"reset","image":"quay.io/dymurray/mta-rhtpa-bridge:latest","command":["/usr/bin/nightly-refresh","reset","--app","<app>","--cve","<CVE-ID>"],"envFrom":[{"secretRef":{"name":"hub-bridge-token"}}],"env":[{"name":"HUB_BASE_URL","value":"http://mta-hub.openshift-mta.svc:8080"}]}]}}'

# watcher dry run
kubectl -n openshift-mta set env deploy/cve-watcher DRY_RUN=true|false
```

Status model per finding: `PullRequestOpen` → `Remediated` (CVE gone from latest SBOM)
/ `PullRequestClosed` / `Exhausted` (3 failed attempts) / `NeedsAttention`
(`noFix`, hash-pinned requirements, update failures). Reachability verdicts
(`exploitable`/`reachable`/`unreachable`/`unknown`) come from `rgctl vuln analyze`
with `internal/osv/catalog.yaml` supplying method-level data that advisories omit.

### 2.9 Teardown

```bash
kubectl -n openshift-mta delete -f bridge/deploy/mta/ -f bridge/deploy/networkpolicy.yaml
# + the secrets and BuildConfigs/ImageStreams created by bridge/hack/setup-mta.sh and hack/build*.sh
helm uninstall redhat-trusted-profile-analyzer -n trusted-profile-analyzer
oc delete namespace trusted-profile-analyzer
# hub: delete service account rhtpa.cve-bridge (and optionally apps/facts/tags); remove
# ui_image_fqin and the provider_*_requests_cpu fields from the Tackle CR
```

### 2.10 Known gotchas

- The hub `addon` role cannot create AgentRuns — hence the architect-grade
  `hub-bridge-token`.
- The operator's `mta-egress` NetworkPolicy blocks registry pushes (:5000) and
  Keycloak (:8080); `deploy/networkpolicy.yaml` reopens both (plus 443 for JIRA/OSV).
- rgctl release binaries need glibc ≥ 2.39 → RHEL10/UBI10 images for the bridge and
  agent (the stock RHEL9 Java agent image can't run rgctl).
- Alizer tags sparse repos with stray fixture languages (2% threshold) — fixed upstream
  in konveyor/tackle2-addon-discovery#48 (10% weight floor, `MIN_LANGUAGE_WEIGHT` env).
- kai `release-0.10` has no root `pyproject.toml` → the analyzer provider fails with
  "unable to get build tool"; use a tagged ref (≤ v0.9.0).
