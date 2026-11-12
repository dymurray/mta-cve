# Deployment customizations: RHTPA ⇄ MTA CVE remediation environment

Everything changed on the **dylan** cluster (`~/Downloads/kubeconfig-dylan`, context `admin`,
OCP 4.22 single node) to run the CVE remediation demo, compared with a stock MTA 8.3.2 install.
Snapshot taken 2026-11-02. Source for everything below is in `~/git/mta-rhtpa-bridge`, unless noted.

> **The MTA operator is scaled to 0** (`deploy/mta-operator`, turned off by the cluster owner).
> Several changes below were made directly to CRs/Deployments. If the operator runs again it will
> revert anything not also set in the Tackle CR (marked ⚠ below).

---

## 1. Red Hat Trusted Profile Analyzer (new install)

Namespace **`trusted-profile-analyzer`**, installed with `hack/install-rhtpa.sh`. It follows the RHTPA
deployment guide's "Helm with Red Hat services" path.

| Item | Customization |
|---|---|
| Helm release | `redhat-trusted-profile-analyzer`, chart `openshift-helm-charts/redhat-trusted-profile-analyzer` **3.1.1** (API is `/api/v3`) |
| OIDC | RHBK operator (`rhbk-operator`, channel stable-v26.6), Keycloak CR `sso` (edge Route), realm import `trustify` with clients `frontend` and `cli`, document scopes, admin user |
| Database | `postgresql` Deployment (rhel9/postgresql-16), shared by RHTPA and Keycloak |
| Storage | **filesystem** (32Gi PVC) instead of ODF S3; PVC `storage` pre-created to work around a chart hook-ordering bug |
| TLS | Ingress router CA mounted as `rhtpa-trust-anchor` (the router certificate is self-signed) |
| Resources | server/importer requests lowered to 500m / 3Gi; importer concurrency 3 |
| URLs | Console `https://server-trusted-profile-analyzer.apps.dylan.mg.dog8code.com`; SSO `https://sso-trusted-profile-analyzer.apps.dylan.mg.dog8code.com` |
| Credentials | Generated into `.secrets.env` (gitignored): admin password, `cli` client secret, DB passwords |

**Importers** (`deploy/rhtpa/values-importers.yaml`):

| Importer | Setting |
|---|---|
| `redhat-csaf` | **Enabled**, hourly, `onlyPatterns: ["/2026/", "cve-2022-1471", "cve-2022-42889"]` (remove the patterns for the full Red Hat feed) |
| `osv-github` | Enabled, hourly, `advisories/github-reviewed`, **no year filter** |
| `go-vulndb` | **Added**: `github.com/golang/vulndb` `data/osv`, hourly (Go module records and `golang.org/x/*` advisories) |
| `cve` | Enabled, daily, years 2022 and 2026 (metadata only) |
| `redhat-sboms`, `quay-redhat-user-workloads` | Disabled |

---

## 2. MTA (namespace `openshift-mta`)

### 2.1 Tackle CR (`tackle/mta`)
| Field | Value | Why |
|---|---|---|
| `ui_image_fqin` | `…/openshift-mta/mta-ui-cve@sha256:…` | Custom UI with the Vulnerabilities tab |
| `provider_java_container_requests_cpu` | `500m` | Lets Java+Go tech-discovery pods schedule (was 1) |
| `provider_go_container_requests_cpu` | `500m` | Same (was 1) |
| annotation `mta-rhtpa-bridge/reconcile` | timestamp | Used once to nudge a reconcile; safe to remove |

### 2.2 Directly modified MTA resources
| Resource | Change |
|---|---|
| `deploy/mta-ui` | Image set directly to the `mta-ui-cve` digest (operator off) |
| `extension/java`, `extension/go` | CPU request **500m** (limit stays at 1) ⚠ also in the Tackle CR |
| `extension/csharp`, `extension/nodejs`, `extension/python`, `addon/analyzer` | Reverted to operator defaults by the operator run; no changes in effect |

### 2.3 New resources added to MTA
| Resource | Purpose |
|---|---|
| `Task sbom-discovery` (label `konveyor.io/discovery: sbom`, priority 2) and `Addon sbom-discovery` | Discovery step: builds a CycloneDX SBOM and imports it into RHTPA (fact `rhtpa:sbom`) |
| `Task cve-remediation` and `Addon cve-remediation` | Per-CVE remediation (requests 500m/1500Mi, limits 2 CPU/3Gi). Env: `CVE_AGENT`, `CVE_AGENT_GO`, `GO_MAJOR_UPGRADE=newest`, `GIT_USER_NAME=Dylan Murray`, `GIT_USER_EMAIL=dymurray@redhat.com` (`GITMOJI_ORGS` defaults to `konveyor`) |
| `Deployment cve-watcher` | Archetype-scoped (`konveyor-cves`), policy-driven dispatch (`internal/policy`): new and returning CVEs any time; failed attempts retried once per nightly refresh, max 3, then `Exhausted`. Polls RHTPA every 30s, tracks AgentRuns, requests PRs for agent branches. `strategy: Recreate`; env `DRY_RUN` |
| `CronJob nightly-refresh` | 02:00 UTC, `concurrencyPolicy: Forbid`, binary `nightly-refresh` (`deploy/mta/40-nightly-refresh.yaml`). Creates `sbom-discovery` tasks with data `{"nightly":true}` for `konveyor-cves` archetype members whose default-branch HEAD moved; skipped apps get `NightlyAt` set |
| Env `CVE_ARCHETYPE=konveyor-cves` | Set on `cve-watcher`, `Addon sbom-discovery`, `Addon cve-remediation` and the CronJob |
| `Agent cve-remediator-java`, `Agent cve-remediator-go` | Gateway `enmaas`; image `agent-cve`; `gitConfig: Dylan Murray <dymurray@redhat.com>`; skills below |
| `SkillCard cve-remediation` (inline, v2.3.0) | Remediation procedure: DCO (`git commit -s`), report in the commit message (no report files), Konveyor gitmoji subjects, PRs opened automatically |
| `SkillCard rgctl-osv` | rgctl v0.4.21 `skills/rgctl` (OSV/OpenVEX workflow), served from the `mta-cve-skills` image with the frontmatter fixed (upstream `rgctl-managed` field rejected by the skill loader) |
| `Secret rhtpa-bridge` | RHTPA URL, token URL, `cli` client credentials, service CA path |
| `Secret hub-bridge-token` | API token for Hub service account **`rhtpa.cve-bridge`** (id 1001, role architect); needed because the addon role cannot create AgentRuns |
| `NetworkPolicy mta-rhtpa-bridge-egress` | Allows egress to the internal registry (5000) and to RHTPA (8080/8443/443); the operator's `mta-egress` blocks these |
| ImageStreams and BuildConfigs: `mta-rhtpa-bridge`, `agent-cve`, `mta-ui-cve`, `mta-cve-skills` | In-cluster image builds (the cluster is amd64; the workstation is arm64) |

### 2.4 Cleanup performed
- Deleted the Sandbox objects of 11 finished AgentRuns, which kept re-creating pods. The AgentRuns themselves were kept.
  New runs leave sandboxes behind again; clean them up the same way when needed.

---

## 3. Custom images (internal registry, `openshift-mta`)

| Image | Contents | Build |
|---|---|---|
| `mta-rhtpa-bridge` | UBI10 + OpenJDK 21 + Maven 3.9 + Go 1.26 + syft 1.18.1 + rgctl 0.4.21 (checksum-verified), plus binaries `sbom-discovery`, `cve-remediation`, `cve-watcher`, `nightly-refresh` | `hack/build.sh` |
| `agent-cve` | `quay.io/dymurray/agent-migiq` (RHEL10 goose harness) + JDK 21 + Maven + Go + rgctl 0.4.21 | `hack/build-agent.sh` |
| `mta-ui-cve` | `migtools/mta-tackle2-ui@release-0.11` + Vulnerabilities tab (worktree `~/git/mta-tackle2-ui-cve`, branch `rhtpa-cve-tab`) | `hack/build-ui.sh` (pins the digest; sets the deployment directly when the operator is at 0) |
| `mta-cve-skills` | `FROM scratch` with the vendored rgctl skill | `images/skills` (`hack/vendor-rgctl-skill.sh <tag>` to refresh) |

The Hub SDK is vendored from `migtools/mta-tackle2-hub@release-0.11` into `third_party/hub-shared`.

---

## 4. Remediation behavior (what the custom code does)

- **SBOM:** Maven projects use the CycloneDX Maven plugin. Go and other projects use syft, then cleanup:
  - duplicates are removed and the guessed Go stdlib entry is dropped
  - `#vN` purl subpaths are moved into the module name
  - Go versions lose the leading `v`, to work around RHTPA strict-semver matching
  - the root component is named after the app
- **Reachability:** `rgctl vuln analyze` on the advisory's OSV document, enriched from `internal/osv/catalog.yaml` method data. This produces the verdict, call sites, taint paths, and OpenVEX.
  - Findings close as **Not affected** (no code changes) only for Maven, when method data is known and nothing calls it.
  - Go is always "unknown", because rgctl 0.4.21 doesn't record calls into external packages.
- **Fix:**
  - **Bump:** Maven updates `pom.xml` (a property, an inline version, or a `dependencyManagement` override). Go runs `go get` and `go mod tidy`; when the fix is only in a new major version (`/vN`), it rewrites imports first.
  - **Nested Go modules:** every `go.mod` in the clone is discovered (skipping `vendor`, `testdata`, `node_modules`, dot dirs). Only the modules that require the vulnerable version are bumped and built, e.g. tackle2-hub `shared/go.mod`.
  - **Guards (no garbage output):** the finding becomes *Needs attention* and nothing is pushed when:
    - the vulnerable version isn't required by any `go.mod`;
    - the update changes no files;
    - a selected `go.mod` still requires the old version afterwards (or no longer requires the module at all, or disappeared);
    - a `replace` directive overrides the fix.
    Commits are refused when the diff against HEAD is empty, so the hub SDK's `--allow-empty` is never reached. A PR is opened only when GitHub's compare shows changed files, including `go.mod` or `pom.xml`; otherwise the finding is *Failed*. Regression tests: `cmd/cve-remediation/pipeline_test.go` (real git, file `GOPROXY`, `assertNoGarbage`). Background: konveyor/tackle2-hub#1176.
  - **Not covered yet:** Maven multi-module projects where a child pom pins the version; Go repos where modules pin *different* vulnerable versions, or a sibling module needs re-tidying.
  - **Build:** `mvn clean verify`, or `go build` + `go test` (in each bumped module).
  - **Compare:** if the build fails, it's compared with a baseline build. Only **new** failures escalate to an AgentRun.
  - **Update failures:** `go get`/`go mod tidy` failures are marked *Needs attention* (no agent).
  - **Module path:** the Go module path is spelled as in `go.mod` (RHTPA lowercases purls).
- **Commits and PRs:**
  - One commit with the summarized report in its message, authored as `Dylan Murray <dymurray@redhat.com>`, with a DCO `Signed-off-by`.
  - Branch `konveyor/<cve>-fix-<UTC timestamp>`.
  - A PR opened with the app's GitHub token: scripted fixes right after the push, agent fixes via a watcher-submitted `action: pull-request` task.
  - Konveyor repos use verify-pr gitmoji titles (`:bug: Upgrade … (CVE-…)`). Other repos use `fix(CVE-…): …`.
- **UI:** the application drawer's **Vulnerabilities** tab shows SBOM status, findings, severity, rgctl reachability and OpenVEX (copy/download), fix strategy and status, branch/PR/AgentRun/task links, and build errors.
- **Nightly refresh and retries:**
  - **Statuses:** new `PullRequestOpen` (fix pushed, PR open or branch only), `PullRequestClosed` (PR closed unmerged; no retry) and `Exhausted` (3 failed attempts). `Remediated` now means the CVE is gone from the latest SBOM, not "branch pushed".
  - **Attempts:** `attempts` counts remediation tasks per CVE, `MaxAttempts` 3. Failed findings are retried once per nightly refresh, never in daytime polls; then `Exhausted`. A returning `Remediated` CVE resets attempts.
  - **No fix published:** not counted as an attempt; re-dispatched only when RHTPA's fixed versions change.
  - **Mass-resolve hold:** if a new SBOM would resolve every open finding of an app at once, the watcher waits one more poll to confirm.
  - **Migration:** one-off, before any dispatch: `Remediated` with PR URL or branch becomes `PullRequestOpen`; failed findings get `attempts = 1`.
  - **Archetype gate:** both addons check membership first; for non-members the task succeeds as a no-op (no facts, no tags).
  - **Manual reset:** sets status `Failed`, attempts 0; retried after the next nightly refresh. Works on `Exhausted` and `PullRequestClosed`. See README "Nightly refresh" (`nightly-refresh reset --app <app> --cve <CVE-ID>`).

Findings are stored as application facts: `rhtpa:sbom`, `cve:<CVE-ID>`.

---

## 5. External changes (outside the cluster)

| Item | Detail |
|---|---|
| GitHub repo `dymurray/mta-cve-demo` | Java demo app (commons-text 1.9, snakeyaml 1.33) |
| GitHub repo `dymurray/mta-cve-demo-go` | Go demo app (x/text v0.3.7, golang-jwt/jwt v3) |
| Remediation branches and PRs | Pushed to the inventory apps' repos, including upstream `konveyor/tackle2-hub` |
| Local tooling | `helm` installed via Homebrew |

---

## 6. Known upstream issues found (worth reporting)

| Project | Issue |
|---|---|
| RHTPA / trustify | OSV `SEMVER` ranges don't match `v`-prefixed Go versions; records without a CVE ID never become vulnerabilities; Go purls are lowercased |
| RHTPA Helm chart 3.1.1 | `storage.type: filesystem` migrate hook mounts a PVC that doesn't exist yet |
| rgctl 0.4.21 | Skill frontmatter field `rgctl-managed` isn't spec-compliant; no call graph into external Go packages; `vuln analyze` reports `not_affected` when the advisory lists no affected methods |
| syft | Go major-version modules written as a purl subpath (`#v4`) |
| alizer / tackle2-addon-discovery | Top-level language detection counts test fixtures (2% threshold) and takes `pom.xml` from any depth, so kantra is tagged Java/Maven/Spring |
| analyzer (java provider) | No root build tool makes provider init fail and fails the whole analysis |

## 7. Reverting

- **MTA:** delete the resources in §2.3, including the nightly job (`kubectl -n openshift-mta delete cronjob nightly-refresh`) (`kubectl delete -f deploy/mta/ -f deploy/networkpolicy.yaml`, the secrets, the build resources). Remove `ui_image_fqin` and the two `provider_*_requests_cpu` fields from the Tackle CR, then scale the operator back up so it restores the defaults (UI image, extensions, analyzer).
- **Hub:** delete service account `rhtpa.cve-bridge`, and optionally the inventory apps, facts and tags.
- **RHTPA:** `helm uninstall redhat-trusted-profile-analyzer -n trusted-profile-analyzer`, then delete the namespace (this removes RHBK, Keycloak and PostgreSQL).

## 8. JIRA CVE source (jira-watcher)

Prodsec CVE tickets in JIRA (project `MTA`, found by their `pscomponent`
label, whose value names the affected product image) are a second CVE source
besides RHTPA. The `jira-watcher` deployment maps each image to source
repositories, ensures them as MTA applications (tagged into the
`konveyor-cves` archetype), and dispatches the same `cve-remediation` tasks
the RHTPA flow drives. Full design:
`docs/superpowers/specs/2026-11-06-jira-cve-source-design.md`.

| Item | Detail |
|---|---|
| Deployment | `deploy/mta/50-jira-watcher.yaml` (image `mta-rhtpa-bridge`, command `/usr/bin/jira-watcher`) |
| Product/stream/image map | ConfigMap `cve-component-map` (`deploy/mta/51-component-map.yaml`), mounted at `/etc/jira-watch/image-map.yaml`, re-read every poll; per-product `products:` config (`jiraProject`, `owner`, `mainBranch`, `streams`, `images`) |
| Credentials | Secret `jira-credentials` (`JIRA_URL`/`JIRA_EMAIL`/`JIRA_TOKEN` in `.secrets.env`, an Atlassian API token), created by `hack/setup-mta.sh` |
| Egress | `deploy/networkpolicy.yaml` opens 443 to any destination (JIRA Cloud + api.osv.dev; NetworkPolicy cannot match DNS names) |
| Env knobs | `JIRA_POLL` (60s), `MTA_UI_URL`, `JIRA_AUTOCLOSE_TRANSITION` (unset = never auto-close), `JIRA_TAG_CATEGORY`/`JIRA_TAG_NAME` (archetype criteria tag), `DRY_RUN` |

Behavior:

- **Ticket -> work:** every open ticket with a mapped `pscomponent` label is
  searched per poll; its CVE ids are parsed from the description
  (`CVE-\d{4}-\d{4,}`). Unmapped images and CVE-less tickets get a one-time
  JIRA comment saying nothing will be analyzed.
- **Streams, owners and main:** each product maps release streams (the
  trailing `[stream]` of the ticket summary) to a branch, fixVersion and
  owner. Applications are named `<repo>-<branch>`. When a stream finding is
  first created the watcher adds the stream's fixVersion to the ticket
  (existing versions kept, never re-appended afterwards). Dead ends
  (unmapped image, unknown stream, no CVE, failed SBOM) and findings that need
  attention or failed assign the ticket to the stream (else product) owner,
  once, together with the comment that reports them. After a stream finding
  has a verdict naming a package, the same remediation is dispatched on the
  main branch only if main's SBOM contains that package (an SBOM without
  purls counts as unknown and waits); main findings only comment. DRY_RUN
  suppresses all of these writes. `JIRA_JQL_PREFIX` is still honored as an
  extra filter ANDed into each product's search.
- **Sliding remediation scale** (per image, `remediation:` in the map):
  `report` (triage only, finding ends needs-attention), `script`
  (renovate-style bump, never escalates to an agent), `agent` (default:
  bump, escalating to an AgentRun when the build breaks).
- **Findings** carry `source: jira`, `jiraKey`, `component` and
  `remediationMode` (schema 2). The `cve-watcher` never dispatches, resolves
  or mass-resolves JIRA-sourced findings; on a dual-source collision the
  JIRA finding wins.
- **OSV.dev fallback:** when RHTPA's importers do not know a JIRA-reported
  CVE, the advisory is fetched from api.osv.dev so analysis and remediation
  still run.
- **Component not present:** when rgctl's deps check finds none of the
  vulnerable packages in the repo, the finding is closed not-affected
  ("not built from this repository") — and the ticket auto-closes when the
  image's map entry sets `autoClose: true`.
- **JIRA comments:** every finding state change is commented on the ticket
  (verdict, severity, OpenVEX, call sites, PR link, MTA UI link); tickets
  that are not auto-progressing say so explicitly.

Deploy: add the JIRA values to `.secrets.env`, then `hack/build.sh` and
`hack/setup-mta.sh`. The deployment starts with `DRY_RUN: "true"`; flip it
to `"false"` once the log shows the expected decisions. Revert: delete
`deploy/jira-watcher`, the `cve-component-map` ConfigMap, the
`jira-credentials` secret and the `0.0.0.0/0:443` egress rule.
