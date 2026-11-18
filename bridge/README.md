# MTA ⇄ Red Hat Trusted Profile Analyzer: CVE remediation demo

When you add an application to the MTA inventory, MTA builds an SBOM, imports it into
RHTPA, and watches RHTPA for vulnerabilities as advisories are published. Each CVE is
surfaced in the MTA UI with an rgctl OSV reachability analysis and OpenVEX statement, then remediated: by a scripted
dependency update when the fix is a drop-in, or by an AI agent (AgentRun) when the
library's API changed.

```
 MTA UI ──add app──▶ Hub ──discovery pipeline──▶ language → tech → sbom-discovery (addon)
                                                                     │ CycloneDX SBOM
                                                                     ▼
  Red Hat CSAF / GitHub OSV / CVE importers ──▶ RHTPA 3.1 (trustify) ◀── POST /api/v3/sbom
                                                   ▲  GET /api/v3/sbom/{id}/advisory
                                                   │
                                     cve-watcher (Deployment, polls every 30s)
                                                   │ new CVEs → fact cve:<id> each + one Task per dependency
                                                   ▼
                                     cve-remediation (addon pod per affected dependency)
                                       1. enrich from RHTPA (severity, advisories, fixed versions);
                                          pick the lowest version that fixes every CVE in the dependency
                                       2. rgctl vuln analyze on the advisory's OSV doc (+ method catalog)
                                          → verdict, call sites, taint paths, OpenVEX
                                          vulnerable methods never called → NotAffected, stop
                                       3. bump dependency → mvn clean verify
                                          ├─ passes → push konveyor/<cve>-fix-<timestamp> branch   (auto-bump)
                                          └─ fails  → AgentRun cve-remediator-java     (agentic)
                                                       (rgctl + cve-remediation skills)
 MTA UI  ◀── application drawer "Vulnerabilities" tab reads facts cve: / rhtpa:sbom
```

## Supported project types

| | Maven (Java) | Go modules | Python |
|---|---|---|---|
| Detected by | `pom.xml` | `go.mod` | `requirements*.txt` (also `requirements/*.txt`) or a `pyproject.toml` with a `[project]` table |
| SBOM | CycloneDX Maven plugin (full resolved tree) | syft on `go.mod`/`go.sum`, deduplicated, stdlib dropped | The lock file (`uv.lock`, `poetry.lock`) if there is one, else pip's dry-run resolution of the requirements and project (includes transitive packages); syft as a fallback |
| Update | `pom.xml` property, inline version, or `dependencyManagement` override | `go get mod@vX` + `go mod tidy` (+ `go mod vendor`, or `go work vendor` in a `go.work` workspace) | Rewrites the requirement wherever it's declared: `requirements*.txt`, `[project]` dependencies, optional dependencies and dependency groups. Pins stay pins, and ranges get a new lower bound. A transitive dependency gets a new `name>=X` requirement, or a `[tool.uv] constraint-dependencies` entry in uv projects. Then `uv lock --upgrade-package` / `poetry lock` |
| Fix applied? | `pom.xml` diff | Every selected `go.mod` requires the fix | The resolved version, from the lock or `pip install --dry-run --report`, must be at least the fix |
| Fix in a new major | n/a | Rewrites imports to `mod/vN` and requires it (`GO_MAJOR_UPGRADE=newest`, the default, or `lowest`) | n/a (PEP 440 ordering) |
| Verify | `mvn clean verify` | `go build ./...` + `go test ./...` | A fresh venv: `uv sync`, `poetry install` or `pip install -r … && pip install .`, then `pytest` (or byte-compile only when the repo has no tests) |
| Escalation agent | `cve-remediator-java` | `cve-remediator-go` | `cve-remediator-python` |
| rgctl reachability | Call sites + paths; can prove "not affected" | rgctl 0.4.21 doesn't record calls into external Go packages, so Go results are always **unknown** (never auto-closed) | Reported as **unknown** (never auto-closed), like Go |

**Repositories with their own dependency procedure.** Some Go repositories commit Bazel BUILD
files in `vendor/` that gazelle generates; kubevirt is one. Re-vendoring with the go command
would delete them, so these repositories skip the scripted update and go straight to the
agent. The `cve-remediation` skill's "Repository dependency procedures" section covers
kubevirt's sequence: `hack/dep-update.sh -- <module>@<version>`, then
`KUBEVIRT_RUN_UNNESTED=true make bazel-generate`, then a check that no BUILD file of a
still-vendored package is deleted. The agent image includes bazelisk for this. Agents push to the
`GIT_FORK_OWNER` fork through the harness's `HARNESS_PUSH_URL` (agentic-controller branch
`harness-push-url`). `hack/build-agent.sh` builds that harness into the agent image.

Hash-pinned requirements (`--hash`) aren't edited. They go to NeedsAttention, because they need
regenerating with `pip-compile`. Poetry-native `[tool.poetry.dependencies]` and Pipenv are not supported.

All agents use `images/agent-cve` (agent-migiq runtime + JDK 21 + Maven + Go 1.26 + Python 3 with
pip/uv/Poetry/pytest + rgctl) and the same `cve-remediation` and `rgctl-osv` skills. The bridge image
adds Python 3, uv 0.5.11 and Poetry 2.1.1.

The cve-remediation addon requests 2Gi and is limited to 8Gi. rgctl may use up to 70% of the
limit (`RGCTL_MEMORY_LIMIT` overrides this). When it goes over, a watchdog stops rgctl, so an
oversized index (kubevirt) only leaves reachability unknown instead of OOM-killing the task.

## Components

| Path | What |
|---|---|
| `cmd/sbom-discovery` | Discovery addon (Task CR labeled `konveyor.io/discovery: sbom`, priority 2). CycloneDX Maven plugin, or syft fallback. |
| `cmd/cve-watcher` | Polls RHTPA per app SBOM, dispatches `cve-remediation` tasks, resolves findings, tracks AgentRun phase. |
| `cmd/cve-remediation` | Enrich, run rgctl OSV analysis, classify, then auto-bump or launch an AgentRun via hub `/agentic/agentruns`. |
| `internal/osv` | OSV preparation (download from RHTPA, merge `catalog.yaml` method data, or synthesize) and `rgctl vuln analyze` interpretation. |
| `images/agent-cve` | Agent image: agent-migiq runtime + JDK 21 + Maven + Go + rgctl 0.4.21 (`hack/build-agent.sh`). |
| `cmd/cve-remediation/project.go` | Maven and Go project handling (detect, declared, bump, build) and git change tracking/revert. |
| `internal/maven` | Version ordering and formatting-preserving pom edits (property, inline, or `dependencyManagement` override). |
| `deploy/rhtpa` | RHTPA install: RHBK realm, PostgreSQL, Helm values (Deployment Guide "Helm with Red Hat services"). |
| `deploy/mta` | Task/Addon CRs, watcher Deployment, `cve-remediator-java` Agent, SkillCards `rgctl-osv` (rgctl repo `skills/rgctl` @ v0.4.21) and `cve-remediation` (inline). |
| `third_party/hub-shared` | Hub SDK vendored from `migtools/mta-tackle2-hub@release-0.11` (MTA 8.3.x). |
| UI | `~/git/mta-tackle2-ui-cve`, branch `rhtpa-cve-tab` (based on `migtools/mta-tackle2-ui@release-0.11`). |

Application facts (the contract between backend and UI): `rhtpa:sbom` holds the SBOM
id, package count, and console URL. Each `cve:<CVE-ID>` holds a `Finding` (see
`internal/finding`).

## Install / rebuild

All scripts read `hack/env.sh`, which uses kubeconfig `~/Downloads/kubeconfig-dylan`,
context `admin`. Generated credentials are stored in the gitignored `.secrets.env`.

1. **RHTPA.** Run `hack/install-rhtpa.sh`. It installs the RHBK operator, PostgreSQL, the Keycloak realm
   `trustify`, the secrets, and the Helm chart `redhat-trusted-profile-analyzer` 3.1.1.
2. **Bridge image.** Run `hack/build.sh` (an in-cluster BuildConfig; the cluster is amd64).
3. **MTA wiring.** Create a hub service account token (`hack/hub.sh POST /serviceaccounts`
   with role architect, then `POST /serviceaccounts/<id>/tokens`) and save it as
   `HUB_BRIDGE_TOKEN=` in `.secrets.env`. Then run `hack/setup-mta.sh` (secrets, NetworkPolicy, CRs, watcher, agent).
4. **UI.** Run `hack/build-ui.sh`, then
   `oc patch tackle mta -n openshift-mta --type merge -p '{"spec":{"ui_image_fqin":"image-registry.openshift-image-registry.svc:5000/openshift-mta/mta-ui-cve@<digest>"}}'` (`hack/build-ui.sh` does this automatically).
   To revert to the stock UI, remove `ui_image_fqin`.

## Running the demo

1. In MTA, create an application with repository `https://github.com/dymurray/mta-cve-demo.git`
   and the git source credential.
2. Discovery runs language, then tech, then **sbom-discovery**. The SBOM appears in the RHTPA console.
3. Within about 30s the watcher finds CVE-2022-42889 (commons-text) and CVE-2022-1471 (snakeyaml).
   The app drawer's **Vulnerabilities** tab shows each finding with its rgctl reachability verdict and OpenVEX statement.
4. commons-text: the bump to 1.10.0 builds green, so branch `konveyor/cve-2022-42889-fix-<UTC timestamp>` is pushed.
5. snakeyaml: the bump to 2.0 breaks `Constructor`/`Representer`, so AgentRun
   `cve-<app>-2022-1471-t<task>` rewrites the call sites (using the rgctl and cve-remediation
   skills) and pushes `konveyor/cve-2022-1471-fix-<UTC timestamp>`, with the report in the commit message.
   Each run gets its own timestamped branch, so the same CVE can be remediated repeatedly.
6. **Go:** add `https://github.com/dymurray/mta-cve-demo-go.git` the same way. You get
   CVE-2022-32149 (`golang.org/x/text` v0.3.7 → v0.3.8, an auto-bump) and CVE-2025-30204
   (`github.com/golang-jwt/jwt` v3 has no fix; migrating to `github.com/golang-jwt/jwt/v5`
   v5.2.2 breaks `StandardClaims`/`ValidationError`, so `cve-remediator-go` runs).
7. To show a live publication, run `hack/publish-advisory.sh`, which uploads GHSA-j288-q9x7-2f5v
   (CVE-2025-48924, commons-lang3). It's picked up on the next poll and fixed with a
   `dependencyManagement` override, because commons-lang3 is a transitive dependency.
8. To start over, run `hack/reset-demo.sh <app-id> [owner/repo]`.

## Nightly refresh

CronJob `nightly-refresh` (02:00 UTC) submits an `sbom-discovery` task for each `konveyor-cves`
archetype member whose default-branch HEAD moved. The watcher then retries failed findings (max 3
attempts) and tracks PRs. Run it by hand:

```
kubectl -n openshift-mta create job nightly-manual-$(date +%s) --from=cronjob/nightly-refresh
```

Reset a finding (status `Failed`, attempts 0; retried after the next nightly refresh; works on
`Exhausted` and `PullRequestClosed`):

```
kubectl -n openshift-mta run reset-$(date +%s) --rm -i --restart=Never \
  --image=quay.io/dymurray/mta-rhtpa-bridge:latest \
  --overrides='{"spec":{"containers":[{"name":"reset","image":"quay.io/dymurray/mta-rhtpa-bridge:latest","command":["/usr/bin/nightly-refresh","reset","--app","<app>","--cve","<CVE-ID>"],"envFrom":[{"secretRef":{"name":"hub-bridge-token"}}],"env":[{"name":"HUB_BASE_URL","value":"http://mta-hub.openshift-mta.svc:8080"}]}]}}'
```

Watcher dry run (log decisions without dispatching):

```
kubectl -n openshift-mta set env deploy/cve-watcher DRY_RUN=true|false
```

Note: `hack/env.sh` hard-codes `KUBECONFIG` (default `~/Downloads/kubeconfig-dylan`) and `KCTX=admin`.
If your kubeconfig differs, set `KUBECONFIG_DYLAN`.

## One task per affected dependency

A newly imported application often has many CVEs in the same library (snakeyaml 1.33 has five).
On each poll the watcher collects every CVE it decides to dispatch, deduplicates them by affected
package (the purl without qualifiers, e.g. `pkg:maven/org.yaml/snakeyaml@1.33`), and submits **one**
`cve-remediation` task per package. The task data has `cve` (the primary CVE: highest score),
`cves` (all of them) and `package`. Each CVE keeps its own `cve:<id>` fact; `group` on the
fact lists the CVEs that share the task, branch, pull request and AgentRun.

The addon then:

- **Version.** It chooses the lowest release that fixes all of the CVEs
  (`maven.CoveringFix`). For CVEs fixed in 1.10.0 and 1.11.0, that's 1.11.0. Fixed versions on
  several release lines (1.10.1 and 2.0.3) count as separate ranges, so 2.0.1 does not fix that CVE.
- **Reachability.** It indexes the repository once and runs `rgctl vuln analyze` for each CVE.
  Unreachable CVEs become `NotAffected` and leave the group. If every CVE is unreachable, nothing is changed.
- **Leftovers.** A CVE with no published fix becomes NeedsAttention (`noFix`). A CVE whose
  only fix is on another release line also becomes NeedsAttention; it counts as a failed
  attempt, so it's retried after the update merges.
- **Output.** It makes one commit, branch and PR. The PR body has a table of every CVE, and the
  commit subject lists them (`fix(deps): upgrade … (CVE-A, CVE-B and 3 more)`). An escalation is a
  single AgentRun whose instructions include every CVE and OSV document. When that run succeeds,
  the watcher submits one pull-request task for the whole group.

If a dependency already has a live `cve-remediation` task, the watcher holds its new CVEs until
that task finishes, so two tasks never race on the same manifest. Attempts, retries and
`Exhausted` are still counted per CVE.

## Reachability and OpenVEX (rgctl OSV)

For each CVE the addon runs the rgctl vuln workflow (`discover --with-cfg --with-taint`,
`deps check`, `vuln analyze --osv`) using rgctl 0.4.21. The OSV document is the
advisory's original from RHTPA (GitHub OSV), or one synthesized from RHTPA data
when only CSAF exists.

Published advisories rarely list the vulnerable *methods*, and without them rgctl
reports `not_affected` for everything. `internal/osv/catalog.yaml` supplies
method-level data, merged into `affected[].ecosystem_specific` before analysis.
Verdicts:

| Verdict | Meaning | Remediation |
|---|---|---|
| exploitable | A path from external input reaches a vulnerable method | Remediate |
| reachable | Vulnerable methods are called, but no external-input path | Remediate |
| unreachable | Method data known, nothing calls it | **Not affected**: no code changes |
| unknown | No method data, transitive dependency, or analysis failed | Remediate; rgctl's `not_affected` is shown as `under_investigation` |

The UI shows the verdict, OpenVEX status and justification, call sites, taint paths,
analysis inputs, and the full OpenVEX document (copy or download). Attachments on
each task: `osv.json`, `rgctl-vuln-analyze.json`, `openvex.json`.

## When a fix goes to an agent

An agent runs only when the dependency update causes **new** build or test failures:

- **Baseline comparison.** If the build or tests fail after the update, the addon reverts it, builds
  the unmodified project, and compares failure signatures (compiler errors, failing packages or tests).
  If nothing is new (for example tests that need live services, or generated assets missing from a
  clean clone), the update is auto-remediated and the commit notes the pre-existing failures. Only the
  new failures are handed to the agent.
- **Update failures are not API changes.** If `go get` / `go mod tidy` fails (unresolvable path, newer
  Go required, network), the finding is marked *Needs attention* with the errors and no agent runs.
- **Go module path case.** RHTPA lowercases Go purls (`github.com/azure/go-ntlmssp`), but module paths
  are case-sensitive. The addon uses the spelling from `go.mod` (`github.com/Azure/go-ntlmssp`).

## Commits and pull requests

Both the scripted auto-bump and the agent (via the `cve-remediation` skill) write
one commit whose message is a summarized remediation report: subject, one-line
rationale, code changes, verification (tests plus rgctl), and refs. No report
file is added to the repository.

- **Identity.** All commits are authored and committed as `Dylan Murray <dymurray@redhat.com>`.
  The addon reads `GIT_USER_NAME` / `GIT_USER_EMAIL` from the `cve-remediation` Addon CR and sets
  `GIT_AUTHOR_*` / `GIT_COMMITTER_*`; the agents use `spec.gitConfig`.
- **DCO.** Every commit carries `Signed-off-by: Dylan Murray <dymurray@redhat.com>`. The addon
  appends the trailer; the skill requires `git commit -s` and checks for it.
- **Konveyor gitmoji titles.** For `github.com/konveyor/*` repos (`GITMOJI_ORGS`, default `konveyor`)
  and any repo whose workflows run `konveyor/release-tools/cmd/verify-pr`, the commit subject and PR
  title use the verify-pr alias prefixes: `:bug: Upgrade <dep> <old> to <new> (CVE-…)` (or
  `:bug: Migrate <old module> to <new module> <ver> (CVE-…)`), with `:warning:` only when the project's
  own API or behavior changes. The skill tells the agent which subject to use, and the PR step rewrites
  a non-compliant title (emoji characters become aliases; a missing prefix becomes `:bug:`). Other
  repos keep `fix(CVE-…): …`.
- **Pull requests.** For GitHub repositories, a PR from the remediation branch to the repository's
  branch (or its default branch) is opened with the app's source identity (a GitHub token):
  - Auto-bump: right after the push.
  - Agent: when the AgentRun succeeds, the cve-watcher submits a `cve-remediation` task with
    `action: pull-request`, which opens the PR from the agent's commit (skipped if the branch has
    no new commits).

  The PR body summarizes the finding (severity, dependency change, strategy, rgctl/OpenVEX, RHTPA
  link, advisories) followed by the commit's remediation report. An existing open PR for the branch
  is reused. The UI links the PR.

## How Red Hat advisories arrive

The `redhat-csaf` importer (`deploy/rhtpa/values-importers.yaml`) polls Red Hat's CSAF
provider metadata (`redhat.com`) **hourly** and ingests new RHSA/VEX documents. For the
demo it's limited to `/2026/` plus the demo CVEs; remove `onlyPatterns` to take the
full feed. Red Hat CSAF describes Red Hat builds (for example, `snakeyaml 1.33.0.SP1-redhat-00001`).
Those are shown as "Red Hat build available" and chosen only when `PREFER_REDHAT_BUILDS=true`.
Upstream Maven coordinates are matched through the GitHub OSV importer.

## Go vulnerability matching in RHTPA

Against the public OSV database, tackle2-hub has 20 distinct vulnerabilities. Initially RHTPA reported 1.
These fixes bring it to 16 of 20 (plus one OSV doesn't index):

| Cause | Where | Fix |
|---|---|---|
| syft writes major-version modules as `pkg:golang/github.com/x/y@v4.5.0#v4` (subpath), but advisories name `github.com/x/y/v4` | SBOM | `sbom-discovery` moves `#vN` into the module name |
| RHTPA compares OSV `SEMVER` ranges (Go vulnerability DB) strictly, rejecting `v0.57.0` | RHTPA bug | `sbom-discovery` drops the `v` from Go purl versions (both `SEMVER` and `ECOSYSTEM` ranges then match); the addon restores it |
| `golang.org/x/*` advisories exist only in the Go vulnerability database, and GitHub often lists Go *packages*, not modules | RHTPA config | `go-vulndb` importer (`github.com/golang/vulndb`, `data/osv`) |
| GitHub advisory importer limited to some years | RHTPA config | Year filter removed |
| Records with no CVE ID (e.g. `GO-2026-5774`, alias GHSA only) never become RHTPA vulnerabilities | RHTPA behavior | Not fixed; these 4 still don't appear |

## Gotchas found while building this

- Chart 3.1.1 serves `/api/v3`. With `storage.type: filesystem`, its pre-install migrate hook
  mounts PVC `storage` before Helm creates it, so pre-create it with Helm ownership metadata.
- The hub `addon` role can't create AgentRuns, so the remediation addon uses the hub service
  account `rhtpa.cve-bridge` (architect) token from secret `hub-bridge-token`.
- The MTA operator's `mta-egress` NetworkPolicy blocks registry pushes (5000) and Keycloak (8080).
  `deploy/networkpolicy.yaml` adds egress for both.
- The rgctl release binary needs glibc ≥ 2.39, so the bridge and agent images are RHEL10/UBI10.
  The stock MTA Java agent image (RHEL9) can't run it, hence `images/agent-cve`.
- The MTA operator deploys the UI with `IfNotPresent`, so `hack/build-ui.sh` pins the Tackle CR by digest.
- Addon-SDK `init()` needs a task pod. `internal/hubutil` must not import `shared/addon`.
