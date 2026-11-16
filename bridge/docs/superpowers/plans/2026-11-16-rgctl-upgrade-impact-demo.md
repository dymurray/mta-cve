# rgctl 0.4.27 Upgrade + Impact Demo Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Upgrade rgctl to 0.4.27 everywhere, make Go reachability real (analysis-time vendoring + bare sink names), and add a proven not-impacted case (guava) so the demo shows impacted code paths and non-impact evidence.

**Architecture:** The cve-remediation addon already runs `rgctl discover --with-cfg --with-taint` + `vuln analyze --osv` and parses the output shape 0.4.27 emits. Changes are: image/skill version bumps; a `go mod vendor` step in the addon's analysis clone for Go projects (flipping the `externalCalls` gate to true when it succeeds); bare-symbol Go method names in catalog.yaml and OSV-merge; a guava dependency + catalog entry in/on the Java demo app; rebuild + cluster verification.

**Tech Stack:** Go 1.2x (bridge), rgctl 0.4.27, Maven demo app, in-cluster OpenShift image builds.

**Spec:** `docs/superpowers/specs/2026-11-16-rgctl-upgrade-impact-demo-design.md`

## Global Constraints

- rgctl 0.4.27 linux-amd64 tarball SHA256: `07b44dcfff911158359efa1e6fe752355d471d2b57a6cb16e4d8e8f536219428` (ARG `RGCTL_SHA256` in both image files).
- Vendoring must never touch git state: run `go mod vendor` in the analysis clone only; the clone's committed tree (what gets committed/pushed) must be unchanged by analysis.
- Existing behavior for Go without successful vendoring stays `unknown` (regression-safe).
- Catalog method field names: `affected_methods` / `affected_classes` under `ecosystem_specific` (rgctl reads exactly these).
- Go sink names in catalog.yaml: bare symbols (`ParseAcceptLanguage`, `ParseWithClaims`), never module-path-prefixed.

## Review Focus

- Go repo where `go mod vendor` fails (no network, module errors): analysis must proceed and produce `unknown`, not fail the task.
- A Go repo that already commits `vendor/`: vendoring must be a no-op-safe re-run, not an error.
- OSV advisory that itself provides `affected_methods` with module-path prefixes for Go: merge must strip to bare names or the sink won't resolve.
- `vuln analyze` emitting `not_exploitable` with zero callers and method data present: verdict must be `unreachable` (not `unknown`) only when externalCalls is true.
- Snakeyaml/commons-text Java behavior must not regress (still exploitable with paths).

---

### Task 1: rgctl 0.4.27 in images + vendored skill

**Files:**
- Modify: `Dockerfile` (ARG RGCTL_VERSION, RGCTL_SHA256, comments)
- Modify: `images/agent-cve/Containerfile` (same)
- Modify: `images/skills/rgctl/**` (re-vendor via script)
- Test: none (image content; verified at build time by Task 5)

**Interfaces:**
- Produces: rgctl 0.4.27 binaries in both images; skill text at v0.4.27.

- [ ] **Step 1: Bump both image files** — `RGCTL_VERSION=0.4.27`, `RGCTL_SHA256=07b44dcfff911158359efa1e6fe752355d471d2b57a6cb16e4d8e8f536219428`, update the rgctl version mentions in comments (Dockerfile header, Containerfile header line 4).
- [ ] **Step 2: Re-vendor the skill** — run `hack/vendor-rgctl-skill.sh v0.4.27` (requires `~/git/rgctl` checkout with tags fetched). Verify `images/skills/rgctl/SKILL.md` frontmatter `source:` URL says v0.4.27 and the vuln workflow section mentions the P0–P6 pipeline.
- [ ] **Step 3: Commit** — `chore: upgrade rgctl to 0.4.27 (binaries + skill)`

### Task 2: Go reachability — analysis-time vendoring + externalCalls gate

**Files:**
- Modify: `cmd/cve-remediation/main.go` (reachability func, ~line 888-960)
- Modify: `cmd/cve-remediation/project.go` or new `cmd/cve-remediation/govendor.go`
- Test: `cmd/cve-remediation/govendor_test.go`

**Interfaces:**
- Consumes: `Rgctl.Discover()` (internal/osv), `m.Package.Ecosystem` (`finding.EcosystemGo`), existing clone dir layout (`project.go`).
- Produces: `func vendorGoModules(dir string) error` — runs `go mod vendor` in dir, returns error; caller decides fallback. Reachability passes `externalCalls = true` for Go iff vendoring succeeded (Maven unchanged: `externalCalls = m.Package.Ecosystem == finding.EcosystemMaven || vendored`).

- [ ] **Step 1: Write failing test** — `TestVendorGoModules` using a temp Go module fixture (go.mod requiring a tiny module from the local file proxy pattern used in `pipeline_test.go`): asserts `vendor/` appears and error is nil on success; asserts error returned when `go.mod` is malformed. Second test: repo already vendored → re-run still succeeds.
- [ ] **Step 2: Run it, watch it fail** — `go test ./cmd/cve-remediation/ -run TestVendorGoModules -v` → FAIL: undefined: vendorGoModules.
- [ ] **Step 3: Implement** `vendorGoModules` (exec `go mod vendor`, env passthrough like existing build invocations in project.go) and wire into `reachability()`: for `EcosystemGo`, call it before `rg.Discover()`; log via `addon.Activity` on failure and continue with `externalCalls=false`; set `externalCalls=true` on success. Vendoring must run after the clone is checked out and must be reverted before any commit path (it only touches the analysis clone; commits happen on a fresh state — verify by reading the commit flow).
- [ ] **Step 4: Tests pass** — `go test ./cmd/cve-remediation/ -v` all green.
- [ ] **Step 5: Commit** — `feat: vendor Go modules at analysis time so rgctl records external calls`

### Task 3: bare Go sink names in catalog + OSV merge; not_exploitable reason

**Files:**
- Modify: `internal/osv/catalog.yaml` (add Go + guava entries)
- Modify: `internal/osv/fetch.go` or `osv.go` (method-name normalization for Go)
- Modify: `internal/osv/osv.go` (`Interpret`: verdict reason mentions rgctl's `not_exploitable`)
- Test: `internal/osv/osv_test.go`

**Interfaces:**
- Consumes: catalog `Entry` (ids, package, affected_classes, affected_methods), OSV merge path.
- Produces: catalog entries for `golang.org/x/text` (CVE-2022-32149, CVE-2026-56851, CVE-2026-56852 — affected_methods: `ParseAcceptLanguage`), `github.com/golang-jwt/jwt` (CVE-2025-30204 — `ParseWithClaims`), `com.google.guava:guava` (CVE-2020-8908 — `com.google.common.io.Files.createTempDir`). Go method normalization: strip `^<module-path[./]]*` prefix to the bare symbol when ecosystem is Go.

- [ ] **Step 1: Write failing tests** — normalization: `github.com/golang-jwt/jwt.ParseWithClaims` → `ParseWithPaths`… (careful: → `ParseWithClaims`), `golang.org/x/text/language.ParseAcceptLanguage` → `ParseAcceptLanguage`, already-bare stays. Interpret: `Exploitability: "not_exploitable"`, callers present → verdict reachable with a reason naming rgctl's not-exploitable assessment; `not_exploitable`, no callers, externalCalls → unreachable.
- [ ] **Step 2: Watch fail.**
- [ ] **Step 3: Implement** — normalization in the OSV/catalog merge path for Go ecosystems; add the catalog entries; extend `Interpret` with the not_exploitable-aware reason.
- [ ] **Step 4: Tests pass** (`go test ./internal/osv/ -v`).
- [ ] **Step 5: Commit** — `feat: bare Go sink names, not_exploitable reasons, Go+guava catalog entries`

### Task 4: Java demo app — guava not-impacted case

**Files (repo `~/git/mta-cve-demo` or fresh clone, branch `main`):**
- Modify: `pom.xml` (add `com.google.guava:guava` 28.2-jre)
- Modify: one safe usage in `src/main/java/...` (e.g. `ImmutableList`/`Strings` in the inventory service)
- Test: existing `mvn clean verify` must pass.

**Interfaces:**
- Produces: a demo repo whose SBOM contains guava 28.2-jre → RHTPA reports CVE-2020-8908 → addon + catalog prove not-affected.

- [ ] **Step 1: Add dependency + safe usage** (never reference `Files.createTempDir`).
- [ ] **Step 2: `mvn clean verify` passes locally.**
- [ ] **Step 3: Push to `dymurray/mta-cve-demo` main** (demo repo; the watcher picks up the moved HEAD on the nightly refresh or after a reset).

### Task 5: build, deploy, verify on cluster

**Files:** none (operations).

- [ ] **Step 1: `hack/build.sh` && `hack/build-skills.sh` && `HARNESS_SRC=~/git/agentic-controller-push-url/harness hack/build-agent.sh`** — all three images rebuild with rgctl 0.4.27.
- [ ] **Step 2: Reset findings** for both apps (`nightly-refresh reset --app 1 --cve CVE-2022-1471` etc., or `hack/reset-demo.sh`), trigger `sbom-discovery` re-runs (the java app needs a fresh SBOM including guava).
- [ ] **Step 3: Verify facts:** app 1 → snakeyaml/commons-text still `exploitable` with paths; guava CVE-2020-8908 `unreachable` verdict with rgctl not-affected VEX and zero callers. App 2 → jwt `exploitable` (caller `TokenService.Verify`, taint path), x/text `reachable` (callers `PreferredLanguage`), no `unknown` verdicts remain except where honest.
- [ ] **Step 4: Record results** in the ledger; screenshots optional.
