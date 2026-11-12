# Stream Mappings Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the jira-watcher stream-aware per product (MTA, CNV): the ticket title's `[stream]` suffix selects the remediation branch, sets the ticket's fixVersion, assigns dead-end tickets to the stream owner, and opens a second PR against main only when the vulnerable package is in main's dependencies.

**Architecture:** The component map becomes a per-product config (`products:` → streams table + images table). Each hub application is keyed by (repo, branch), so stream and main analyses are separate apps with plain `cve:<CVE>` facts — the cve-remediation addon is untouched. The main gate reads package purls from the `rhtpa:sbom` fact, extended by sbom-discovery.

**Tech Stack:** Go (stdlib + existing deps only), JIRA Cloud REST v3, tackle2-hub binding facts.

**Spec:** `docs/superpowers/specs/2026-11-09-stream-mappings-design.md`

## Global Constraints

- Go, no new dependencies; hand-rolled JIRA REST v3 client stays hand-rolled.
- TDD: every behavior change is a test watched failing first.
- `DRY_RUN` covers every new JIRA write (fixVersion edit, assignee) the way it covers comments today.
- The component map stays a ConfigMap re-read every poll; live mappings stay demo-only — no automated writes on real prodsec tickets without explicit user confirmation.
- Branch precedence: the stream's `branch` wins; `ImageEntry.Branch` is ignored once a stream resolved.
- JIRA transitions and auto-close are driven by the stream finding only; main-branch findings comment but never transition.
- Full suite (`go test ./...`) green at every task boundary.

## Review Focus

Input classes the task tests do not exercise, most likely to bite first:

1. A stream token naming a stream of a *different* product (e.g. `[cnv-4.22]` on an MTA-project ticket) must dead-end against MTA's streams, not match CNV's — pinned by `TestUnknownStreamAssignsProductOwner` (Task 4).
2. A fixVersion name JIRA rejects (typo'd, no version object) must log and continue, never block remediation — pinned by `TestSetFixVersionEditFailureIsNonFatal` (Task 2).
3. A main SBOM whose bootstrap terminally failed must not re-spawn sbom-discovery or the main dispatch every poll — pinned by `TestMainGateSBOMFailedNotResubmitted` (Task 6).
4. An email with no matching JIRA user (left the company) must log and skip assignment without crashing the poll — pinned by `TestAccountIDNoMatch` (Task 2).
5. A summary with brackets mid-title (`"[urgent] CVE-... [mta-8.2]"`) must parse the *trailing* token only — pinned by `TestStreamFromSummary` cases (Task 1).

---

### Task 1: Product/stream config schema and title stream parsing

**Files:**
- Modify: `internal/jira/imageMap.go`
- Test: `internal/jira/imageMap_test.go`

**Interfaces:**
- Consumes: existing `ImageEntry`, `Ticket`, `Dispatches`, `Unmapped`.
- Produces:
  - `type Stream struct { Branch, FixVersion, Owner string }` (yaml: `branch`, `fixVersion`, `owner`)
  - `type Product struct` with fields `JiraProject string` (yaml `jiraProject`), `Owner string` (yaml `owner`), `MainBranch string` (yaml `mainBranch`), `Streams map[string]Stream` (yaml `streams`), `Images map[string]ImageEntry` (yaml `images`)
  - `type Config struct { Products map[string]Product }` (yaml `products`)
  - `func ParseConfig(data []byte) (*Config, error)` — replaces `ParseImageMap` (delete it; migrate its tests)
  - `func StreamFromSummary(summary string) string` — trailing `[token]`; `""` when none
  - `func (p Product) MainRefOf(e ImageEntry) string` — `e.MainBranch` or `p.MainBranch` or `"main"`
  - `ImageEntry` gains `MainBranch string` (yaml `mainBranch`, json `mainBranch,omitempty`)
  - `Work` gains `Product string`, `Stream string`, `StreamCfg Stream`
  - `Dispatches(tickets []Ticket, prod Product, cves func(Ticket) ([]string, error)) []Work` — per-product; `Unmapped(tickets []Ticket, prod Product) []Ticket`

- [ ] **Step 1: Write the failing tests**

`TestParseConfigProducts`: the spec's mta block (jiraProject MTA, one stream `mta-8.2` → branch `release-0.10`, fixVersion `MTA 8.2.4`, owner email; one image with `repo` shorthand) parses; `Repo` folded into `Repos`; `MainRefOf` returns `main` when nothing overrides, the image's `mainBranch` when set.
`TestStreamFromSummary`: both real titles parse (`...tasks [mta-8.2]` → `mta-8.2`, `...frames [cnv-4.22]` → `cnv-4.22`); `"[urgent] CVE-1 x [mta-8.2]"` → `mta-8.2`; `"CVE-1 no stream"` and `"CVE-1 trailing [not-a-stream"` → `""`.
`TestDispatchesCarriesStream`: a ticket with pscomponent + stream yields Work with `Product`, `Stream`, `StreamCfg.Branch` set.
Migrate `ParseImageMap` tests (shorthand fold, bad remediation rejection) onto `ParseConfig` — a `products:` wrapper is added to their fixtures.

- [ ] **Step 2: Run to verify they fail**

Run: `go test ./internal/jira/`
Expected: FAIL — undefined `ParseConfig`/`StreamFromSummary`, `Dispatches` signature mismatch.

- [ ] **Step 3: Implement in `internal/jira/imageMap.go`**

`StreamFromSummary` uses `regexp.MustCompile(`\[([A-Za-z0-9][A-Za-z0-9._-]*)\]\s*$`)` on the summary, returning the captured token. `ParseConfig` unmarshals the whole document as `Config`, then validates remediation modes per image exactly as `ParseImageMap` did. `Dispatches`/`Unmapped`/`sortedComponents` take `Product` and read `prod.Images`.

- [ ] **Step 4: Run to verify they pass**

Run: `go test ./internal/jira/`
Expected: PASS. Then keep the suite green across the signature change: adapt `cmd/jira-watcher`'s call sites to the new `Dispatches`/`Unmapped` signatures mechanically (wrap the existing flat map in a single synthetic product; behavior lands in Task 3) and run `go test ./...` — Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/jira/ cmd/jira-watcher/
git commit -m "feat(jira): per-product config schema and title stream parsing"
```

### Task 2: JIRA client — fixVersion edit, assignee, account lookup

**Files:**
- Modify: `internal/jira/client.go`
- Test: `internal/jira/client_test.go`

**Interfaces:**
- Consumes: existing `Client.get/post/do`, fake JIRA server in `client_test.go`.
- Produces:
  - `func (c *Client) SetFixVersion(key, fixVersion string) error` — reads the issue's `fixVersions`, no-op when the name is present, else `PUT /rest/api/3/issue/{key}` `{"fields":{"fixVersions":[...existing, {"name":fixVersion}]}}`; a failed edit returns the error (caller logs and continues)
  - `func (c *Client) Assign(key, accountID string) error` — `PUT /rest/api/3/issue/{key}/assignee` `{"accountId":accountID}`
  - `func (c *Client) AccountID(email string) (string, error)` — `GET /rest/api/3/user/search?query=<email>`, first result whose `emailAddress` equals the query; error `"jira: no user found for %s"` otherwise
  - `Ticket` gains `AssigneeID string`, `AssigneeEmail string`, parsed from `fields.assignee.{accountId,emailAddress}`; `Search` adds `"assignee"` to its fields list

- [ ] **Step 1: Write the failing tests**

`TestSetFixVersionIdempotent`: fake issue already carries fixVersions `["MTA 8.2.4"]` → no PUT; absent → exactly one PUT whose body includes both the existing and the new name.
`TestSetFixVersionEditFailureIsNonFatal`: fake returns 400 on PUT → `SetFixVersion` returns an error containing the status (the *caller* logs; the test pins that the error is returned, not panicking).
`TestAssignUsesAccountID`: body is `{"accountId":"123"}`.
`TestAccountIDSearch`: user-search returns two users, only one matching email → that `accountId`; empty result → error.
`TestSearchParsesTickets` extended: assignee fields land on `Ticket`.

- [ ] **Step 2: Run to verify they fail**

Run: `go test ./internal/jira/`
Expected: FAIL — undefined methods.

- [ ] **Step 3: Implement**

Add fake endpoints `PUT /rest/api/3/issue/{key}/assignee`, `PUT /rest/api/3/issue/{key}` (edit), `GET /rest/api/3/user/search` to `newFakeJIRA` first. `SetFixVersion` needs a GET of `fields=fixVersions` (reuse the issue GET handler, keyed on the fake's `issue` fixture). Client needs a `put` helper mirroring `post`.

- [ ] **Step 4: Run to verify they pass**

Run: `go test ./internal/jira/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/jira/
git commit -m "feat(jira): fixVersion edit, assignee, and account-id lookup"
```

### Task 3: Watcher — per-product polling, stream branch, branch-keyed apps

**Files:**
- Modify: `cmd/jira-watcher/main.go`, `cmd/jira-watcher/reconcile.go`
- Test: `cmd/jira-watcher/jiraWatcher_test.go`

**Interfaces:**
- Consumes: `jira.Config/Product/Stream/StreamFromSummary/MainRefOf/Dispatches/Unmapped` (Task 1), `jira.Client` (Task 2).
- Produces:
  - `Watcher.cfg *jira.Config` replaces `images map[string]jira.ImageEntry`; `jqlPrefix` env becomes an extra AND-clause applied to every product search (default `""`)
  - `poll()` iterates `cfg.Products`; per product, one search per image with JQL `project = <JiraProject> AND labels = "pscomponent:<image>" AND status not in (Closed, Done)` (+ jqlPrefix when set); tickets tagged with their product in the open map
  - `handleTicket(tk jira.Ticket, prod jira.Product)`: stream resolution via `StreamFromSummary`; unknown/missing stream is a dead end (Task 4 adds assignment; here: `noteOnce` "unknown-stream" with a body naming the parsed token or its absence, then return)
  - `ensureApp(repoURL, branch string)` / `findApp(repoURL, branch string)`: match on `normalizeRepo(URL)` AND `Repository.Branch == branch`; create with name `repoBase` when `branch == ""`, else `repoBase-<branch>`; existing apps are never retargeted
  - `dispatchWork(wk jira.Work, prod jira.Product)`: analysis branch is `wk.StreamCfg.Branch`; `Work` flows carry the product
  - `reconcileComments(tk, prod)`: iterates each mapped image's repos and **both** apps — the stream app (`StreamCfg.Branch`) and the main app (`MainRefOf`) when it exists; findings of both comment; **transitions and auto-close fire only for findings on the stream app** (pass `isMain bool` to the transition gates)
  - `mainApp` name is `repoBase-<mainRef>` via the same `ensureApp` rule

- [ ] **Step 1: Write the failing tests**

`TestPollPerProductProjects`: fake JIRA serves tickets per project; a Config with mta + cnv products searches `project = MTA` and `project = CNV` (assert both JQLs hit the search endpoint).
`TestDispatchUsesStreamBranch`: a ticket with `[mta-8.2]` dispatches; the created hub application has `Repository.Branch == "release-0.10"` and name `mta-cve-demo-release-0.10`.
`TestStreamAppAdoptedWhenBranchMatches`: an app pre-exists with the stream branch → adopted, no new app.
`TestSecondStreamSeparateApp`: two tickets, streams `mta-8.1` and `mta-8.2`, same repo → two apps, two findings, no clobber.
`TestUnknownStreamNotesOnce`: `[mta-9.9]` ticket → one comment mentioning the token, no app, no task.
`TestMainFindingNoTransition`: a finding with `jiraKey` on the main app reaching PullRequestOpen comments but does not fire `prTransition`; the same status on the stream app does.
Migrate existing `jiraWatcher_test.go` fixtures from flat image maps to `products:` config (mechanical).

- [ ] **Step 2: Run to verify they fail**

Run: `go test ./cmd/jira-watcher/`
Expected: FAIL — compile errors from Task 1 signature changes first; fix those, then behavior failures.

- [ ] **Step 3: Implement**

Follow the interfaces block. `dispatchCVE` sets `Component: wk.Image` and `Message` mentioning the stream (`"Reported in JIRA ticket %s (stream %s)."`). Keep `bootstrapSBOM` as-is (it is keyed by app). `noteOnce` markers: add `"unknown-stream"`.

- [ ] **Step 4: Run the whole suite**

Run: `go test ./...`
Expected: all PASS (sbom-discovery, cve-remediation untouched).

- [ ] **Step 5: Commit**

```bash
git add cmd/jira-watcher/
git commit -m "feat(jira-watcher): per-product polling, stream branches, branch-keyed apps"
```

### Task 4: fixVersion write and owner assignment

**Files:**
- Modify: `cmd/jira-watcher/main.go`, `cmd/jira-watcher/reconcile.go`
- Test: `cmd/jira-watcher/jiraWatcher_test.go`

**Interfaces:**
- Consumes: `Client.SetFixVersion/Assign/AccountID`, `Ticket.AssigneeID/AssigneeEmail` (Task 2), stream resolution (Task 3).
- Produces:
  - `Watcher.accountIDs map[string]string` cache; `func (w *Watcher) owner(prod jira.Product, st *jira.Stream) string` — stream owner when a stream resolved, else `prod.Owner`
  - `func (w *Watcher) assignOwner(tk jira.Ticket, email string)` — resolve+cache accountID, skip when `tk.AssigneeEmail == email`, `DRY_RUN` logs; assignment failure logs and continues
  - fixVersion: in `handleTicket` after stream resolution, once per ticket (client-side idempotent), only when `st.FixVersion != ""`
  - assignment triggers: unknown/missing stream (→ `prod.Owner`), unmapped image, no CVE parsed, terminal SBOM bootstrap failure, finding reaching `NeedsAttention` or `Failed` (→ stream owner)

- [ ] **Step 1: Write the failing tests**

`TestFixVersionSetAtDispatch`: ticket with `[mta-8.2]` → fake receives the fixVersion edit with `MTA 8.2.4`; a second poll sends no second edit.
`TestUnknownStreamAssignsProductOwner`: `[mta-9.9]` → assignee PUT to the product owner's accountID.
`TestNeedsAttentionAssignsStreamOwner`: stream finding → NeedsAttention → assignee PUT to the stream owner.
`TestNoReassignWhenAlreadyOwner`: ticket already assigned to the owner's email → no assignee PUT.
`TestAccountLookupCached`: two assignments to the same owner hit user-search once.

- [ ] **Step 2: Run to verify they fail**

Run: `go test ./cmd/jira-watcher/`
Expected: FAIL on the new tests.

- [ ] **Step 3: Implement**

Wire `assignOwner` next to each existing `noteOnce` dead-end and into `reconcileComments`' status switch. `DRY_RUN` must log every would-be write.

- [ ] **Step 4: Run the whole suite**

Run: `go test ./...`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/jira-watcher/
git commit -m "feat(jira-watcher): set fixVersion at dispatch, assign owner on dead ends"
```

### Task 5: SBOM purls for the main gate

**Files:**
- Modify: `internal/finding/finding.go` (SBOM struct), `cmd/sbom-discovery/main.go`
- Test: `cmd/sbom-discovery/main_test.go`

**Interfaces:**
- Consumes: the cleaned CycloneDX document in sbom-discovery (post-`cleanSyft` for syft docs, raw for cdxgen).
- Produces:
  - `SBOM.Purls []string` (json `purls,omitempty`) — the document's component purls, deduplicated, Go-normalized (reuse `goMajorPurl`/`goVersionPurl`), empty-string-free
  - `func sbomPurls(doc []byte) []string` in `cmd/sbom-discovery/main.go` — collects `components[].purl` and `packages[].purl`
  - sbom-discovery writes `Purls` into the `rhtpa:sbom` fact alongside `Packages`

- [ ] **Step 1: Write the failing tests**

`TestSBOMPurlsWritten`: a fixture CycloneDX doc (maven + golang components, one duplicate, one empty purl) → `sbomPurls` returns deduplicated normalized purls; the persisted `finding.SBOM` carries them; JSON round-trip keeps the `purls` key.

- [ ] **Step 2: Run to verify they fail**

Run: `go test ./cmd/sbom-discovery/`
Expected: FAIL — no `Purls` field / `sbomPurls` undefined.

- [ ] **Step 3: Implement**

Collection happens after document cleaning so the fact matches what RHTPA ingested. Cap is not needed (SBOMs are bounded by package count).

- [ ] **Step 4: Run the whole suite**

Run: `go test ./...`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/finding/finding.go cmd/sbom-discovery/
git commit -m "feat(sbom-discovery): record component purls in the sbom fact"
```

### Task 6: Main gate

**Files:**
- Modify: `cmd/jira-watcher/reconcile.go`
- Test: `cmd/jira-watcher/jiraWatcher_test.go`

**Interfaces:**
- Consumes: branch-keyed apps (Task 3), `SBOM.Purls` (Task 5), `dispatchCVE`/`bootstrapSBOM`/`noteOnce`.
- Produces:
  - `func (w *Watcher) reconcileMain(tk jira.Ticket, prod jira.Product, wk jira.Work, app *api.Application, f *finding.Finding) error` — called from `handleTicket` after `reconcileComments` for the ticket's stream findings
  - gate condition: `f.Status` in `{PullRequestOpen, Remediated, NeedsAttention}` AND `f.Package.Name != ""`
  - `func mainHasPackage(sbom *finding.SBOM, pkg finding.Package) bool` — purl compare via `finding.PackageKey` against `sbom.Purls`, falling back to `pkg.Group`+`pkg.Name` matching the purl's namespace/name segments
  - main dispatch reuses `dispatchWork` against the main app (branch `MainRefOf`), creating the finding via the same `dispatchCVE` path
  - absent package → `noteOnce(tk, "main-clean", ...)` comment: `"MTA CVE bridge: main is not affected: <coordinate> is not in main's dependencies."`

- [ ] **Step 1: Write the failing tests**

`TestMainGateDispatchesWhenPurlPresent`: stream finding PullRequestOpen with `Package` set; main app + SBOM fact whose `Purls` include the package → a cve-remediation task is created against the main app (branch `main`).
`TestMainGateCleanMainNotesOnce`: purls absent → one "main is not affected" comment, no task, and no repeat on the next poll.
`TestMainGateWaitsForSBOM`: main app exists, no SBOM → sbom-discovery submitted, no remediation yet; next poll with SBOM present proceeds.
`TestMainGateSBOMFailedNotResubmitted`: terminal sbom task → one note, nothing resubmitted.
`TestMainGateNotBeforeVerdict`: stream finding `Analyzing` → nothing happens.
`TestMainGateSkipsFailedRemediation`: stream finding `Failed` with `Package` set → no main dispatch (owner assignment covers it, Task 4).

- [ ] **Step 2: Run to verify they fail**

Run: `go test ./cmd/jira-watcher/`
Expected: FAIL — `reconcileMain`/`mainHasPackage` undefined.

- [ ] **Step 3: Implement**

`mainHasPackage` in one function per the spec's "left to the builder". The main-app finding's comments flow through `reconcileComments`' existing main-app loop next poll; Task 3's `isMain` gate already keeps it transition-free.

- [ ] **Step 4: Run the whole suite**

Run: `go test ./...`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/jira-watcher/
git commit -m "feat(jira-watcher): main-branch remediation gated on main's dependencies"
```

### Task 7: Config migration and deployment wiring

**Files:**
- Modify: `deploy/mta/51-component-map.yaml`, `deploy/mta/50-jira-watcher.yaml`
- Test: `go test ./internal/jira/` (fixtures mirror the deployed YAML)

**Interfaces:**
- Consumes: `ParseConfig` (Task 1).
- Produces: the deployed ConfigMap in `products:` form; `JIRA_JQL_PREFIX` removed from the deployment (products carry `jiraProject`); CNV product block with placeholder images/streams commented out until the user supplies repos.

- [ ] **Step 1: Write the failing test**

`TestDeployedComponentMapParses`: the test reads `deploy/mta/51-component-map.yaml`, extracts the ConfigMap's `image-map.yaml` data value, and asserts `ParseConfig` succeeds with the mta product present (`jiraProject: MTA`, stream `mta-8.2`) and at least one image. (File-reading test, same pattern as other deploy-fixture tests in the repo if any; otherwise place under `internal/jira` with a `//go:build` free relative path from the package dir.)

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/jira/ -run TestDeployedComponentMapParses`
Expected: FAIL — the deployed map is still flat.

- [ ] **Step 3: Migrate the YAML**

Demo entry becomes the mta product with a demo stream (e.g. `mta-8.2` → the demo repo's default branch or a `release-0.10`-style branch the user picks at verification time; fixVersion `MTA 8.2.4`, owner from `.secrets.env`'s JIRA_EMAIL — never commit the real email, use the user's placeholder guidance). CNV block present but with images commented `# <pending user-supplied repos>`.

- [ ] **Step 4: Run the whole suite**

Run: `go test ./...`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add deploy/mta/ internal/jira/
git commit -m "feat(deploy): migrate the component map to per-product stream config"
```

- [ ] **Step 6: Live verification (deferred until user green-lights)**

`hack/build.sh` + rollout restart; update the demo ticket's summary to carry a stream suffix (or file a new MTA demo ticket as Vulnerability type — user permission required, as with MTA-8282); observe: stream-branch app created, fixVersion set, PR on the stream branch, POST transition, main-gate comment or main PR. CNV verification additionally waits on the user's repos and ticket permission. Record outcomes in the SDD ledger.
