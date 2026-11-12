# Remediation Guards and Nested Go Modules Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `cve-remediation` must never push a branch or open a PR without a real change that installs the fixed version. A vulnerable Go version declared in a nested module (e.g. tackle2-hub `shared/go.mod`) must be bumped in that module.

**Architecture:**
- **Go module discovery:** pure helpers find every `go.mod` in the clone and select the modules that require the vulnerable version.
- **Multi-module Go project:** `goProject` bumps and builds each selected module.
- **Seams for testing:** a small set of interfaces (activity log, finding persistence, VCS, PR opener) lets hermetic tests drive the scripted-fix pipeline against real git repos and a file-based `GOPROXY`.
- **Guards:** checks before the bump (the vulnerable version is present), after the bump (the fixed version is present and the diff is non-empty), and before the PR (GitHub shows at least one changed file).

**Tech Stack:** Go 1.25, `os/exec` git, a file-based `GOPROXY`, `net/http/httptest`.

**Background (incident 2026-11-03):** konveyor/tackle2-hub#1176.
- Root `go.mod` already had `golang.org/x/net v0.62.0`; `shared/go.mod` (a separate module, wired in with `replace ... => ./shared`) still required `v0.57.0`. `syft dir:.` catalogs both, so RHTPA correctly kept reporting CVE-2026-78661.
- `cve-remediation` only edits the root module. `go get` changed nothing, `changedSince` returned an empty list, and `autoRemediate` still called `repo.Commit([], msg)`. The SDK commits with `--allow-empty` (`third_party/hub-shared/scm/git.go:113`) and pushes, and the PR was opened.
- User decision: remediation bumps the nested module.

## Global Constraints

- **Hard invariant:** no `Commit`/push and no PR unless the working tree has a non-empty diff against HEAD **and** every selected manifest now requires the fixed version (or the `FixedModule` path for major moves). A violation is `StatusNeedsAttention` with `StrategyNone`, a clear `StrategyReason`, and no branch fields set.
- Exact reasons (copy):
  - not present: `"<module> <version> is not required by any go.mod in the repository (found: <path> <ver>, ...)."`, or with `(found: none)`.
  - no change: `"The dependency update made no changes to the repository; nothing to commit."`
  - not applied: `"After the update <path> still requires <module> <ver>, not <fixed>."`
- PR guard message (`f.Message`): `"Branch has no file changes against <base>; no pull request opened."`. The finding then gets `Status = Failed` (it counts as a failed attempt).
- Module discovery skips directories named `vendor`, `testdata`, `node_modules`, and any directory starting with `.`. It honors the app's `repository.path`: discovery starts at `srcDir`.
- Go versions are compared after normalizing the leading `v` (RHTPA purls drop it). `+incompatible` is kept as part of the version.
- Tests are hermetic: no network. Go tests use `GOPROXY=file://<tmp>`, `GOSUMDB=off`, `GOFLAGS=-mod=mod`, `GOTOOLCHAIN=local`, and a temp `GOMODCACHE`/`GOCACHE`. Skip with `t.Skip` only if `go` or `git` is missing from PATH.
- Match the existing code style. Commit with `git commit -s`; the message ends with a blank line then `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. The fix is already applied in every module (the #1176 case) → no push, NeedsAttention "not required by any go.mod" naming the root at v0.62.0. Test in Task 2.
2. The vulnerable version is in a nested module only → only that module's `go.mod`/`go.sum` change, the build runs in that module, and the commit lists `shared/go.mod`. Test in Task 2.
3. Both root and nested modules are vulnerable → one commit bumps both. Test in Task 2.
4. The bump command succeeds but changes nothing (e.g. a Maven pom already at the fixed version) → no push. Test in Task 2 (Maven fixture, no network: `pom.xml` text only, build stubbed).
5. Any test fixture would let `git push` happen with an empty diff → the shared assertion helper `assertNoGarbage` fails it. Used by every pipeline test in Task 2.

---

### Task 1: Go module discovery and multi-module Go project

**Files:**
- Create: `cmd/cve-remediation/gomodules.go`
- Modify: `cmd/cve-remediation/project.go` (`goProject`: the single `dir` becomes root plus selected modules; `Bump`, `Build`, `Declared`, `Canonical`)
- Create: `cmd/cve-remediation/goproxy_test.go` (file-`GOPROXY` fixture helper, shared with Task 2)
- Test: `cmd/cve-remediation/gomodules_test.go`

**Interfaces:**
- Produces:
  - `type goModule struct { Dir string /* relative to srcDir, "." for root */; Path string /* module path */; Requires map[string]goRequire }`
  - `type goRequire struct { Version string /* as written, with "v" */; Indirect bool }`
  - `func findGoModules(srcDir string) (mods []goModule, err error)`: sorted by `Dir`, root first. It parses `module` and `require` lines (single-line and block forms; reuse `requireRe`).
  - `func selectVulnerable(mods []goModule, name, version string) (hit []goModule, found []string)`. A module path matches case-insensitively, and the version matches after normalizing the leading `v`. `found` lists `"<dir>/go.mod <ver>"` for modules that require the package at another version (for the reason text).
  - `func fixApplied(mods []goModule, name, fixed string) (missing []string)`: for each module in `mods` (re-parsed after the bump), the requirement must equal `fixed` (normalized). It returns `"<dir>/go.mod <ver>"` for each that doesn't.
  - `goProject` gains `root string` and `mods []string` (relative dirs to operate on, default `["."]`), plus `func (p *goProject) Select(dirs []string)`. `Bump` runs `go get` and `go mod tidy` in each selected dir. `Build` runs `go build ./... && go test ./...` in each selected dir and concatenates outputs, each prefixed with `== <dir> ==`; it returns an error if any dir fails. `BuildCommand()` names the dirs when there is more than one.
  - Test helper (in `goproxy_test.go`): `func newGoProxy(t *testing.T, mods map[string][]string /* module path -> versions */) (env []string)` writes `@v/list`, `.info`, `.mod`, `.zip` under a temp dir. The zip contains `<path>@<ver>/go.mod` and one `.go` file with a package declaration. It returns the env from Global Constraints. Also `func setRunGoEnv(t *testing.T, env []string)`, which points `runGo` at the real `go` binary with that env and restores it after the test.

- [ ] **Step 1: Write the failing tests**
  - `TestFindGoModules`: a temp tree with `go.mod` (module `example.com/app`, require `example.com/vuln v1.0.0 // indirect`), `shared/go.mod` (module `example.com/app/shared`, require block containing `example.com/vuln v1.0.0`), plus `vendor/x/go.mod`, `testdata/go.mod` and `.hidden/go.mod`, which must be ignored. Assert 2 modules, Dirs `[".", "shared"]`, and both requirements with the correct Indirect flags.
  - `TestSelectVulnerable`: root at `v1.1.0` and shared at `v1.0.0`; `selectVulnerable(mods, "EXAMPLE.com/vuln", "1.0.0")` → hit `["shared"]`, found `["./go.mod v1.1.0"]`. With both at `v1.1.0` → hit empty, found has 2 entries.
  - `TestFixApplied`: after editing shared to `v1.1.0` → missing empty. Unedited → `["shared/go.mod v1.0.0"]`.
  - `TestGoProjectBumpNestedModule` (uses `newGoProxy` with `example.com/vuln` versions `v1.0.0`, `v1.1.0`): a git-initialized fixture with root at `v1.1.0` and `shared` at `v1.0.0`, both importing the package so tidy keeps it. `Select(["shared"])`, then `Bump(pkg, "", "v1.1.0")`. Assert that `changedSince` = `shared/go.mod` and `shared/go.sum` only, that `Build` succeeds, and that the output contains `== shared ==`.
- [ ] **Step 2: Run them and confirm they fail** (`go test ./cmd/cve-remediation/ -run 'GoModules|SelectVulnerable|FixApplied|BumpNested'`; expect undefined symbols)
- [ ] **Step 3: Implement.** `detectProject` keeps working for root-only projects. A Go project gets `root = dir` and `mods = ["."]` by default. `Declared` and `Canonical` read the first selected module's `go.mod`.
- [ ] **Step 4: Run the package tests and confirm they pass** (`go test ./cmd/cve-remediation/`)
- [ ] **Step 5: Commit** `feat(cve-remediation): discover and bump nested Go modules`

---

### Task 2: Pipeline seams, guards and garbage-proof pipeline tests

**Files:**
- Modify: `cmd/cve-remediation/main.go` (`Remediation` gains seams, `Run`'s scripted-fix section moves into `func (r *Remediation) scriptedFix() error`, `autoRemediate` gets the guards)
- Create: `cmd/cve-remediation/seams.go`
- Test: `cmd/cve-remediation/pipeline_test.go`

**Interfaces:**
- Consumes: Task 1 (`findGoModules`, `selectVulnerable`, `fixApplied`, `goProject.Select`, `newGoProxy`, `setRunGoEnv`).
- Produces (in `seams.go`):

```go
type activityLog interface{ Activity(format string, v ...any) }
type findingStore interface{ Save(f *finding.Finding) error }
type vcs interface {
	Branch(name string) error
	Commit(files []string, msg string) error // commits and pushes
}
type prOpener interface {
	// Open opens (or finds) the PR for branch; commits are the remediation commit messages.
	Open(r *Remediation, commits []string) error
}
var errNoChanges = errors.New("no changes to commit")
// commitChanges refuses empty commits: it returns errNoChanges when files
// is empty or `git diff --quiet HEAD -- <files>` (run at the git root)
// reports no difference; otherwise it calls v.Commit.
func commitChanges(v vcs, srcDir string, files []string, msg string) error
```

`Remediation` gains fields `log activityLog`, `store findingStore`, `vcs vcs`, `prs prOpener`.
- `main()` wires the production adapters: `addon.Activity`, the existing fact save, `r.repo` as the scm (`Branch(name)` maps to `r.repo.Branch(name, scm.CREATE)`), and the existing `pullRequest`.
- Every `addon.Activity`/`r.save()`/`r.repo.*`/`r.pullRequest` call on the scripted-fix path (`scriptedFix`, `autoRemediate`, `bumpFailed`, `pushedOutcome` callers) goes through the seams. Other paths (`enrich`, `reachability`, `escalate`, rgctl) keep their current calls; `scriptedFix` starts after reachability.

**Guards in `scriptedFix`** (Go projects; Maven gets only the no-change and commit guards):
1. Discover modules and run `selectVulnerable` with `pkg.Name` and `pkg.Version`. An empty hit gives the NeedsAttention "not present" reason, with no bump. Otherwise `Select(hit dirs)` and log `Activity("Vulnerable %s %s required by: %s", ...)`.
2. After the bump: `changedSince` must be non-empty. Empty gives NeedsAttention with the "no change" reason, and the tree is reverted.
3. After the bump: `fixApplied` (re-run `findGoModules`) on the hit modules must be empty (for a major move, check `FixedModule` instead of `pkg.Name`). Otherwise NeedsAttention "not applied", and the tree is reverted.
4. In `autoRemediate`: `commitChanges`. `errNoChanges` gives NeedsAttention "no change", and nothing is pushed or opened.
5. The commit message's file list can never be empty, because guards 2 and 4 come first.

- [ ] **Step 1: Write the test harness**
  - In `pipeline_test.go`, `newFixture(t, files map[string]string) (srcDir string)` runs git init, commits everything, and adds a local bare remote as `origin`.
  - `fakeVCS` implements `vcs` with real git: `Branch` runs `git checkout -b`. `Commit` runs `git add` and `git commit` **without** `--allow-empty`, then records `pushes = append(pushes, push{branch, sha})`.
  - `fakePRs` records calls. `memStore` and `memLog` record findings and activities.
  - `assertNoGarbage(t, srcDir, pushes, prs, fixed string)`: for every push, `git show --stat <sha>` must list at least one file and `git show <sha>` must contain `fixed`. Every PR call must correspond to a recorded push. A PR call without a push fails the test.
- [ ] **Step 2: Write the failing pipeline tests.** Each one builds a `Remediation` with a pre-filled finding (Package `pkg:golang/example.com/vuln@1.0.0`, FixedVersion `v1.1.0`, `CVE-2099-0001`), a `goProject` and the fakes, then calls `scriptedFix()`. Each ends with `assertNoGarbage`.
  - `TestScriptedFixAlreadyFixed` (the #1176 reproduction): root `v1.1.0`, shared `v1.1.0` → 0 pushes, 0 PRs, status `NeedsAttention`, reason contains `"is not required by any go.mod"` and `"./go.mod v1.1.0"`, `Branch == ""`.
  - `TestScriptedFixNestedOnly`: root `v1.1.0`, shared `v1.0.0` → 1 push whose files are exactly `shared/go.mod` and `shared/go.sum`, 1 PR, status `PullRequestOpen`, commit message lists `shared/go.mod`.
  - `TestScriptedFixRootAndNested`: both `v1.0.0` → 1 push touching both `go.mod` files.
  - `TestScriptedFixNoChange`: a `goProject` whose `Bump` is wrapped to do nothing (test-only `Project` wrapper) → 0 pushes, status `NeedsAttention`, reason = the exact "no change" string.
  - `TestScriptedFixMavenNoChange`: a `pom.xml` fixture already at the fixed version, and a stub `Project` whose `Build` returns success (no mvn needed) → 0 pushes.
  - `TestCommitChangesRefusesEmpty`: unit test of `commitChanges` with an unchanged file list → `errNoChanges`, and `fakeVCS` not called.
- [ ] **Step 3: Run them and confirm they fail** (`go test ./cmd/cve-remediation/ -run 'ScriptedFix|CommitChanges'`)
- [ ] **Step 4: Implement the seams, `scriptedFix`, `commitChanges` and the guards**
- [ ] **Step 5: Run the full suite and confirm it passes** (`go test ./... && go vet ./...`); the existing tests keep passing.
- [ ] **Step 6: Commit** `fix(cve-remediation): never push or open a PR without a real dependency change`

---

### Task 3: PR guard

**Files:**
- Modify: `internal/github/github.go` (`Comparison` gains `Files []struct{ Filename string json:"filename" } json:"files"`)
- Modify: `cmd/cve-remediation/pr.go` (`pullRequest`)
- Test: `internal/github/github_test.go`, `cmd/cve-remediation/pr_test.go`

**Interfaces:**
- Produces: `pullRequest` **always** calls `gh.Compare(owner, repo, base, f.Branch)` before opening, including the scripted path that passes `commits`. If `AheadBy == 0` or `len(Files) == 0`, it sets the PR guard message and returns `errEmptyBranch` (new sentinel). Callers (`pushedOutcome`, `runPullRequestAction`) then mark the finding `Failed` through the existing error paths. It never calls `OpenPullRequest` in that case.
- To make it testable, `pullRequest` takes the base URL from `github.New`'s client (add an unexported `baseURL` field that tests can override, if one doesn't exist yet). Tests use `httptest`.

- [ ] **Step 1: Write failing tests**
  - `TestCompareFiles`: decode `files` from a fake compare response.
  - `TestPullRequestRefusesEmptyBranch`: fake GitHub returns compare `{"ahead_by":1,"files":[]}` → `errors.Is(err, errEmptyBranch)` and **no** POST to `/pulls` (the fake fails the test if it receives one).
  - `TestPullRequestOpensWithFiles`: compare with one file → POST made, `PullRequestURL` set.
- [ ] **Step 2: Run them and confirm they fail**
- [ ] **Step 3: Implement**
- [ ] **Step 4: Run the tests and confirm they pass** (`go test ./... && go vet ./...`)
- [ ] **Step 5: Commit** `fix(cve-remediation): refuse to open pull requests for branches without file changes`

---

### Task 4: Deploy and verify (controller, not a subagent)

- [ ] Build the bridge image in-cluster (`oc start-build mta-rhtpa-bridge --from-archive`, default kubeconfig context; `hack/env.sh` targets a stale kubeconfig).
- [ ] Confirm the image digest changed and no `cve-remediation` tasks are in flight.
- [ ] Document the guards and nested-module behavior in `CUSTOMIZATIONS.md` §4, and commit.
- [ ] Report to the user. Re-running tackle2-hub CVE-2026-78661 (finding now points at closed #1176) needs `nightly-refresh reset`, and would open a real PR bumping `shared/go.mod`. **Ask before resetting.**
