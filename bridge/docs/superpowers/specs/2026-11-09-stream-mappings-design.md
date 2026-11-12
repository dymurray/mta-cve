# Stream Mappings Design

Date: 2026-11-09
Status: approved in conversation, pending builder check
Builds on: `2026-11-06-jira-cve-source-design.md` (jira-cve-source feature, branch `jira-cve-source`)

## Intent and why

Prodsec CVE tickets carry a version stream in the title suffix (e.g.
`CVE-2026-78254 mta/mta-cli-rhel9: Apache Ant: ... [mta-8.2]`). The stream
tells us which release the vulnerability was found in, which branch fixes
land on, which fixVersion the ticket should carry, and who owns the
component. Today the bridge ignores all of that: it analyzes the repo's
default branch and never touches fixVersions or assignees.

This design makes the bridge stream-aware per product (MTA and CNV are
both live), so a ticket drives remediation against the right release
branch, gets its fixVersion set, and reaches a human (the stream owner)
whenever the automation dead-ends. It also opens a second PR against
main/master when — and only when — the vulnerable package is present in
main's dependencies.

Real ticket shapes (fetched 2026-11-09):

- [MTA-7688](https://redhat.atlassian.net/browse/MTA-7688): summary ends
  `[mta-8.2]`, pscomponent `mta/mta-cli-rhel9`, fixVersions `MTA 8.2.4`,
  issuetype **Vulnerability**, project MTA.
- [CNV-98898](https://redhat.atlassian.net/browse/CNV-98898): summary ends
  `[cnv-4.22]`, pscomponent `openshift-golang-builder-container`,
  fixVersions `CNV v4.22.z`, project CNV.

## Goals

1. Per-product configuration: products (MTA, CNV) each own a streams table
   (stream → branch, fixVersion, owner) and an images table (the existing
   image → repos/remediation/autoClose entries).
2. The watcher polls every configured product's JIRA project.
3. The stream is parsed from the trailing `[...]` of the ticket summary;
   it selects the analysis branch for remediation.
4. The ticket's fixVersions field gets the stream's fixVersion at dispatch.
5. When automation dead-ends (unresolvable CVE, NeedsAttention verdict,
   failed remediation, unknown stream, unmapped image), the ticket is
   assigned to the stream owner.
6. A second remediation against main/master runs only after the stream
   verdict confirms the vulnerable package is in main's dependency tree;
   its PR targets main.
7. Findings distinguish the stream branch from main, so both can exist
   for one CVE on one repo.

## Non-goals

- `openshift-golang-builder-container` semantics: "patch every repo in
  CNV with a golang bump" fan-out. Explicitly deferred; that component
  will simply have no image mapping until it is tackled.
- Version information from anywhere but the title suffix (no ticket
  field, description, or label parsing).
- Products beyond MTA and CNV (the schema must not preclude them).
- Setting fixVersion to anything other than the configured per-stream
  value (no arithmetic like "next z-stream").

## UI: CVE remediation tab

The customized UI (`~/git/mta-tackle2-ui-cve` worktree, built by
`hack/build-ui.sh`) gains a **new top-level tab** so CVE remediation
work is tracked on one isolated page instead of being scattered across
application views. The user wants to watch the whole pipeline — JIRA
ticket in, PR out — per product.

The tab is product-first:

- **Product overview cards** (MTA, CNV): one card per configured
  product, showing its streams (branch, fixVersion, owner) and the
  product's aggregated finding counts by status (open PRs, agent runs,
  needs-attention, remediated).
- **Per-product drill-in**: the product's applications (stream and
  main-branch apps distinguished by their branch), and under each, its
  findings — CVE, package, status, strategy, JIRA ticket link, PR link,
  reachability verdict — i.e. the existing finding fact data, grouped
  for this workflow.
- Data source is what the bridge already writes: hub application facts
  (`cve:<CVE>` findings, `rhtpa:sbom`) plus the component-map-derived
  product/stream structure. No new backend API is required for v1: the
  UI can read the component map structure from a small hub-side fact or
  config endpoint the bridge publishes, and findings through the
  existing facts API.
- The existing agentic-console affordances (AgentRun links) carry over
  into the finding rows where an agent run exists.

The UI work is a separate codebase and gets its own plan after the
watcher-side stream mappings land; this section is the design
interface contract between the two.

## Constraints

- Existing stack unchanged: Go, no new dependencies, hand-rolled JIRA
  REST v3 client, hub facts via tackle2-hub binding, TDD everywhere.
- The component map stays a ConfigMap re-read every poll
  (`51-component-map.yaml` shape, mounted at `/etc/jira-watch`).
- `DRY_RUN` mode must cover every new JIRA write (fixVersions, assignee)
  the way it covers comments and transitions today.
- No automated comments/assignments on real prodsec tickets without
  explicit user confirmation — the demo entries stay the only live
  mappings until the user says otherwise.

## The design

### Config schema (cve-component-map)

The ConfigMap data becomes a single YAML document with a top-level
`products` map (breaking change from the flat image→entry map; the live
map is demo-only, so it is migrated in place):

```yaml
products:
  mta:
    jiraProject: MTA
    owner: dymurray@redhat.com        # fallback when the stream is unknown
    mainBranch: main                  # default; per-image override below
    streams:
      mta-8.2:
        branch: release-0.10
        fixVersion: "MTA 8.2.4"
        owner: dymurray@redhat.com
    images:
      demo/mta-cve-demo:
        repo: https://github.com/dymurray/mta-cve-demo.git
        remediation: agent
        autoClose: true
  cnv:
    jiraProject: CNV
    owner: <user-supplied>
    streams:
      cnv-4.22:
        branch: <user-supplied>
        fixVersion: "CNV v4.22.z"
        owner: <user-supplied>
    images:
      <user-supplied component>:
        repo: <user-supplied repo>
        remediation: agent
```

- `products.<name>.jiraProject` drives one JQL search per product per
  poll (`project = <key> AND labels = "pscomponent:<image>" AND status
  not in (Closed, Done)`), replacing the single `JIRA_JQL_PREFIX` env
  (the env stays as an extra AND-clause filter if set, for demos).
- `ImageEntry` is unchanged except for an optional `mainBranch`
  overriding the product default (a repo whose default ref is `master`
  or a distro-style ref).
- **Branch precedence: the stream's `branch` wins.** A stream resolves
  per ticket and selects the analysis branch for every repo of the
  image; `ImageEntry.Branch` is retained only as documentation-era
  fallback and is ignored once a stream resolved. A stream's branch is
  assumed valid in every repo of its image; if that ever fails for a
  real component, a per-image override is the extension point (not
  built now).
- Stream lookup is exact-match on the bracketed token; no globbing.

### Stream parsing

A trailing bracketed token on the summary: regexp
`\[([A-Za-z0-9][A-Za-z0-9._-]*)\]\s*$` applied to `Ticket.Summary`.
No trailing token or a token absent from the product's streams table is
a dead end (see Owner assignment). The parsed stream rides on the
`jira.Work` struct next to `Image`/`Entry`.

### Applications and findings per branch

A hub application's repository carries a single branch, so the bridge
uses **one application per (repo, branch)**. App lookup (`ensureApp`/
`findApp`) is keyed by (repo URL, branch): an existing app is adopted
only when both match; otherwise a new app named `<repoBase>-<branch>` is
created. The watcher never retargets an existing app's branch. The main
app is created lazily, only when the main-gate fires.

Because facts are scoped per application, both analyses use the plain
`cve:<CVE>` fact key on their own app — **no branch suffix, no
`Finding.Branch` field, and no changes to `cmd/cve-remediation`** (the
addon, task data, PR titles, and comment bodies are untouched). Two
streams against the same repo are two apps and never collide;
`liveTask`'s appID+CVE matching separates them the same way.

The dual-source stamp path (JIRA identity onto an RHTPA-created finding)
still applies when the stream branch is the app's existing branch; a
stream app on a different branch is a new app and gets a fresh finding.

Comment reconcile considers the findings of every app the ticket maps to
(stream app and, if it exists, the main app). **JIRA transitions and
auto-close are driven by the stream finding only** — a main-branch
finding comments on the ticket but never fires the POST transition or an
auto-close, so a clean main can't close a ticket whose stream PR is
still open.

### fixVersion

At dispatch time (once per ticket, idempotent), the watcher edits the
issue: `PUT /rest/api/3/issue/<key>` with
`{"fields":{"fixVersions":[{"name":"<fixVersion>"}]}}` (name-based; the
existing fixVersions list is preserved, the stream's value appended only
when absent). A failed edit logs and continues — it never blocks
remediation.

### Main gate

After the stream finding reaches a verdict that identifies the
vulnerable package — **PullRequestOpen, Remediated, or NeedsAttention**
(these three only: a Failed/Exhausted remediation assigns the owner
instead of spawning main-branch work) — and `f.Package.Name != ""`:

1. Ensure the main app exists and has an SBOM (reuse `bootstrapSBOM`;
   the existing terminal-failure note applies).
2. Look up the package in the main SBOM's package list. **The list
   lives in the `rhtpa:sbom` fact**: `finding.SBOM` gains
   `Purls []string`, written by sbom-discovery from the component purls
   it already parses and normalizes before upload (no new RHTPA client
   endpoint). Matching is purl-based with a name+group fallback for
   ecosystems without clean purls, kept in one function.
3. Present → dispatch a second remediation for the same CVE on the main
   app (same dispatch path; PR targets main). Absent → one `noteOnce`
   comment ("main is not affected: <coordinate> not in main's
   dependencies") and nothing further.

The check runs in the watcher's poll, mirroring `bootstrapSBOM`'s shape
(a gate that waits for prerequisites and then acts once).

### Owner assignment

`jira.Client` gains `Edit` support (fixVersions) and `Assign(key,
accountId)`. Email → accountId resolution uses
`GET /rest/api/3/user/search?query=<email>` (first exact match),
cached per email for the watcher's lifetime.

Assignment fires (once — skip if the ticket's assignee is already the
owner) when:

- the ticket's stream token is missing or unknown to the product,
- an image has no mapping (alongside the existing unmapped note),
- no CVE id can be parsed (alongside the existing nocve note),
- the SBOM bootstrap task failed terminally,
- a finding reaches NeedsAttention,
- a remediation task ends Failed.

Unknown stream falls back to the product-level `owner`; every other
case uses the stream owner when a stream resolved, product owner
otherwise.

## What's left to the builder

- Exact SBOM purl-matching fallback rules for the main gate (kept in
  one function; strict purl compare first, name+group fallback).
- Whether `Assign` and the fixVersion edit share one `Edit` call or
  stay separate methods (tests will push toward separate).
- Regex polish for stream tokens that carry odd characters, provided
  the two real examples keep parsing.
- Test fixtures: reuse the fake JIRA server pattern; add user-search
  and edit-issue endpoints to it.

## Calls made after the builder check (2026-11-09)

- Main-gate dependency list source: `finding.SBOM.Purls`, written by
  sbom-discovery from purls it already parses — no RHTPA API change.
- Branch dimension via app-per-(repo,branch) with plain `cve:<CVE>` fact
  keys per app — cve-remediation addon is out of scope, unchanged.
- App lookup keyed by (repo URL, branch); existing apps are never
  retargeted; second stream on the same repo gets a suffixed app.
- Stream branch beats `ImageEntry.Branch`; uniform across the image's
  repos; per-image override is a future extension point.
- Main gate fires on PullRequestOpen/Remediated/NeedsAttention only;
  failed remediations assign the owner instead.
- Main-branch findings comment but never transition or auto-close.
- CNV verification: mechanism ships now; live CNV demo verification is
  gated on the user supplying the 1–2 CNV repos and green-lighting a
  CNV demo ticket (MTA demo verifies first).

## Verification sketch (live, after the user supplies CNV repos)

Demo tickets in both MTA and CNV projects (Vulnerability type, stream
suffix, pscomponent labels), run through: stream dispatch on the release
branch → fixVersion set → PR open → POST transition → main-gate comment
or main PR → a dead-end ticket assigned to the owner. Creating CNV demo
tickets needs the user's go-ahead the way MTA-8282 did.
