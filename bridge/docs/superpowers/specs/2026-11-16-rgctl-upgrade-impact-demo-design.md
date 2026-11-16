# rgctl 0.4.27 upgrade + impacted-code-path demo — Design

## Intent

The demo's reachability story is weak: the Go app's verdicts are all `unknown`
(rgctl 0.4.21 does not record calls into external Go packages), and there is no
case that shows why a CVE does **not** impact a codebase. Upgrade rgctl to
0.4.27, upgrade the vendored rgctl skill, and enhance both demo apps so the
rgctl OSV / vuln-analyze calls show **impacted code paths** (callers, taint
paths, file:line anchors) or **prove non-impact** (zero callers → not-affected
with justification). Vulnerabilities come from RHTPA/TPA only; JIRA is out of
scope for this story.

## Empirical grounding (rgctl 0.4.27, tested 2026-11-16)

| Case | Result |
|---|---|
| Java / snakeyaml CVE-2022-1471, catalog methods | `exploitable`, sink resolved at ConfigLoader.java:17, 6 taint paths with hops |
| Go / jwt CVE-2025-30204, vendored deps, bare sink name `ParseWithClaims` | `exploitable`, caller `TokenService.Verify`, taint path to token.go:55 |
| Go / x/text CVE-2022-32149, vendored deps, bare sink name | callers `PreferredLanguage` (i18n.go:17) + `MatchStrings`, 0 taint paths → `not_exploitable` |
| Go, NOT vendored | sink unresolvable → no callers → proves nothing |
| Go sink named `github.com/golang-jwt/jwt.ParseWithClaims` (module-path prefix) | resolves to the wrong node / no callers — **bare symbol names are required** |

Facts that drive the design:

1. `go mod vendor` in the analysis clone brings external Go functions into
   rgctl's graph; sinks then resolve and callers/taint paths work.
2. rgctl 0.4.27 reads `affected[].ecosystem_specific.affected_methods` (same
   field the bridge's catalog merge already writes) and `affected_classes`.
3. `vuln analyze` output shape is unchanged from what `internal/osv` already
   parses (`exploitability`, `sink_taint.sink_callers/call_sites/paths`,
   `openvex`). New value `not_exploitable`; `deps_verdict` unchanged.
4. rgctl 0.4.27 linux-amd64 SHA256:
   `07b44dcfff911158359efa1e6fe752355d471d2b57a6cb16e4d8e8f536219428`.

## Goals

1. rgctl 0.4.27 in the bridge image, the agent image, and the vendored skill
   (skill at v0.4.27 has the P0–P6 vuln workflow, new verdict vocabulary and
   honesty fields).
2. Go reachability: the cve-remediation addon vendors dependencies in its
   analysis clone before `rgctl discover`, and Go sink names are bare symbols.
   With that, `externalCalls` is true for Go and verdicts become
   exploitable/reachable instead of unknown.
3. A not-impacted case: the Java demo app gains a dependency with a CVE whose
   vulnerable method it never calls (guava CVE-2020-8908,
   `com.google.common.io.Files.createTempDir`), so rgctl proves
   `not_affected / vulnerable_code_not_in_execute_path` with zero-caller
   evidence.
4. End-to-end verification on the cluster: findings for both apps carry
   verdicts, callers, taint paths and call-site anchors in their facts.

## Non-goals

- JIRA-sourced CVEs (untouched; this story is TPA-only).
- Fixing rgctl's Go PDG gaps (no external-input taint for x/text; that is
  upstream). The bridge reports callers/blast-radius evidence honestly.
- Committing `vendor/` to the demo Go repo (vendoring is analysis-time only).

## Decisions (rulings)

- **R1 — Analysis-time vendoring.** The addon runs `go mod vendor` in its
  clone before rgctl indexing for Go projects; on failure it proceeds
  unvendored with the old `unknown` behavior. Nothing is ever committed.
- **R2 — Bare Go sink names.** catalog.yaml Go entries use bare symbol names;
  OSV-provided Go method names get their module-path prefix stripped during
  catalog/OSV merge.
- **R3 — `not_exploitable` mapping.** Existing fallthrough already yields
  reachable-when-called / unreachable-when-not; keep it, with the verdict
  reason noting rgctl's assessment.
- **R4 — Guava as the not-impacted case.** guava 28.2-jre (CVE-2020-8908,
  fixed 30.0) added to the Java demo app, used only through safe APIs;
  catalog entry names `Files.createTempDir`.
- **R5 — Skill upgrade via the existing vendor script** at v0.4.27.

## What's left to the builder

- Exact placement of the vendoring step in `cmd/cve-remediation` (before
  `Rgctl.Discover`, after clone checkout).
- Test strategy per file (existing test patterns: `pipeline_test.go`,
  `osv_test.go`).
