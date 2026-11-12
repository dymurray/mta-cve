# mta-cve — Automated CVE Remediation with MTA

A complete, self-contained installer and reference for the MTA ⇄ RHTPA automated
CVE remediation environment: applications added to MTA get an SBOM, vulnerabilities
are discovered from RHTPA and JIRA, and each one is remediated — by a scripted
dependency update when the fix is a drop-in, or by an AI agent (AgentRun) when the
library's API changed.

## Quick start

```bash
git clone https://github.com/dymurray/mta-cve.git
cd mta-cve
./install-mta.sh
```

One script brings up the whole environment on an OpenShift cluster you are
cluster-admin on: the public MTA operator (channel 8.3, `agentic_enabled`), RHTPA 3.1,
the bridge/agent/skills/UI images, and all CRs. Prerequisites: `oc`, `helm`, `jq`,
`go`, `git`. Credentials are generated into `bridge/.secrets.env` (gitignored);
`JIRA_URL`/`JIRA_EMAIL`/`JIRA_TOKEN` and `LLM_API_KEY` must be added by hand before
installing — the installer tells you when. See `./install-mta.sh --help`-style header
comments for `STEP=`, `SKIP_UI=`, `MTA_CHANNEL=`, `UI_DIR=`, `HARNESS_SRC=` knobs.

Then: add `https://github.com/dymurray/mta-cve-demo.git` as an application in the MTA
UI, tag it into the `konveyor-cves` archetype, and watch CVE-2022-42889 (auto-bump)
and CVE-2022-1471 (agent) get remediated.

## Documentation

| Document | Contents |
|---|---|
| [SYSTEM-OVERVIEW.md](SYSTEM-OVERVIEW.md) | How the system works end to end, every component, and the full provisioning runbook (what `install-mta.sh` automates, step by step) |
| [EXTERNAL-AGENTRUN-DRIVER.md](EXTERNAL-AGENTRUN-DRIVER.md) | Driving agentic CVE remediation from an external pipeline on a stock public MTA 8.3.3 — no MTA inventory, AgentRuns by API with examples |
| [bridge/README.md](bridge/README.md) | The bridge's own README: project-type support matrix, remediation behavior, reachability/OpenVEX, demo steps, gotchas |
| [bridge/CUSTOMIZATIONS.md](bridge/CUSTOMIZATIONS.md) | Everything customized versus a stock MTA install, resource by resource |

## Repository layout

```
install-mta.sh            one-shot installer (orchestrates bridge/hack/*)
bridge/                   the mta-rhtpa-bridge repo, vendored at the demo revision
  hack/                   setup/build scripts (env.sh is the shared environment)
  deploy/                 RHTPA helm values, MTA CRs, NetworkPolicy, BuildConfigs
  cmd/ internal/          bridge Go code (sbom-discovery, cve-watcher, jira-watcher,
                          cve-remediation, nightly-refresh)
  images/                 agent-cve and skills container images
  third_party/hub-shared  hub SDK vendored from migtools/mta-tackle2-hub@release-0.11
checkouts/                created at install time (custom UI + agent harness clones)
```

## Customized components and where their code lives

Everything customized for this environment is on public branches of Dylan's forks
(the installer clones the two it needs into `checkouts/`):

| Component | What it does | Code |
|---|---|---|
| **mta-rhtpa-bridge** | SBOM discovery addon, cve-watcher, jira-watcher, cve-remediation addon, nightly refresh, agent image, all deploy manifests and hack scripts (vendored here under `bridge/`) | [dymurray/mta-rhtpa-bridge](https://github.com/dymurray/mta-rhtpa-bridge) · branch [`jira-cve-source`](https://github.com/dymurray/mta-rhtpa-bridge/tree/jira-cve-source) |
| **mta-tackle2-ui (custom)** | Vulnerabilities tab, CVE config admin panel, agent-runs/agents/workflows pages, JIRA links | [dymurray/tackle2-ui](https://github.com/dymurray/tackle2-ui) · branch [`agentic-observability`](https://github.com/dymurray/tackle2-ui/tree/agentic-observability) |
| **mta-tackle2-hub (custom)** | Custom hub build paired with the custom UI (agentic observability) | [dymurray/tackle2-hub](https://github.com/dymurray/tackle2-hub) · branch [`agentic-observability`](https://github.com/dymurray/tackle2-hub/tree/agentic-observability) |
| **agentic-controller harness** | The `migration-harness` that runs inside AgentRun pods; this branch adds `HARNESS_PUSH_URL` (push to a fork while cloning upstream). Built into the agent image. | [dymurray/agentic-controller](https://github.com/dymurray/agentic-controller) · branch [`harness-push-url`](https://github.com/dymurray/agentic-controller/tree/harness-push-url) |
| **tackle2-addon-discovery fix** | Language-weight threshold so sparse repos aren't mis-tagged (e.g. kai tagged `java` from 2 fixture files) | [konveyor/tackle2-addon-discovery#48](https://github.com/konveyor/tackle2-addon-discovery/pull/48) from [dymurray/tackle2-addon-discovery](https://github.com/dymurray/tackle2-addon-discovery) · branch [`language-weight-threshold`](https://github.com/dymurray/tackle2-addon-discovery/tree/language-weight-threshold) |
| **agent base image** | Public goose-harness runtime the agent image builds on | [quay.io/dymurray/agent-migiq](https://quay.io/repository/dymurray/agent-migiq) |
| **claude skills** | ART/SPMM ticket + Jira drafting skills | [dymurray/claude-skills](https://github.com/dymurray/claude-skills) |
| **demo apps** | Java and Go apps with known-vulnerable dependencies | [dymurray/mta-cve-demo](https://github.com/dymurray/mta-cve-demo) · [dymurray/mta-cve-demo-go](https://github.com/dymurray/mta-cve-demo-go) |

Upstream bases: the bridge's hub SDK is vendored from
[migtools/mta-tackle2-hub@release-0.11](https://github.com/migtools/mta-tackle2-hub/tree/release-0.11)
(MTA 8.3.x); the custom UI is based on
[migtools/mta-tackle2-ui@release-0.11](https://github.com/migtools/mta-tackle2-ui/tree/release-0.11).

## Divergences from the live demo cluster

`bridge/` is a vendored snapshot of `jira-cve-source`, plus these installer
additions (kept only here):

- `hack/install-mta-operator.sh`, `hack/mint-hub-token.sh`, `hack/build-skills.sh` — new
- `deploy/mta/05-gateway.yaml` — the LLM Gateway CR (applied by hand on the demo
  cluster, now manifest-tracked), with its key from `LLM_API_KEY`
- `hack/setup-mta.sh` — creates the `enmaas-key` secret
- `hack/env.sh` — kubeconfig defaults to the ambient `KUBECONFIG` instead of
  Dylan's laptop path

The demo cluster itself runs the internal ART operator build (8.3.4) with the
operator scaled to 0; the installer uses the public OLM build (channel `8.3`, e.g.
8.3.3) with the operator left running.
