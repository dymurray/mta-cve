# Agentic run observability — design

Date: 2026-11-05
Status: draft, awaiting approval
Repos touched: `~/git/mta-tackle2-ui-cve` (UI), `~/git/mta-tackle2-hub` (hub, branch `release-0.11`), `~/git/mta-rhtpa-bridge` (build/deploy scripts)

## Intent

Watching an agentic run in the MTA console today is frustrating. The pages look
stale and placeholder-ish, a finished run shows almost nothing of what the agent
did, and there is no way to see the pod's raw output. The concrete trigger:
workflow run `ui-drfxw` failed in its `execute` stage. The pod log shows the
agent actually did the work (mvn package green, 9/9 tests, 49 subtasks), then
`worktree dirty at stage end — agent left 2562 uncommitted paths` and the final
push died with `index-pack failed`. The console showed only "Failed" plus a raw
JSON blob, and the 67-turn transcript was gone.

Success: open any run — live or finished, single AgentRun or multi-stage
workflow — and see clearly where it is, what each stage did, the agent's
transcript, and the raw pod log, without dropping to `kubectl`.

## Observed problems (from the live UI, 2026-11-05)

1. **Raw JSON failure text on the workflow-run page.** The workflow condition
   message is `Stage "execute" did not succeed: {"exitCode":1,...}`.
   `unwrapStopReason` (`client/src/app/pages/agent-runs/runOutcome.ts`) only
   parses messages that *start* with `{`, so the prefix defeats it and the blob
   (including a literal `\u0001` escape) is shown verbatim.
2. **Transcript vanishes once a run ends.** The ACP session lives in the pod;
   after the pod exits the agent-run page shows only a "The run failed" alert,
   and the workflow-run page hides the chat panel entirely
   (`liveStageOf` returns undefined when terminal).
3. **Thin stage stepper.** PatternFly `ProgressStepper` with name + "Open run"
   link or the word "Pending". No agent, no timing, no inline failure reason.
4. **"branch not pushed yet — the harness pushes after its first commit"**
   (`agentic.runDetail.feedNotPushed`, BranchPanel). The browser queries the
   unauthenticated GitHub REST API (60 req/hr/IP); the text appears whenever
   GitHub says the branch does not exist yet — i.e. every live stage before its
   first push — and reads as a stuck placeholder.
5. **No raw logs anywhere.** The hub has no logs endpoint.

## Goals

- **Workflow-run page, layout A (user-chosen):** stage cards across the top;
  below them, a tabbed panel for the selected stage: **Transcript · Logs · Details**.
- **Agent-run page:** the same Transcript · Logs · Details tabs.
- **Logs tab:** raw pod log in a dark terminal-style viewer, live tail with
  follow, works after the run ends.
- **Transcript saved after the run ends** (user requirement) and rendered
  identically to the live view.
- Pod logs also saved when the run ends, so the Logs tab survives pod cleanup.
- Human-readable failure reason everywhere; no raw JSON.
- Fix the BranchPanel placeholder text.
- Deploy all of it to the dylan cluster as custom images.

## Non-goals

- Fixing the `index-pack failed` push failure itself (harness / agent-skill
  problem — tracked separately).
- Any harness or agent-image change. Capture must work for every agent image
  unchanged (`agent-migiq`, `agent-cve`, stock `mta-agent-java-rhel9`).
- Upstreaming. This is a demo-cluster customization; keep diffs clean enough to
  upstream later, but don't design for upstream review now.
- Workflow-runs list page / agent-runs list page redesign.
- Steering UX changes (steer stays disabled on this cluster).

## Anti-goals (would make this a failure even if it technically works)

- The recorder changes a run's outcome or timing in auto mode.
- A DB schema migration on the hub. The hub runs a custom image against the
  operator-managed database; reverting to the stock `mta-hub-rhel9` image must
  remain a one-line image swap.
- The Logs tab shows a different story than `kubectl logs` (truncation without
  saying so, reordering, dropped lines).
- New placeholder-ish copy that claims a state the UI hasn't verified.

## Constraints and environment facts

- Cluster access: default kubeconfig, context
  `openshift-mta/api-dylan-mg-dog8code-com:6443/kube:admin`; namespace `openshift-mta`.
- `mta-operator` is scaled to 0, so deployment image edits stick.
  `hack/build-ui.sh` already handles this (patches the Tackle CR and the
  deployment directly).
- UI: `~/git/mta-tackle2-ui-cve`, branch `rhtpa-cve-tab`, built by
  `hack/build-ui.sh` into ImageStream `mta-ui-cve` via binary BuildConfig.
- Hub: deployed image is `registry.redhat.io/mta/mta-hub-rhel9@sha256:76f4…`
  (operator 8.3.2). Source `~/git/mta-tackle2-hub` `release-0.11`. Hub volumes:
  `/database` and `/buckets` (persistent).
- The hub ServiceAccount can already `get pods/log` in `openshift-mta` (verified).
- The hub already proxies ACP: `AgentRunConnect` → `AgentConn.Relay`
  (`internal/api/agentic.go`), reading the run's ACP key from
  `status.secretKeyRef` and dialing `status.sandboxName`.
- The hub already persists task pod logs (`internal/task/collector.go`,
  follow-stream into a file).
- AgentRun status gives: `phase`, `startTime`, `completionTime`, `sandboxName`,
  `secretKeyRef`, conditions incl. `ACPReady`, `terminationData`.
  Workflow-run stage status gives: `name`, `agentRef`, `agentRunName`,
  `instructions`, `phase`, `execution`. Child AgentRuns carry labels
  `konveyor.io/agentworkflowrun` and `konveyor.io/stage`.
- Pods: container `agent`, init container `skill-loader`. Pod name == AgentRun name.
- `ttlSecondsAfterFinished` exists on AgentRun but is unset today, so pods
  linger; don't rely on that.
- UI conventions (repo CLAUDE.md): all strings through `react-i18next`,
  kebab-case filenames, `id != null` checks, import order react → external →
  @patternfly → @app → relative.

## Design

### 1. Hub: run recorder (new)

A background component in the hub that, for every AgentRun in the hub
namespace:

- **Transcript:** when `ACPReady=True` and the run is not terminal, opens an
  ACP WebSocket to the sandbox exactly like `AgentConn` does (same key, same
  URL), sends `initialize` + `session/new` as a silent client, never prompts,
  and appends every inbound frame verbatim, one JSON object per line, with a
  receive timestamp, to `transcript.jsonl`. Reconnects with backoff while the
  run is live; records a `{"gap": {...}}` marker line for any disconnect window.
  Stops when the run is terminal or the socket closes for good.
- **Logs:** follows the `agent` container log (and `skill-loader` once,
  after it completes) into `agent.log` / `skill-loader.log`, resuming by byte
  offset after a hub restart, as `LogCollector` does.
- **Storage:** plain files under the bucket volume, e.g.
  `/buckets/agentruns/<run-name>-<run-uid>/`. No DB tables (see anti-goals).
  A small `meta.json` there records run name/uid, start/stop of capture, and
  whether the transcript is complete (no gaps) — **builder's call on exact layout.**
- **Discovery:** watch or poll AgentRuns (poll every few seconds is fine);
  idempotent per run uid so a hub restart resumes capture.
- **Retention:** keep until the AgentRun is deleted; builder may add a simple
  cap. **Builder's call.**

**Gaps are acceptable (user confirmed).** The harness starts prompting before
any viewer attaches, and the recorder attaches only after `ACPReady` is seen,
so the opening frames and any hub-restart window may be missing. Record them as
gaps in `meta.json` and show the "incomplete" banner. Do **not** call
`session/load` on the run's goose session to backfill. That touches the live
run, which the anti-goals forbid. Use a watch, or a ≤2s poll, on AgentRuns to
keep the opening gap small. *Watch vs. poll is the builder's call.*

**Runs that can ask a human are logs-only (user decision).** The harness tee
treats any attached client as a viewer. With zero viewers, permission asks and
`ask_user` fail fast to the headless policy (`forwardAsk` →
`ForwardNoViewers`). With a client attached they wait the 3-minute HITL timeout
instead, and `addViewer` resets the unresponsive guard on every reconnect. So
the recorder **must not attach** to a run whose `spec.execution.mode` is
`approve` or whose `spec.execution.askUser` is true. For those runs it captures
logs only, and writes `meta.json` with `transcript: "skipped"` and the reason.
Auto-mode runs, which is every run on this cluster today, are recorded.

### 2. Hub: read endpoints (new)

Under the existing `agentic.agentruns` scope:

- `GET /agentic/agentruns/{name}/logs?container=agent&follow=true&tailLines=N`
  — while the pod exists, stream straight from the kube API (chunked
  `text/plain`); when the pod is gone or the run is terminal, serve the saved
  file. Response header says which (`X-Log-Source: live|saved`).
- `GET /agentic/agentruns/{name}/transcript?follow=true|false`: the recorded
  frames as NDJSON, **available while the run is live too**. With
  `follow=true` the hub streams the file from the start, then keeps streaming
  new lines as the recorder appends them, and ends when capture ends.
  Completeness and skip status come from `meta.json` (a response header or a
  leading meta line; builder's call). Returns 404 when nothing was recorded.

The UI already proxies `/hub/*` to the hub, so no UI-server change is
expected; confirm streaming isn't buffered by the UI's proxy.

### 3. UI: shared run panel

A new tabbed component used by both detail pages:

- **Transcript tab: the full history, live or finished (user decision).**
  - **Recorded runs** (auto mode): render from the hub's
    `/transcript?follow=true` stream, live or finished, feeding the frames
    through the existing `reduceUpdate` reducer so the result looks identical
    to today (tools, plan, notices, diffs, usage). Opening or refreshing
    mid-run shows every turn so far, then keeps updating. Using one source
    means there's no join between saved and live frames to de-duplicate.
    *Call made by the designer.* The panel's own ACP dial is not used for
    content on these runs. If steering is enabled later, the steer and cancel
    controls may keep a control-only ACP connection; out of scope now.
  - **Runs the recorder skips** (approve mode or askUser): today's `ChatPanel`
    live connection, unchanged, so a person can still answer asks. After the
    run ends, the tab says "No transcript was recorded for this run: runs that
    can stop to ask a person aren't recorded, so they keep their fail-fast
    behavior. See the Logs tab."
  - Gaps: "Transcript incomplete: the recorder was disconnected for N
    minutes", shown inline where the gap falls when practical.
  - Refactor `reduceUpdate` and the item views out of `ChatPanel.tsx` only as
    far as needed to reuse them.
- **Logs tab.** Dark terminal-style viewer, monospace, ANSI color codes
  rendered (the harness emits them). Follow on by default; scrolling up pauses
  follow, a button resumes. Download, fullscreen, line count, live/saved
  indicator. Large logs: virtualize or cap the rendered lines with a clear
  "showing last N lines — download for full" note. Container picker only if
  more than one container has output.
- **Details tab.** Agent, stage instructions (workflow), AgentRun name + link,
  conditions table, skills, start/end/duration, termination usage.
- Default tab: Transcript when live; for finished runs the builder may pick
  Transcript if recorded, else Logs.

### 4. UI: workflow-run page (layout A)

- Header: phase label + one readable failure sentence: stage, stop reason,
  turns, context %. No raw JSON.
- Stage cards in a row: name, status icon, agent, duration (ticking while
  running), phase badge; unstarted stages say "Not started". Selected card is
  highlighted. Default selection: running stage, else failed stage, else last.
  Selection persisted in the URL (`?stage=execute`).
- Below: the shared run panel for the selected stage's AgentRun. Unstarted
  stage: show its instructions and "This stage hasn't started."
- Keep the existing approve-mode / auto-mode notice above the panel when live.
- Keep BranchPanel and Run-again.
- Timing comes from each stage's child AgentRun (`startTime`/`completionTime`);
  fetch the child runs (by name from stage status) on the existing poll.

### 5. UI: agent-run page

Replace the bare chat panel with the shared run panel. Header, metadata,
"Run details" expander, and Run-again stay.

### 6. UI fixes

- `unwrapStopReason`: find the JSON object inside a prefixed message, keep the
  prefix's meaning ("execute failed: <stopReason>"), strip control characters.
  Add a unit test with the real `ui-drfxw` message.
- BranchPanel: while a stage is running and GitHub reports no branch, show a
  neutral "Waiting for the first push" (or nothing) instead of the current
  sentence; show rate-limited state honestly. Builder may reduce GitHub polling.

### 7. Build and deploy

- **Source and Dockerfile (decided after checking the cluster):** deployed hub
  reports version 8.3.3, binary `/usr/local/bin/mta-hub` (no command override
  in the deployment — the image ENTRYPOINT is used), and `/database/migration`
  tops out at **v23**. `release-0.11` HEAD (`771b73b`) also tops out at v23, so
  building from it runs no schema migration. Build from `release-0.11` with
  the downstream `konflux.Dockerfile` (same binary path, `mta-branding`, repo
  `hack/build/seed`), except replace its `brew.registry.redhat.io` `report`
  stage by copying `/tmp/analysis/report` out of the currently deployed stock
  image (`registry.redhat.io/mta/mta-hub-rhel9@sha256:76f4…`, already pullable
  by the cluster). Keep this as a separate Dockerfile in the bridge repo or a
  build-arg; don't edit `konflux.Dockerfile` in place. *Call made by the
  designer.* Guard in the build script: refuse to deploy if the source's
  highest migration exceeds the deployed `/database/migration` level.
- New BuildConfig + ImageStream `mta-hub-custom` (binary Docker build of
  `~/git/mta-tackle2-hub` as above), and
  `hack/build-hub.sh` in the bridge repo modeled on `hack/build-ui.sh`: build,
  pin by digest, set `deploy/mta-hub` image, wait for rollout.
- Rebuild UI with existing `hack/build-ui.sh`.
- Record the stock hub image digest in the script/README so reverting is a
  one-line `set image`.

## Verification

- Unit tests: `unwrapStopReason` prefixed case; transcript replay through
  `reduceUpdate` yields the same items as live; logs endpoint live vs saved.
- On cluster: start a new single-stage run and a `migiq-migration-multistage`
  run; watch Logs tail live and match `kubectl logs`; after completion, reload —
  transcript and logs still render; delete the pod — logs still render
  (`X-Log-Source: saved`); restart the hub mid-run — transcript shows a gap
  marker and log capture resumes without duplication.
- Confirm an auto-mode run's outcome and duration are unaffected by the recorder.

- Open a live run mid-way: the Transcript shows the earlier turns and keeps
  streaming. Start an approve-mode run with no viewer: an ask still fails fast,
  as it does today, and the recorder logs that it skipped the run.

## Left to the builder

File layout under `/buckets`, transcript wire format, retention cap, polling vs
watch, log virtualization approach, exact copy (through i18n), component
boundaries in the UI.
