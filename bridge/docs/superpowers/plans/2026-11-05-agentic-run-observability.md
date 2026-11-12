# Agentic Run Observability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a durable transcript and log recorder plus streaming read endpoints to the MTA hub, and rebuild the UI's run pages with stage cards and Transcript · Logs · Details tabs. Deploy both to the dylan cluster.

**Architecture:** A recorder inside the hub attaches to each auto-mode AgentRun's ACP endpoint as a silent client. It appends run-session frames to `transcript.jsonl` and follows the pod's container logs into files under the bucket volume. Two hub endpoints stream these back, from the live pod or the saved file, with byte or line offsets so clients can resume after the route's 300s idle cut. The UI renders the transcript by feeding saved frames through the existing chat reducer, and shows logs in a terminal-style tab.

**Tech Stack:** Go 1.26, gin, gorilla/websocket, controller-runtime client, client-go (hub). React 18, PatternFly 6, @patternfly/chatbot, react-query, jest and testing-library (UI). OpenShift binary BuildConfigs.

**Spec:** `docs/superpowers/specs/2026-11-05-agentic-run-observability-design.md` (this repo). Read it before starting any task.

## Global Constraints

- Hub work: `~/git/mta-tackle2-hub`, new branch `agentic-observability` off `release-0.11` (`771b73b`). UI work: `~/git/mta-tackle2-ui-cve`, new branch `agentic-observability` off `rhtpa-cve-tab`. Deploy scripts: this repo, branch `nightly-cve-refresh`.
- No hub DB schema change: no new gorm models and no new `internal/migration/v24`. Recordings are plain files.
- Recording root: `<Settings.Hub.Bucket.Path>/agentruns/<run-name>-<run-uid>/`, containing `transcript.jsonl`, `agent.log`, `skill-loader.log`, `meta.json`.
- The recorder never attaches to a run with `spec.execution.mode == "approve"` or `spec.execution.askUser == true`. The vendored `agent.ExecutionSpec` has **no `AskUser` field**, so read both from the unstructured object.
- The recorder never sends `session/prompt`, `session/load`, steer, or cancel. It sends only `initialize` and `session/new`.
- New endpoints use the existing `agentic.agentruns` scope.
- Cluster: default kubeconfig (`unset KUBECONFIG`), context `openshift-mta/api-dylan-mg-dog8code-com:6443/kube:admin`, namespace `openshift-mta`. `mta-operator` is at 0 replicas.
- UI rules (repo CLAUDE.md): every user-facing string goes through `react-i18next` (`client/public/locales/en/translation.json`); kebab-case filenames; `id != null` checks; import order react → external → @patternfly → @app → relative.
- The route `mta` has `haproxy.router.openshift.io/timeout: 300s`. Every follow stream must resume from an offset when the connection drops.

## Review Focus

1. **A follow stream cut after 300s idle mid-run:** the UI resumes from its last offset with no duplicated or missing lines. Owned by Task 9 (`resumes from offset after stream end`).
2. **A run that is already terminal before the hub ever saw it** (hub down for the whole run): the logs endpoint still serves the live pod log, and the transcript endpoint returns 404, shown as "No transcript was recorded". Owned by Task 6 (`terminal run with no recording`).
3. **A hub restart mid-run:** log capture resumes at the saved byte size without duplicating lines, and the transcript gets one gap marker. Owned by Task 3 (`gap marker on reconnect`) and Task 4 (`resume skips saved bytes`).
4. **A large log (over 50k lines) or transcript:** the Logs tab stays responsive by rendering only the last 5,000 lines with a "showing last 5000 of N lines" notice. Owned by Task 10 (`caps rendered lines`).
5. **A partial NDJSON line at a chunk boundary:** the stream parser buffers until the newline and never drops or garbles a frame. Owned by Task 9 (`splits frames across chunks`).

---

## Hub (`~/git/mta-tackle2-hub`)

### Task 1: Recording store

**Files:**
- Create: `internal/agentic/record/store.go`
- Test: `internal/agentic/record/store_test.go`

**Interfaces:**
- Produces:
  - `type Store struct { Root string }`. `Root` is `<bucket>/agentruns`.
  - `func (s *Store) Dir(name, uid string) string`
  - `type Meta struct { Run string; UID string; Transcript string /* "recording"|"complete"|"incomplete"|"skipped" */; SkipReason string; Gaps []Gap; Started, Ended *time.Time }` with JSON tags in lowerCamel.
  - `type Gap struct { From, To time.Time }`
  - `func (s *Store) ReadMeta(name, uid string) (Meta, bool, error)` and `func (s *Store) WriteMeta(name, uid string, m Meta) error`. Writes are atomic: temp file, then rename.
  - `func (s *Store) OpenAppend(name, uid, file string) (*os.File, int64, error)`. Creates the dir and file, and returns the current size.
  - `func (s *Store) Find(name string) (dir string, uid string, found bool)`. Returns the newest dir whose name prefix is `<name>-`, used when the CR is already gone.

- [ ] **Step 1:** Write tests `TestMetaRoundTrip`, `TestOpenAppendReturnsSize` (write 10 bytes, reopen, size == 10), and `TestFindNewest` (two dirs `run-a-uid1` and `run-a-uid2`, the second with a newer mtime, expect `uid2`).
- [ ] **Step 2:** Run `go test ./internal/agentic/record/ -run 'TestMeta|TestOpenAppend|TestFind'`. Expected: FAIL (package missing).
- [ ] **Step 3:** Implement `store.go`.
- [ ] **Step 4:** Run the same command. Expected: PASS.
- [ ] **Step 5:** Commit: `feat(agentic): recording store for agent run transcripts and logs`.

### Task 2: Recording gate and frame filter

**Files:**
- Create: `internal/agentic/record/gate.go`
- Test: `internal/agentic/record/gate_test.go`

**Interfaces:**
- Produces:
  - `func TranscriptAllowed(u *unstructured.Unstructured) (ok bool, reason string)`. Returns false with reason `"approve mode"` or `"askUser enabled"`.
  - `func RunFrame(raw []byte, ownSession string) (line []byte, keep bool)`. Keeps only JSON-RPC notifications (no `id`) whose method is `session/update` or `_goose/unstable/session/update` and whose `params.sessionId != ownSession`. The output line is `{"t":"<RFC3339Nano>","frame":<raw>}`.
  - `func GapLine(from, to time.Time) []byte` produces `{"gap":{"from":"…","to":"…"}}`.

- [ ] **Step 1:** Write the tests:
  - `TestTranscriptAllowed` table: no execution → true; `mode: auto` → true; `mode: approve` → false, "approve mode"; `askUser: true` → false, "askUser enabled".
  - `TestRunFrame`:
    - a run-session `session/update` is kept;
    - an own-session update is dropped;
    - a frame with an `id` (a response) is dropped;
    - a `_goose/unstable/session/update` is kept;
    - malformed JSON is dropped.
- [ ] **Step 2:** Run `go test ./internal/agentic/record/ -run 'TestTranscriptAllowed|TestRunFrame'`. Expected: FAIL.
- [ ] **Step 3:** Implement `gate.go`.
- [ ] **Step 4:** Run the tests. Expected: PASS.
- [ ] **Step 5:** Commit: `feat(agentic): recorder gate skips approve/askUser runs`.

### Task 3: Transcript capture

**Files:**
- Create: `internal/agentic/record/transcript.go`
- Test: `internal/agentic/record/transcript_test.go`

**Interfaces:**
- Consumes: `Store`, `RunFrame`, `GapLine`, `Meta` (Tasks 1–2).
- Produces: `type TranscriptCapture struct { Store *Store; Name, UID string; URL, Key string; Live func() bool }` with `func (c *TranscriptCapture) Run(ctx context.Context)`.
  - Dial `URL` with header `X-Secret-Key: Key`, the same as `AgentConn.Relay`.
  - Send `initialize` (`protocolVersion: 1`, `clientCapabilities: {}`), then `session/new` (`cwd: "/"`, `mcpServers: []`). Store the returned `sessionId` as the own session.
  - Append each kept frame and fsync about once a second.
  - On disconnect, if `Live()` is true: retry with backoff 1s→30s, and on reconnect append a `GapLine` and add a `Gap` to meta.
  - On end: set `Meta.Transcript` to `complete` (no gaps) or `incomplete`, and set `Ended`.

- [ ] **Step 1:** Write tests against an `httptest` websocket fake agent that answers `initialize` and `session/new` (`sessionId: "viewer-1"`), then sends three `session/update` frames for `run-1` and one for `viewer-1`, then closes:
  - `TestCaptureWritesRunFramesOnly`: three lines, meta `complete`.
  - `TestGapMarkerOnReconnect`: the fake drops after one frame, `Live()` returns true for the first reconnect, and the second connection sends two frames. Expect a gap line between them and meta `incomplete` with one Gap.
  - `TestNeverPrompts`: the fake records every method it receives. Expect exactly `["initialize","session/new"]` per connection.
- [ ] **Step 2:** Run `go test ./internal/agentic/record/ -run TestCapture\|TestGap\|TestNever`. Expected: FAIL.
- [ ] **Step 3:** Implement `transcript.go`.
- [ ] **Step 4:** Run the tests. Expected: PASS.
- [ ] **Step 5:** Commit: `feat(agentic): silent ACP transcript capture with gap markers`.

### Task 4: Log capture

**Files:**
- Create: `internal/agentic/record/logs.go`
- Test: `internal/agentic/record/logs_test.go`

**Interfaces:**
- Consumes: `Store.OpenAppend`.
- Produces:
  - `type LogOpener func(ctx context.Context, pod, container string, follow bool) (io.ReadCloser, error)`
  - `func KubeLogOpener(cs kubernetes.Interface, ns string) LogOpener`
  - `type LogCapture struct { Store *Store; Name, UID, Container string; Open LogOpener }` with `func (c *LogCapture) Run(ctx context.Context) error`. It opens with follow, skips the first `size` bytes of the stream (the same approach as `task.LogCollector.copy`), and appends the rest to `<container>.log`.

- [ ] **Step 1:** Write the tests:
  - `TestLogCaptureCopies`: the fake opener returns "a\nb\n" and the file contains "a\nb\n".
  - `TestResumeSkipsSavedBytes`: the file already holds "a\n", the opener returns "a\nb\n", and the file ends as "a\nb\n".
- [ ] **Step 2:** Run `go test ./internal/agentic/record/ -run TestLogCapture\|TestResume`. Expected: FAIL.
- [ ] **Step 3:** Implement `logs.go`.
- [ ] **Step 4:** Run the tests. Expected: PASS.
- [ ] **Step 5:** Commit: `feat(agentic): resumable pod log capture`.

### Task 5: Recorder manager wired into the hub

**Files:**
- Create: `internal/agentic/record/manager.go`
- Test: `internal/agentic/record/manager_test.go`
- Modify: `cmd/main.go` (start the manager next to the other managers, around line 165)

**Interfaces:**
- Consumes: Tasks 1–4.
- Produces: `type Manager struct { Client client.Client; Store *Store; Logs LogOpener; KeyFor func(ctx context.Context, secretName string) (string, error); URLFor func(sandbox string) string; Interval time.Duration /* 2s */ }` with `func (m *Manager) Run(ctx context.Context)`.
  - Every `Interval`, list AgentRuns in `Settings.Hub.Namespace` as `unstructured.UnstructuredList` (GVK `konveyor.io/v1alpha1, AgentRunList`).
  - Per uid, start at most one LogCapture for `agent` once the pod's container has started, and one for `skill-loader` once it has terminated.
  - Start a TranscriptCapture when `TranscriptAllowed` is true and `ACPReady=True` and the run isn't terminal. Otherwise write meta `skipped` with the reason.
  - `Live` reads the latest observed phase.
- In `main.go`:
  - Build `KeyFor` from the same secret-key lookup as `AgenticHandler.acpKey`. Move that lookup to a shared func, such as `api.ACPKey(ctx, client, name)`, rather than duplicating it.
  - `URLFor` uses `ws://<sandbox>.<ns>.svc:<ACPPort>/acp`.
  - Run `go manager.Run(ctx)`.

- [ ] **Step 1:** Write tests with a fake controller-runtime client (`sigs.k8s.io/controller-runtime/pkg/client/fake`) and stub captures (inject factories via unexported fields for testing):
  - `TestStartsTranscriptWhenACPReady`
  - `TestSkipsApproveMode`: meta is `skipped` with "approve mode" and no transcript capture starts.
  - `TestOneCapturePerUID`: two ticks start one capture.
  - `TestNoTranscriptForTerminalRun`
- [ ] **Step 2:** Run `go test ./internal/agentic/record/ -run TestStarts\|TestSkips\|TestOne\|TestNoTranscript`. Expected: FAIL.
- [ ] **Step 3:** Implement `manager.go` and wire it into `main.go`.
- [ ] **Step 4:** Run `go test ./internal/agentic/... ./internal/api/... && go build ./...`. Expected: PASS, and the build succeeds.
- [ ] **Step 5:** Commit: `feat(agentic): run recorder manager`.

### Task 6: Logs and transcript endpoints

**Files:**
- Modify: `shared/api/pkg.go` (add `AgenticAgentRunLogsRoute = AgenticAgentRunRoute + "/logs"` and `AgenticAgentRunTranscriptRoute = AgenticAgentRunRoute + "/transcript"`)
- Modify: `internal/api/agentic.go` (register both under the `agentic.agentruns` group, next to `AgentRunGet`)
- Create: `internal/api/agentic_record.go`
- Test: `internal/api/agentic_record_test.go`

**Interfaces:**
- Consumes: `record.Store` (via `Find`, `ReadMeta`, `Dir`) and `record.LogOpener`.
- Produces HTTP:
  - `GET …/logs?container=agent&follow=true|false&offset=<bytes>` returns `text/plain`, streamed and flushed per chunk.
    - Source: if the pod exists and the run isn't terminal, the live kube stream, skipping `offset` bytes. Otherwise the saved file from `offset`, and if the run is live and the file is still growing, tail it.
    - Headers: `X-Log-Source: live|saved`. 404 if there's neither a pod nor a file.
  - `GET …/transcript?follow=true|false&offset=<lines>` returns `application/x-ndjson`, starting from line `offset`. With `follow`, it polls the file every 500ms until meta is no longer `recording`.
    - Headers: `X-Transcript-Status: <meta.transcript>`, plus `X-Transcript-Skip-Reason` when skipped.
    - Returns 404 with `X-Transcript-Status: none` when there's no dir.
    - Returns 200 with an empty body and the `skipped` header when the run was skipped.

- [ ] **Step 1:** Write the gin `httptest` tests:
  - `TestLogsSavedFromOffset`: the file holds "abcdef", `offset=2` returns "cdef" with source `saved`.
  - `TestLogsLivePreferred`: a fake opener for a live run gives source `live`.
  - `TestTranscriptOffsetLines`
  - `TestTranscriptSkippedHeader`
  - `TestTerminalRunNoRecording`: the logs endpoint uses the live pod if one exists, and the transcript endpoint returns 404 with `none`.
- [ ] **Step 2:** Run `go test ./internal/api/ -run 'TestLogs|TestTranscript|TestTerminalRun'`. Expected: FAIL.
- [ ] **Step 3:** Implement the handlers. Use `ctx.Writer.Flush()` after each write, and stop when the request context is done.
- [ ] **Step 4:** Run the tests. Expected: PASS. Then run `go vet ./...`, which should be clean.
- [ ] **Step 5:** Commit: `feat(agentic): logs and transcript read endpoints`.

### Task 7: Build and deploy the custom hub (bridge repo)

**Files:**
- Create: `~/git/mta-rhtpa-bridge/images/hub/Dockerfile`. This is a copy of the hub's `konflux.Dockerfile` with the `report` stage changed to `FROM registry.redhat.io/mta/mta-hub-rhel9@sha256:76f433d71711b0c261da9eca6cc7174cff4aa8a99047edfed34d5a63949431f0 AS report`, still copying `/tmp/analysis/report`.
- Create: `~/git/mta-rhtpa-bridge/deploy/hub-custom-build.yaml` (ImageStream and binary Docker BuildConfig `mta-hub-custom`, matching the existing `mta-ui-cve` objects)
- Create: `~/git/mta-rhtpa-bridge/hack/build-hub.sh`, modeled on `hack/build-ui.sh`

**Interfaces:**
- `build-hub.sh` does the following:
  1. **Migration guard.** Compare the highest `internal/migration/vNN` in the source with `kubectl exec deploy/mta-hub -- ls /database/migration | sort -n | tail -1`. Abort if the source is higher.
  2. Tar `${HUB_DIR:-$HOME/git/mta-tackle2-hub}`, excluding `.git`, with `images/hub/Dockerfile` placed at the archive root as `Dockerfile`.
  3. Run `oc start-build mta-hub-custom --from-archive --follow --wait`.
  4. Pin the image by digest, then `kubectl set image deploy/mta-hub mta-hub=<digest ref>`.
  5. Run `rollout status`.
  6. Print the revert command, which uses the stock digest above.

- [ ] **Step 1:** Create the files and `oc apply -f deploy/hub-custom-build.yaml`. Expected: the ImageStream and BuildConfig are created.
- [ ] **Step 2:** Run `hack/build-hub.sh`. Expected: the build completes, the rollout succeeds, and the hub pod is Running with `Started:` in its log and no migration lines.
- [ ] **Step 3:** Verify the endpoints with a hub token (log in as admin through `/hub/oidc` or use an existing token):
  - `curl -s -H "Authorization: Bearer $T" https://mta-openshift-mta.apps.dylan.mg.dog8code.com/hub/agentic/agentruns/ui-drfxw-execute/logs | tail -3` should end with the `index-pack failed` line and `X-Log-Source: live`.
  - The `transcript` endpoint for the same run should return 404 with `none`, because that run predates the recorder.
- [ ] **Step 4:** Commit to the bridge repo: `feat: custom hub build with agent run recorder`.

## UI (`~/git/mta-tackle2-ui-cve`)

### Task 8: Readable failure text

**Files:**
- Modify: `client/src/app/pages/agent-runs/runOutcome.ts` (`unwrapStopReason`)
- Test: `client/src/app/pages/agent-runs/runOutcome.test.ts`

**Interfaces:**
- Produces: `unwrapStopReason(message?: string): string | undefined` now also handles `"<prefix>: {json}"`. It returns `"<prefix>: <stopReason>"` and strips C0 control characters other than `\n`.

- [ ] **Step 1:** Add the test `unwraps a workflow-prefixed termination message`. Input (verbatim from the `ui-drfxw` workflow condition):
  `Stage "execute" did not succeed: {"exitCode":1,"outcome":"failed","stopReason":"final push: push konveyor/migration-1793928293: malformed unpack status: \u0001001dunpack index-pack failed","usage":{"turnsUsed":67,"contextUsed":114330,"contextSize":128000}}`
  Expected: `Stage "execute" did not succeed: final push: push konveyor/migration-1793928293: malformed unpack status: 001dunpack index-pack failed`
- [ ] **Step 2:** Run `cd client && npm test -- runOutcome`. Expected: FAIL.
- [ ] **Step 3:** Implement the change.
- [ ] **Step 4:** Run `npm test -- runOutcome RunConditionSummary`. Expected: PASS.
- [ ] **Step 5:** Commit: `fix(agentic): readable stop reason for prefixed workflow failures`.

### Task 9: Transcript model extraction and stream client

**Files:**
- Create: `client/src/app/pages/agent-runs/transcript/transcript-model.ts`. Move into it, unchanged, the `ChatItem` types, the `RunUsage` type, `reduceUpdate`, `mergeUsage`, `statusMessageOf`, `gooseMeta`, and the helpers they use from `ChatPanel.tsx`. Export them, and have `ChatPanel.tsx` import them.
- Create: `client/src/app/api/rest/agent-run-streams.ts`
- Test: `client/src/app/pages/agent-runs/transcript/transcript-model.test.ts`, `client/src/app/api/rest/agent-run-streams.test.ts`

**Interfaces:**
- Produces:
  - `frameToUpdate(frame: unknown): { update: SessionUpdate; sessionId: string } | undefined`. This uses the same rules as `AcpSession.handleNotification`, including both methods.
  - `type RecordedLine = { t: string; frame: unknown } | { gap: { from: string; to: string } }`
  - `replayTranscript(lines: RecordedLine[]): { items: ChatItem[]; usage: RunUsage | null; gaps: { from: string; to: string; afterItemId: number }[] }`
  - `type StreamStatus = { source?: "live" | "saved"; transcript?: "recording" | "complete" | "incomplete" | "skipped" | "none"; skipReason?: string }`
  - `streamAgentRunLogs(name: string, opts: { container?: string; follow: boolean; onChunk: (text: string) => void; onStatus?: (s: StreamStatus) => void; signal: AbortSignal; isLive: () => boolean }): Promise<void>`
  - `streamAgentRunTranscript(name: string, opts: { follow: boolean; onLine: (l: RecordedLine) => void; onStatus?: (s: StreamStatus) => void; signal: AbortSignal; isLive: () => boolean }): Promise<void>`
  - Both use `fetch` on `/hub/agentic/agentruns/<name>/…`, with `Authorization: Bearer ${(await userManager.getUser())?.access_token}` when auth is required (`isAuthRequired`). They track the offset: bytes for logs, complete lines for transcripts. When a stream ends with no abort and `isLive()` is still true, they re-request from that offset after 1s.

- [ ] **Step 1:** Write the tests:
  - `replays recorded frames to the same items as live updates`: feed the same three updates through `reduceUpdate` directly and through `replayTranscript`, and expect deep-equal items, ignoring `at`.
  - `records gap position`
  - `splits frames across chunks`: a mocked fetch body yields `'{"t":"1","frame":{'` and then `'…}}\n'`, giving one `onLine`.
  - `resumes from offset after stream end`: the first response delivers 2 lines and ends while `isLive()` is true, the second request carries `offset=2`, and there are no duplicates.
- [ ] **Step 2:** Run `npm test -- transcript-model agent-run-streams`. Expected: FAIL.
- [ ] **Step 3:** Implement the code. The move is mechanical, so ChatPanel's behavior must not change.
- [ ] **Step 4:** Run `npm test -- transcript-model agent-run-streams ChatPanel workflow-run-detail-page && npm run tsc`. Expected: PASS.
- [ ] **Step 5:** Commit: `refactor(agentic): extract transcript model; add run stream client`.

### Task 10: Logs tab

**Files:**
- Create: `client/src/app/pages/agent-runs/components/run-logs-tab.tsx`, `client/src/app/pages/agent-runs/components/ansi.ts`
- Modify: `client/src/app/pages/agent-runs/agent-runs.css` (add `.run-logs-*` terminal styles: background `#1e1e1e`, text `#d4d4d4`, Red Hat Mono 12px, line-height 1.5)
- Test: `client/src/app/pages/agent-runs/components/run-logs-tab.test.tsx`

**Interfaces:**
- Consumes: `streamAgentRunLogs`.
- Produces:
  - `RunLogsTab(props: { runName: string; isLive: boolean })`
  - `ansiToSpans(line: string): { text: string; className?: string }[]`, covering SGR 0, 1, and 30–37/90–97. These map to `.ansi-<color>` classes.
- Behavior:
  - Follow is on by default. Scrolling up more than 40px from the bottom pauses follow, and a "Resume following" button turns it back on.
  - Toolbar: line count, a live or saved badge, Download (a Blob of the full buffered text named `<runName>-agent.log`), and Fullscreen (portal to `body`, the same as ChatPanel's expand).
  - Render at most the last 5,000 lines. Above that, show the `agentic.logs.truncated` notice, with `{{shown}}` and `{{total}}`.

- [ ] **Step 1:** Write the tests:
  - `renders streamed lines with ansi colors`: `"\x1b[33mWARN\x1b[0m x"` renders a span with class `ansi-yellow` containing "WARN".
  - `caps rendered lines`: 6,000 lines give 5,000 rows and the notice "Showing last 5000 of 6000 lines".
  - `pauses follow on scroll up`
- [ ] **Step 2:** Run `npm test -- run-logs-tab`. Expected: FAIL.
- [ ] **Step 3:** Implement the tab, and add i18n keys under `agentic.logs.*`: `title`, `live`, `saved`, `follow`, `resumeFollow`, `download`, `fullscreen`, `truncated`, `empty`, `notFound`.
- [ ] **Step 4:** Run `npm test -- run-logs-tab`. Expected: PASS.
- [ ] **Step 5:** Commit: `feat(agentic): terminal-style logs tab with live tail`.

### Task 11: Recorded transcript and run panel tabs

**Files:**
- Modify: `client/src/app/pages/agent-runs/components/ChatPanel.tsx` (export `ChatItemView`, `PinnedPlan`, and `UsageBadge` so they can be reused; no behavior change)
- Create: `client/src/app/pages/agent-runs/components/recorded-transcript.tsx`
- Create: `client/src/app/pages/agent-runs/components/run-details-tab.tsx`
- Create: `client/src/app/pages/agent-runs/components/run-panel.tsx`
- Modify: `client/src/app/pages/agent-runs/agent-run-detail-page.tsx` (replace the `<ChatPanel …/>` at about line 343 with `<RunPanel …/>`)
- Test: `client/src/app/pages/agent-runs/components/run-panel.test.tsx`

**Interfaces:**
- Consumes: `streamAgentRunTranscript`, `replayTranscript`, `RunLogsTab`, `ChatPanel`, and the exported item views.
- Produces:
  - `RecordedTranscript(props: { runName: string; agentRef?: string; isLive: boolean; targetBranch?: string })`. It renders inside the same `Chatbot` and `MessageBox` shell as ChatPanel, without a footer. Gaps render as `MessageDivider` items with `agentic.transcript.gap` ("Transcript incomplete: the recorder was disconnected for {{minutes}} minutes").
  - `RunPanel(props: { run: AgentRun; targetBranch?: string; stageInstructions?: string; tab?: RunPanelTab; onTabChange?: (t: RunPanelTab) => void })`, where `type RunPanelTab = "transcript" | "logs" | "details"`. It uses PatternFly `Tabs`.
- Transcript tab decision:
  - If `spec.execution.mode === "approve"` or `spec.execution.askUser`: show `ChatPanel` while the run is live. Once it's finished, show `agentic.transcript.skipped` ("No transcript was recorded for this run: runs that can stop to ask a person aren't recorded, so they keep their fail-fast behavior. See the Logs tab.").
  - Otherwise: `RecordedTranscript`. If the status is `none`, show `agentic.transcript.none` ("No transcript was recorded for this run.").
- Default tab: `transcript`, except for a finished run whose transcript status is `none` or `skipped`, which defaults to `logs`.
- The Details tab shows agent, instructions (`stageInstructions ?? spec.instructions`), the AgentRun name, start, end, and duration, a conditions table (type, status, reason, message), skills (reuse `RunSkillsSummary`), and termination usage.

- [ ] **Step 1:** Write the tests:
  - `auto-mode run uses recorded transcript`
  - `approve-mode live run uses ChatPanel`
  - `finished run with no recording defaults to logs tab`
  - `details tab lists conditions`
- [ ] **Step 2:** Run `npm test -- run-panel`. Expected: FAIL.
- [ ] **Step 3:** Implement the components and the agent-run page change. Add the i18n keys `agentic.runPanel.{transcript,logs,details}` and `agentic.transcript.{gap,none,skipped,loading}`.
- [ ] **Step 4:** Run `npm test -- run-panel ChatPanel && npm run tsc`. Expected: PASS.
- [ ] **Step 5:** Commit: `feat(agentic): run panel with transcript, logs and details tabs`.

### Task 12: Workflow-run page, layout A

**Files:**
- Create: `client/src/app/pages/workflow-runs/components/stage-cards.tsx`
- Modify: `client/src/app/pages/workflow-runs/workflow-run-detail-page.tsx` (replace the `ProgressStepper` block, lines 253–300, and the live-stage section, lines 310–367)
- Modify: `client/src/app/queries/agent-runs.ts` (add `useFetchAgentRunsByNames(names: string[])`, which runs parallel `useQueries` on the same 5s poll and reuses `AGENT_RUN_QUERY_KEY`)
- Test: `client/src/app/pages/workflow-runs/workflow-run-detail-page.test.tsx` (extend the existing file)

**Interfaces:**
- Consumes: `RunPanel`, `useFetchAgentRunsByNames`, and `explanatoryMessage` (now fixed).
- Produces:
  - `StageCards(props: { stages: AgentWorkflowRunStageStatus[]; runs: Record<string, AgentRun | undefined>; selected: string; onSelect: (stage: string) => void })`
  - `defaultStage(stages, currentStage): string`. Returns the running stage, else the failed one, else the last stage that has an `agentRunName`, else the first.
- Card content: status icon, name, `agentRef`, and duration. The duration comes from the child run's `startTime` and `completionTime`, ticks every second while the stage is running, and uses the existing `formatDuration`. Each card also shows a `PhaseLabel`. Stages with no run show `agentic.workflowRuns.notStarted` ("Not started").
- The selection lives in the `?stage=` URL search param.
- Below the cards:
  - If the selected stage has a run, show `RunPanel` with `stageInstructions={stage.instructions}`.
  - Otherwise show its instructions and `agentic.workflowRuns.stageNotStarted` ("This stage hasn't started.").
- Keep the approve/auto notice above the panel while the selected stage is live.
- Header: the existing `RunConditionSummary`. It now prints readable text because of Task 8.

- [ ] **Step 1:** Extend the tests:
  - `renders a card per stage with agent and status`
  - `defaults selection to the failed stage`
  - `selecting a card updates ?stage`
  - `unstarted stage shows instructions`
  - `failure header has no raw JSON`, using the `ui-drfxw` condition message from Task 8 and asserting the text doesn't contain `"exitCode"`.
- [ ] **Step 2:** Run `npm test -- workflow-run-detail-page`. Expected: FAIL.
- [ ] **Step 3:** Implement the changes and add the i18n keys.
- [ ] **Step 4:** Run `npm test -- workflow-run-detail-page && npm run tsc && npm run lint`. Expected: PASS, with at most 20 lint warnings.
- [ ] **Step 5:** Commit: `feat(agentic): workflow run stage cards with per-stage run panel`.

### Task 13: BranchPanel copy

**Files:**
- Modify: `client/src/app/pages/agent-runs/components/BranchPanel.tsx` (the `feed === "not-pushed"` branch, around line 314), `client/public/locales/en/translation.json` (`agentic.runDetail.feedNotPushed`)

**Interfaces:**
- When the run is live and GitHub reports no branch: show `"Waiting for the first push"` (with a small spinner).
- When the run is terminal and there's no branch: show `"Nothing was pushed to this branch"`.
- Rate-limited: keep the existing honest copy.

- [ ] **Step 1:** Add the BranchPanel tests `live run without branch says waiting` and `finished run without branch says nothing pushed`, with fetch mocked to 404.
- [ ] **Step 2:** Run `npm test -- BranchPanel`. Expected: FAIL.
- [ ] **Step 3:** Implement the change.
- [ ] **Step 4:** Run `npm test -- BranchPanel`. Expected: PASS.
- [ ] **Step 5:** Commit: `fix(agentic): honest target-branch copy`.

### Task 14: Build, deploy, and verify on the cluster

**Files:**
- Modify: `~/git/mta-tackle2-ui-cve/.gitignore` (add `.superpowers/`)

- [ ] **Step 1:** Run `cd client && npm test && npm run tsc && npm run lint`. Expected: all pass.
- [ ] **Step 2:** Run `~/git/mta-rhtpa-bridge/hack/build-ui.sh`. Expected: the build succeeds and `mta-ui` rolls out.
- [ ] **Step 3:** Start a new `migiq-migration-multistage` workflow run from the UI for application 1 (or `cve-remediator-go` for a shorter run). With Chrome:
  - the workflow page shows stage cards;
  - the Logs tab tails live and matches `kubectl logs <run> -c agent --tail=5`;
  - reloading mid-run shows the earlier turns in Transcript.
- [ ] **Step 4:** After a stage finishes, reload. The Transcript is still there (status `complete`). Delete one finished run's pod with `kubectl delete pod`, and that run's Logs tab now shows the `saved` badge.
- [ ] **Step 5:** Restart the hub mid-run with `kubectl rollout restart deploy/mta-hub`. After it recovers, the transcript shows one gap divider, and the saved `agent.log` has no duplicated lines (`sort | uniq -d` on the timestamped lines is empty).
- [ ] **Step 6:** Check the approve-mode guard on the cluster. Create a single AgentRun with `execution.mode: approve`. Expected: the hub log says the recorder skipped it ("approve mode"), and its Transcript tab shows the live ChatPanel.
- [ ] **Step 7:** Commit: `chore: ignore brainstorm artifacts`. Report the results with screenshots.
