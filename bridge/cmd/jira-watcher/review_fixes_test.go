package main

import (
	"strings"
	"testing"

	"github.com/dymurray/mta-rhtpa-bridge/internal/finding"
	"github.com/dymurray/mta-rhtpa-bridge/internal/jira"
	"github.com/konveyor/tackle2-hub/shared/api"
)

const scriptModeMap = `
products:
  demo:
    jiraProject: MTA
    streams:
      demo-1:
        branch: release-1
    images:
      img/demo:
        repo: https://github.com/example/demo.git
        remediation: script
        autoClose: true
`

func demoApp() *api.Application {
	return &api.Application{
		Resource:   api.Resource{ID: 1},
		Name:       "demo",
		Repository: &api.Repository{Kind: "git", URL: "https://github.com/example/demo.git", Branch: "release-1"},
	}
}

// TestDispatchSkipsWhenLiveTaskExists: a task created whose finding save
// failed must not be joined by a second task on the next poll.
func TestDispatchSkipsWhenLiveTaskExists(t *testing.T) {
	fh := &fakeHub{facts: map[string]any{}}
	fh.apps = append(fh.apps, demoApp())
	fh.facts["1:rhtpa:sbom"] = map[string]any{"id": "sbom-1"}
	fh.tasks = append(fh.tasks, &api.Task{
		Resource:    api.Resource{ID: 7},
		Kind:        finding.KindRemediation,
		Name:        "demo-cve-2024-1234",
		Application: &api.Ref{ID: 1},
		State:       "Ready",
		Data:        api.Map{"cve": "CVE-2024-1234", "sbomId": "sbom-1"},
	})
	hubSrv := startHub(t, fh)
	fj := &fakeJIRA{issueDesc: map[string]string{"MTA-1": "CVE-2024-1234"}}
	fj.tickets = []jira.Ticket{ticket("MTA-1", "pscomponent:img/demo")}
	jiraSrv := fj.srv(t)
	w, _, _ := newTestWatcher(t, hubSrv, jiraSrv, imageMap)

	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	if len(fh.tasks) != 1 {
		t.Errorf("tasks = %v, want only the pre-existing live task", fh.taskKinds())
	}
	if fh.fact(1, "cve", "CVE-2024-1234") != nil {
		t.Error("finding must not be written while the live task owns it")
	}
}

// TestDispatchCancelsTaskWhenSaveFails: a task whose finding save fails is
// canceled, so the next poll can dispatch cleanly.
func TestDispatchCancelsTaskWhenSaveFails(t *testing.T) {
	fh := &fakeHub{facts: map[string]any{}, failFactPut: true}
	fh.apps = append(fh.apps, demoApp())
	fh.facts["1:rhtpa:sbom"] = map[string]any{"id": "sbom-1"}
	hubSrv := startHub(t, fh)
	fj := &fakeJIRA{issueDesc: map[string]string{"MTA-1": "CVE-2024-1234"}}
	fj.tickets = []jira.Ticket{ticket("MTA-1", "pscomponent:img/demo")}
	jiraSrv := fj.srv(t)
	w, _, _ := newTestWatcher(t, hubSrv, jiraSrv, imageMap)

	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	fh.mu.Lock()
	defer fh.mu.Unlock()
	if len(fh.tasks) != 1 {
		t.Fatalf("tasks = %v, want the created task", fh.taskKinds())
	}
	if len(fh.canceled) != 1 || fh.canceled[0] != fh.tasks[0].ID {
		t.Errorf("canceled = %v, want the created task canceled", fh.canceled)
	}
	if fh.tasks[0].State != "Canceled" {
		t.Errorf("task state = %q, want Canceled", fh.tasks[0].State)
	}
}

// TestFailedBootstrapNotResubmitted: a terminal (failed) sbom-discovery
// task must not be resubmitted every poll; the ticket is told once.
func TestFailedBootstrapNotResubmitted(t *testing.T) {
	fh := &fakeHub{facts: map[string]any{}}
	fh.apps = append(fh.apps, demoApp())
	fh.tasks = append(fh.tasks, &api.Task{
		Resource:    api.Resource{ID: 5},
		Kind:        finding.KindSBOM,
		Name:        "demo-sbom",
		Application: &api.Ref{ID: 1},
		State:       "Failed",
	})
	hubSrv := startHub(t, fh)
	fj := &fakeJIRA{issueDesc: map[string]string{"MTA-1": "CVE-2024-1234"}}
	fj.tickets = []jira.Ticket{ticket("MTA-1", "pscomponent:img/demo")}
	jiraSrv := fj.srv(t)
	w, _, _ := newTestWatcher(t, hubSrv, jiraSrv, imageMap)

	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	if len(fh.tasks) != 1 {
		t.Errorf("tasks = %v, want no resubmission after the failed bootstrap", fh.taskKinds())
	}
	if len(fj.comments) != 1 || !strings.Contains(fj.comments[0], "SBOM discovery") || !strings.Contains(fj.comments[0], "Failed") {
		t.Errorf("comments = %v, want one sbom-failed note", fj.comments)
	}
	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	if len(fh.tasks) != 1 || len(fj.comments) != 1 {
		t.Errorf("second poll: tasks = %v comments = %v, want no churn", fh.taskKinds(), fj.comments)
	}
}

// TestNoCVECommentNotRepeatedAfterRestart: one-off notes are deduplicated
// against the ticket's existing comments, not only in memory.
func TestNoCVECommentNotRepeatedAfterRestart(t *testing.T) {
	fh := &fakeHub{facts: map[string]any{}}
	hubSrv := startHub(t, fh)
	fj := &fakeJIRA{issueDesc: map[string]string{"MTA-1": "no ids here"}}
	fj.tickets = []jira.Ticket{ticket("MTA-1", "pscomponent:img/demo")}
	fj.comments = []string{
		"MTA-1: MTA CVE bridge: no CVE id could be parsed from this ticket; nothing will be analyzed. [mta-bridge-note:nocve]",
	}
	jiraSrv := fj.srv(t)
	w, _, _ := newTestWatcher(t, hubSrv, jiraSrv, imageMap) // fresh process: noted is empty

	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	if len(fj.comments) != 1 {
		t.Errorf("comments = %v, want the pre-existing one only (no repost after restart)", fj.comments)
	}
}

// TestStampsJIRAFieldsOnRHTPAFinding: when the cve-watcher created the
// finding first, the jira-watcher stamps the JIRA identity and the image's
// remediation mode onto it so comments and mode gates apply.
func TestStampsJIRAFieldsOnRHTPAFinding(t *testing.T) {
	fh := &fakeHub{facts: map[string]any{}}
	fh.apps = append(fh.apps, demoApp())
	fh.facts["1:rhtpa:sbom"] = map[string]any{"id": "sbom-1"}
	fh.facts["1:cve:CVE-2024-1234"] = &finding.Finding{
		CVE: "CVE-2024-1234", Schema: 2, Source: "rhtpa",
		Status: finding.StatusDetected,
	}
	hubSrv := startHub(t, fh)
	fj := &fakeJIRA{issueDesc: map[string]string{"MTA-1": "CVE-2024-1234"}}
	fj.tickets = []jira.Ticket{ticket("MTA-1", "pscomponent:img/demo")}
	jiraSrv := fj.srv(t)
	w, _, _ := newTestWatcher(t, hubSrv, jiraSrv, scriptModeMap)

	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	if len(fh.tasks) != 0 {
		t.Errorf("tasks = %v, want none (finding exists)", fh.taskKinds())
	}
	f := fh.fact(1, "cve", "CVE-2024-1234")
	if f == nil || f.JiraKey != "MTA-1" || f.Component != "img/demo" || f.RemediationMode != "script" {
		t.Errorf("finding = %+v, want JIRA identity + mode stamped", f)
	}
	if len(fj.comments) != 1 {
		t.Errorf("comments = %v, want the state comment now that the ticket owns the finding", fj.comments)
	}
}

// TestPollExcludesDoneTickets: the auto-close transition is Done, so the
// search must exclude both Closed and Done.
func TestPollExcludesDoneTickets(t *testing.T) {
	fh := &fakeHub{facts: map[string]any{}}
	hubSrv := startHub(t, fh)
	fj := &fakeJIRA{issueDesc: map[string]string{}}
	jiraSrv := fj.srv(t)
	w, _, _ := newTestWatcher(t, hubSrv, jiraSrv, imageMap)

	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	fj.mu.Lock()
	defer fj.mu.Unlock()
	if len(fj.jqls) == 0 {
		t.Fatal("no searches recorded")
	}
	for _, q := range fj.jqls {
		if !strings.Contains(q, "status not in (Closed, Done)") {
			t.Errorf("jql %q does not exclude Done", q)
		}
	}
}
