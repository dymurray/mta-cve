package main

import (
	"strings"
	"testing"

	"github.com/dymurray/mta-rhtpa-bridge/internal/finding"
	"github.com/dymurray/mta-rhtpa-bridge/internal/jira"
)

// An SBOM fact without purls is unknown, not "main is clean".
func TestMainGateEmptyPurlsIsUnknown(t *testing.T) {
	w, fh, fj := mainGateEnv(t, finding.StatusRemediated, testPkg, []string{})
	for i := 0; i < 2; i++ {
		if err := w.poll(); err != nil {
			t.Fatal(err)
		}
	}
	if len(fj.comments) != 0 || countRemediation(fh, 2) != 0 {
		t.Errorf("comments %v tasks %v, want no note and no dispatch", fj.comments, fh.taskKinds())
	}
}

func TestDeadEndAssignNotRepeatedAfterRestart(t *testing.T) {
	fh := &fakeHub{facts: map[string]any{}}
	hubSrv := startHub(t, fh)
	fj := ownerJIRA()
	fj.tickets = []jira.Ticket{streamTicket("MTA-1", "mta-9.9")}
	jiraSrv := fj.srv(t)
	w, _, _ := newTestWatcher(t, hubSrv, jiraSrv, ownerMap)
	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	w2, _, _ := newTestWatcher(t, hubSrv, jiraSrv, ownerMap) // restart
	if err := w2.poll(); err != nil {
		t.Fatal(err)
	}
	if len(fj.assigned) != 1 {
		t.Errorf("assigned = %v, want one assignment across a restart", fj.assigned)
	}
}

func TestFindingAssignNotRepeatedAfterRestart(t *testing.T) {
	fh := &fakeHub{facts: map[string]any{}}
	fh.apps = append(fh.apps, repoApp(1, "mta-cve-demo-release-0.10", "release-0.10"))
	fh.facts["1:rhtpa:sbom"] = map[string]any{"id": "sbom-1"}
	fh.facts["1:cve:CVE-2024-1234"] = &finding.Finding{
		CVE: "CVE-2024-1234", Source: finding.SourceFieldJIRA, JiraKey: "MTA-1",
		Status: finding.StatusNeedsAttention, JiraCommentState: finding.StatusDetected,
	}
	hubSrv := startHub(t, fh)
	fj := ownerJIRA()
	fj.tickets = []jira.Ticket{streamTicket("MTA-1", "mta-8.2")}
	jiraSrv := fj.srv(t)
	for i := 0; i < 2; i++ {
		w, _, _ := newTestWatcher(t, hubSrv, jiraSrv, ownerMap)
		if err := w.poll(); err != nil {
			t.Fatal(err)
		}
	}
	if len(fj.assigned) != 1 {
		t.Errorf("assigned = %v, want one", fj.assigned)
	}
}

func fixVersionEnv(t *testing.T) (*fakeJIRA, func() *Watcher) {
	fh := &fakeHub{facts: map[string]any{}}
	fh.apps = append(fh.apps, repoApp(1, "mta-cve-demo-release-0.10", "release-0.10"))
	fh.facts["1:rhtpa:sbom"] = map[string]any{"id": "sbom-1"}
	hubSrv := startHub(t, fh)
	fj := ownerJIRA()
	fj.tickets = []jira.Ticket{streamTicket("MTA-1", "mta-8.2")}
	jiraSrv := fj.srv(t)
	return fj, func() *Watcher {
		w, _, _ := newTestWatcher(t, hubSrv, jiraSrv, ownerMap)
		return w
	}
}

func TestFixVersionNotReappendedAfterReplacementOrRestart(t *testing.T) {
	fj, mk := fixVersionEnv(t)
	w := mk()
	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	if len(fj.fixEdits) != 1 {
		t.Fatalf("fixEdits = %v, want one", fj.fixEdits)
	}
	fj.fixVersions["MTA-1"] = []string{"Prodsec 1.0"} // prodsec replaces it
	for _, w := range []*Watcher{w, mk()} {
		if err := w.poll(); err != nil {
			t.Fatal(err)
		}
	}
	if len(fj.fixEdits) != 1 {
		t.Errorf("fixEdits = %v, want no re-append", fj.fixEdits)
	}
}

func TestTransientLookupErrorNotCached(t *testing.T) {
	fh := &fakeHub{facts: map[string]any{}}
	hubSrv := startHub(t, fh)
	fj := ownerJIRA()
	fj.userStatus = 503
	fj.tickets = []jira.Ticket{streamTicket("MTA-1", "mta-9.9")}
	w, _, _ := newTestWatcher(t, hubSrv, fj.srv(t), ownerMap)
	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	if len(fj.assigned) != 0 {
		t.Fatalf("assigned = %v", fj.assigned)
	}
	fj.userStatus = 0
	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	if len(fj.assigned) != 1 {
		t.Errorf("assigned = %v, want the retry to assign after the transient error", fj.assigned)
	}
}

func TestMainCleanNotePerRepoAndStreamNameCleared(t *testing.T) {
	w, _, fj := mainGateEnv(t, finding.StatusRemediated, testPkg, []string{"pkg:golang/other/x@1.0.0"})
	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	if n := countNotes(fj, "in https://github.com/example/demo.git"); n != 1 {
		t.Errorf("clean note must name the repo: %v", fj.comments)
	}
	if n := countNotes(fj, "mta-bridge-note:main-clean:CVE-2024-1234:https://github.com/example/demo.git"); n != 1 {
		t.Errorf("marker not per CVE+repo: %v", fj.comments)
	}
}

func TestMainFindingMessageHasNoStreamName(t *testing.T) {
	w, fh, _ := mainGateEnv(t, finding.StatusPullRequestOpen, testPkg, []string{"pkg:golang/github.com/foo/bar/v4@4.4.0"})
	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	f := fh.fact(2, "cve", "CVE-2024-1234")
	if f == nil || strings.Contains(f.Message, "demo-1") {
		t.Errorf("main finding message = %+v, must not name the stream", f)
	}
}
