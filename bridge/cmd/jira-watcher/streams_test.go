package main

import (
	"log"
	"os"
	"strings"
	"testing"

	"github.com/dymurray/mta-rhtpa-bridge/internal/finding"
	"github.com/dymurray/mta-rhtpa-bridge/internal/jira"
	"github.com/konveyor/tackle2-hub/shared/api"
)

const streamMap = `
products:
  mta:
    jiraProject: MTA
    streams:
      mta-8.1:
        branch: release-0.9
      mta-8.2:
        branch: release-0.10
    images:
      img/demo:
        repo: https://github.com/example/mta-cve-demo.git
`

func streamTicket(key, stream string) jira.Ticket {
	tk := ticket(key, "pscomponent:img/demo")
	tk.Summary = "CVE fix " + key + " [" + stream + "]"
	return tk
}

func repoApp(id uint, name, branch string) *api.Application {
	return &api.Application{
		Resource:   api.Resource{ID: id},
		Name:       name,
		Repository: &api.Repository{Kind: "git", URL: "https://github.com/example/mta-cve-demo.git", Branch: branch},
	}
}

func TestPollPerProductProjects(t *testing.T) {
	fh := &fakeHub{facts: map[string]any{}}
	hubSrv := startHub(t, fh)
	fj := &fakeJIRA{byProject: map[string][]jira.Ticket{}}
	jiraSrv := fj.srv(t)
	w, _, _ := newTestWatcher(t, hubSrv, jiraSrv, `
products:
  mta:
    jiraProject: MTA
    images:
      img/a: {repo: "https://github.com/example/a.git"}
  cnv:
    jiraProject: CNV
    images:
      img/b: {repo: "https://github.com/example/b.git"}
`)
	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	fj.mu.Lock()
	defer fj.mu.Unlock()
	var mta, cnv bool
	for _, q := range fj.jqls {
		mta = mta || strings.HasPrefix(q, "project = MTA AND labels = \"pscomponent:img/a\"")
		cnv = cnv || strings.HasPrefix(q, "project = CNV AND labels = \"pscomponent:img/b\"")
	}
	if !mta || !cnv || len(fj.jqls) != 2 {
		t.Errorf("jqls = %v, want one search per product image", fj.jqls)
	}
}

func TestDispatchUsesStreamBranch(t *testing.T) {
	fh := &fakeHub{facts: map[string]any{}}
	hubSrv := startHub(t, fh)
	fj := &fakeJIRA{issueDesc: map[string]string{"MTA-1": "CVE-2024-1234"}}
	fj.tickets = []jira.Ticket{streamTicket("MTA-1", "mta-8.2")}
	jiraSrv := fj.srv(t)
	w, _, _ := newTestWatcher(t, hubSrv, jiraSrv, streamMap)
	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	if len(fh.repoApps()) != 1 {
		t.Fatalf("apps = %d, want 1", len(fh.repoApps()))
	}
	app := fh.repoApps()[0]
	if app.Repository.Branch != "release-0.10" || app.Name != "mta-cve-demo-release-0.10" {
		t.Errorf("app = %s branch %q, want mta-cve-demo-release-0.10 on release-0.10", app.Name, app.Repository.Branch)
	}
}

func TestStreamAppAdoptedWhenBranchMatches(t *testing.T) {
	fh := &fakeHub{facts: map[string]any{}}
	fh.apps = append(fh.apps, repoApp(1, "preexisting", "release-0.10"))
	fh.nextAppID = 1
	hubSrv := startHub(t, fh)
	fj := &fakeJIRA{issueDesc: map[string]string{"MTA-1": "CVE-2024-1234"}}
	fj.tickets = []jira.Ticket{streamTicket("MTA-1", "mta-8.2")}
	jiraSrv := fj.srv(t)
	w, _, _ := newTestWatcher(t, hubSrv, jiraSrv, streamMap)
	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	if len(fh.repoApps()) != 1 {
		t.Errorf("apps = %d, want the pre-existing app adopted", len(fh.repoApps()))
	}
}

func TestSecondStreamSeparateApp(t *testing.T) {
	fh := &fakeHub{facts: map[string]any{}}
	hubSrv := startHub(t, fh)
	fj := &fakeJIRA{issueDesc: map[string]string{"MTA-1": "CVE-2024-1234", "MTA-2": "CVE-2024-1234"}}
	fj.tickets = []jira.Ticket{streamTicket("MTA-1", "mta-8.1"), streamTicket("MTA-2", "mta-8.2")}
	jiraSrv := fj.srv(t)
	w, _, _ := newTestWatcher(t, hubSrv, jiraSrv, streamMap)
	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	if len(fh.repoApps()) != 2 {
		t.Fatalf("apps = %d, want 2", len(fh.repoApps()))
	}
	for _, app := range fh.repoApps() {
		// no SBOM yet: bootstrap tasks are fine, but give each an SBOM
		// and poll again to dispatch.
		fh.mu.Lock()
		fh.facts[idKey(app.ID, "rhtpa", "sbom")] = map[string]any{"id": "sbom"}
		fh.mu.Unlock()
	}
	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	f1, f2 := fh.fact(fh.repoApps()[0].ID, "cve", "CVE-2024-1234"), fh.fact(fh.repoApps()[1].ID, "cve", "CVE-2024-1234")
	if f1 == nil || f2 == nil || f1.JiraKey == f2.JiraKey {
		t.Errorf("findings = %+v / %+v, want one per stream app with distinct tickets", f1, f2)
	}
}

func idKey(id uint, source, key string) string {
	return strings.Join([]string{uitoa(id), source, key}, ":")
}

func uitoa(n uint) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

func TestUnknownStreamNotesOnce(t *testing.T) {
	fh := &fakeHub{facts: map[string]any{}}
	hubSrv := startHub(t, fh)
	fj := &fakeJIRA{issueDesc: map[string]string{"MTA-1": "CVE-2024-1234"}}
	fj.tickets = []jira.Ticket{streamTicket("MTA-1", "mta-9.9")}
	jiraSrv := fj.srv(t)
	w, _, _ := newTestWatcher(t, hubSrv, jiraSrv, streamMap)
	for i := 0; i < 2; i++ {
		if err := w.poll(); err != nil {
			t.Fatal(err)
		}
	}
	if len(fj.comments) != 1 || !strings.Contains(fj.comments[0], "mta-9.9") {
		t.Fatalf("comments = %v, want one note naming mta-9.9", fj.comments)
	}
	if len(fh.repoApps()) != 0 || len(fh.tasks) != 0 {
		t.Errorf("apps = %d tasks = %v, want none", len(fh.repoApps()), fh.taskKinds())
	}
}

func TestMainFindingNoTransition(t *testing.T) {
	fh := &fakeHub{facts: map[string]any{}}
	fh.apps = append(fh.apps, repoApp(1, "mta-cve-demo-release-0.10", "release-0.10"), repoApp(2, "mta-cve-demo-main", "main"))
	fh.facts["1:rhtpa:sbom"] = map[string]any{"id": "sbom-1"}
	fh.facts["2:cve:CVE-2024-1234"] = &finding.Finding{
		CVE: "CVE-2024-1234", Source: finding.SourceFieldJIRA, JiraKey: "MTA-1",
		Status: finding.StatusPullRequestOpen, JiraCommentState: finding.StatusDetected,
		PullRequestURL: "https://github.com/example/mta-cve-demo/pull/1",
	}
	hubSrv := startHub(t, fh)
	fj := &fakeJIRA{issueDesc: map[string]string{"MTA-1": "CVE-2024-1234"}}
	fj.tickets = []jira.Ticket{streamTicket("MTA-1", "mta-8.2")}
	jiraSrv := fj.srv(t)
	w, _, _ := newTestWatcher(t, hubSrv, jiraSrv, streamMap)
	w.prTransition = "POST"

	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	if len(fj.comments) != 1 || !strings.Contains(fj.comments[0], "Pull request") {
		t.Fatalf("comments = %v, want the main-app finding commented", fj.comments)
	}
	if len(fj.closed) != 0 {
		t.Fatalf("transitions = %v, want none for a main-branch finding", fj.closed)
	}
	if len(fj.assigned) != 0 {
		t.Fatalf("assigned = %v, want none for a main-branch finding", fj.assigned)
	}

	f := fh.fact(1, "cve", "CVE-2024-1234")
	f.Status = finding.StatusPullRequestOpen
	fh.mu.Lock()
	fh.facts["1:cve:CVE-2024-1234"] = f
	fh.mu.Unlock()
	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	if len(fj.closed) != 1 || fj.closed[0] != "MTA-1:41" {
		t.Errorf("transitions = %v, want [MTA-1:41] from the stream finding", fj.closed)
	}
}

const ownerMap = `
products:
  mta:
    jiraProject: MTA
    owner: product@example.com
    streams:
      mta-8.2:
        branch: release-0.10
        fixVersion: MTA 8.2.4
        owner: stream@example.com
    images:
      img/demo:
        repo: https://github.com/example/mta-cve-demo.git
`

func ownerJIRA() *fakeJIRA {
	return &fakeJIRA{
		issueDesc: map[string]string{"MTA-1": "CVE-2024-1234", "MTA-2": "CVE-2024-1234"},
		users:     map[string]string{"product@example.com": "acc-product", "stream@example.com": "acc-stream"},
	}
}

func TestFixVersionSetAtDispatch(t *testing.T) {
	fh := &fakeHub{facts: map[string]any{}}
	fh.apps = append(fh.apps, repoApp(1, "mta-cve-demo-release-0.10", "release-0.10"))
	fh.facts["1:rhtpa:sbom"] = map[string]any{"id": "sbom-1"}
	hubSrv := startHub(t, fh)
	fj := ownerJIRA()
	fj.tickets = []jira.Ticket{streamTicket("MTA-1", "mta-8.2")}
	jiraSrv := fj.srv(t)
	w, _, _ := newTestWatcher(t, hubSrv, jiraSrv, ownerMap)
	for i := 0; i < 2; i++ {
		if err := w.poll(); err != nil {
			t.Fatal(err)
		}
	}
	if len(fj.fixEdits) != 1 || fj.fixEdits[0] != "MTA-1: MTA 8.2.4" {
		t.Errorf("fixEdits = %v, want one edit setting MTA 8.2.4", fj.fixEdits)
	}
}

func TestUnknownStreamAssignsProductOwner(t *testing.T) {
	fh := &fakeHub{facts: map[string]any{}}
	hubSrv := startHub(t, fh)
	fj := ownerJIRA()
	fj.tickets = []jira.Ticket{streamTicket("MTA-1", "mta-9.9")}
	jiraSrv := fj.srv(t)
	w, _, _ := newTestWatcher(t, hubSrv, jiraSrv, ownerMap)
	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	if len(fj.assigned) != 1 || fj.assigned[0] != "MTA-1: acc-product" {
		t.Errorf("assigned = %v, want MTA-1 to the product owner", fj.assigned)
	}
}

func TestNeedsAttentionAssignsStreamOwner(t *testing.T) {
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
	w, _, _ := newTestWatcher(t, hubSrv, jiraSrv, ownerMap)
	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	if len(fj.assigned) != 1 || fj.assigned[0] != "MTA-1: acc-stream" {
		t.Errorf("assigned = %v, want MTA-1 to the stream owner", fj.assigned)
	}
}

func TestNoReassignWhenAlreadyOwner(t *testing.T) {
	fh := &fakeHub{facts: map[string]any{}}
	hubSrv := startHub(t, fh)
	fj := ownerJIRA()
	tk := streamTicket("MTA-1", "mta-9.9")
	tk.AssigneeID, tk.AssigneeEmail = "acc-product", "product@example.com"
	fj.tickets = []jira.Ticket{tk}
	jiraSrv := fj.srv(t)
	w, _, _ := newTestWatcher(t, hubSrv, jiraSrv, ownerMap)
	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	if len(fj.assigned) != 0 {
		t.Errorf("assigned = %v, want none", fj.assigned)
	}
}

func TestAccountLookupCached(t *testing.T) {
	fh := &fakeHub{facts: map[string]any{}}
	hubSrv := startHub(t, fh)
	fj := ownerJIRA()
	fj.tickets = []jira.Ticket{streamTicket("MTA-1", "mta-9.9"), streamTicket("MTA-2", "mta-9.8")}
	jiraSrv := fj.srv(t)
	w, _, _ := newTestWatcher(t, hubSrv, jiraSrv, ownerMap)
	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	if len(fj.assigned) != 2 || fj.userSearches != 1 {
		t.Errorf("assigned = %v searches = %d, want 2 assignments from 1 lookup", fj.assigned, fj.userSearches)
	}
}

func TestFailedAssignsStreamOwner(t *testing.T) {
	fh := &fakeHub{facts: map[string]any{}}
	fh.apps = append(fh.apps, repoApp(1, "mta-cve-demo-release-0.10", "release-0.10"))
	fh.facts["1:rhtpa:sbom"] = map[string]any{"id": "sbom-1"}
	fh.facts["1:cve:CVE-2024-1234"] = &finding.Finding{
		CVE: "CVE-2024-1234", Source: finding.SourceFieldJIRA, JiraKey: "MTA-1",
		Status: finding.StatusFailed, JiraCommentState: finding.StatusDetected,
	}
	hubSrv := startHub(t, fh)
	fj := ownerJIRA()
	fj.tickets = []jira.Ticket{streamTicket("MTA-1", "mta-8.2")}
	w, _, _ := newTestWatcher(t, hubSrv, fj.srv(t), ownerMap)
	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	if len(fj.assigned) != 1 || fj.assigned[0] != "MTA-1: acc-stream" {
		t.Errorf("assigned = %v, want MTA-1 to the stream owner", fj.assigned)
	}
}

func TestMainFindingNeverAssigns(t *testing.T) {
	fh := &fakeHub{facts: map[string]any{}}
	fh.apps = append(fh.apps, repoApp(1, "mta-cve-demo-release-0.10", "release-0.10"), repoApp(2, "mta-cve-demo-main", "main"))
	fh.facts["1:rhtpa:sbom"] = map[string]any{"id": "sbom-1"}
	fh.facts["2:cve:CVE-2024-1234"] = &finding.Finding{
		CVE: "CVE-2024-1234", Source: finding.SourceFieldJIRA, JiraKey: "MTA-1",
		Status: finding.StatusNeedsAttention, JiraCommentState: finding.StatusDetected,
	}
	hubSrv := startHub(t, fh)
	fj := ownerJIRA()
	fj.tickets = []jira.Ticket{streamTicket("MTA-1", "mta-8.2")}
	w, _, _ := newTestWatcher(t, hubSrv, fj.srv(t), ownerMap)
	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	if len(fj.comments) != 1 || len(fj.assigned) != 0 {
		t.Errorf("comments = %v assigned = %v, want the comment but no assignment", fj.comments, fj.assigned)
	}
}

func TestDeadEndAssignsOnce(t *testing.T) {
	fh := &fakeHub{facts: map[string]any{}}
	hubSrv := startHub(t, fh)
	fj := ownerJIRA()
	fj.tickets = []jira.Ticket{streamTicket("MTA-1", "mta-9.9")}
	w, _, _ := newTestWatcher(t, hubSrv, fj.srv(t), ownerMap)
	for i := 0; i < 3; i++ {
		if err := w.poll(); err != nil {
			t.Fatal(err)
		}
	}
	if len(fj.assigned) != 1 {
		t.Errorf("assigned = %v, want a single assignment across polls", fj.assigned)
	}
}

func TestUnknownOwnerLookupFailsOnce(t *testing.T) {
	fh := &fakeHub{facts: map[string]any{}}
	hubSrv := startHub(t, fh)
	fj := ownerJIRA()
	fj.users = map[string]string{}
	fj.tickets = []jira.Ticket{streamTicket("MTA-1", "mta-9.9")}
	w, _, _ := newTestWatcher(t, hubSrv, fj.srv(t), ownerMap)
	for i := 0; i < 3; i++ {
		if err := w.poll(); err != nil {
			t.Fatal(err)
		}
	}
	if fj.userSearches != 1 || len(fj.assigned) != 0 {
		t.Errorf("searches = %d assigned = %v, want one failed lookup and no assignment", fj.userSearches, fj.assigned)
	}
}

func TestDryRunSkipsFixVersionAndAssign(t *testing.T) {
	fh := &fakeHub{facts: map[string]any{}}
	fh.apps = append(fh.apps, repoApp(1, "mta-cve-demo-release-0.10", "release-0.10"))
	fh.facts["1:rhtpa:sbom"] = map[string]any{"id": "sbom-1"}
	hubSrv := startHub(t, fh)
	fj := ownerJIRA()
	fj.tickets = []jira.Ticket{streamTicket("MTA-1", "mta-8.2"), streamTicket("MTA-2", "mta-9.9")}
	w, _, _ := newTestWatcher(t, hubSrv, fj.srv(t), ownerMap)
	w.dryRun = true
	var logs strings.Builder
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	if len(fj.fixEdits) != 0 || len(fj.assigned) != 0 {
		t.Errorf("fixEdits = %v assigned = %v, want no writes in DRY_RUN", fj.fixEdits, fj.assigned)
	}
	for _, want := range []string{"would set fixVersion MTA 8.2.4", "MTA-2: would assign to product@example.com"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("log lacks %q:\n%s", want, logs.String())
		}
	}
}

func TestUnmappedAssignsStreamOwner(t *testing.T) {
	fh := &fakeHub{facts: map[string]any{}}
	hubSrv := startHub(t, fh)
	fj := ownerJIRA()
	tk := streamTicket("MTA-1", "mta-8.2")
	tk.Labels = append(tk.Labels, "pscomponent:img/other")
	fj.tickets = []jira.Ticket{tk}
	w, _, _ := newTestWatcher(t, hubSrv, fj.srv(t), ownerMap)
	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	if len(fj.assigned) != 1 || fj.assigned[0] != "MTA-1: acc-stream" {
		t.Errorf("assigned = %v, want the stream owner at the unmapped dead end", fj.assigned)
	}
}
