package policy

import (
	"testing"
	"time"

	"github.com/dymurray/mta-rhtpa-bridge/internal/finding"
)

func TestDecide(t *testing.T) {
	t0 := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	f := func(fn func(*finding.Finding)) *finding.Finding {
		x := &finding.Finding{}
		fn(x)
		return x
	}
	st := func(s string) *finding.Finding { return &finding.Finding{Status: s} }
	tests := []struct {
		name string
		in   Input
		want Decision
	}{
		{"nil reported", Input{Reported: true}, Decision{Action: Dispatch, CountAttempt: true}},
		{"nil not reported", Input{}, Decision{Action: Skip}},
		{"unreported new sbom detected", Input{Finding: st(finding.StatusDetected), NewSBOM: true}, Decision{Action: Resolve}},
		{"unreported new sbom remediated", Input{Finding: st(finding.StatusRemediated), NewSBOM: true}, Decision{Action: Skip}},
		{"unreported new sbom notaffected", Input{Finding: st(finding.StatusNotAffected), NewSBOM: true}, Decision{Action: Skip}},
		{"unreported new sbom pr closed", Input{Finding: st(finding.StatusPullRequestClosed), NewSBOM: true}, Decision{Action: Skip}},
		{"unreported same sbom", Input{Finding: st(finding.StatusDetected)}, Decision{Action: Skip}},
		{"remediated reported", Input{Finding: st(finding.StatusRemediated), Reported: true}, Decision{Action: Dispatch, ResetAttempts: true, CountAttempt: true}},
		{"remediated attempts 3", Input{Finding: &finding.Finding{Status: finding.StatusRemediated, Attempts: 3}, Reported: true}, Decision{Action: Dispatch, ResetAttempts: true, CountAttempt: true}},
		{"remediated open pr reported", Input{Finding: &finding.Finding{Status: finding.StatusRemediated, PullRequestState: finding.PRStateOpen, PullRequestURL: "u"}, Reported: true, Nightly: true}, Decision{Action: RestorePR}},
		{"remediated merged pr reported", Input{Finding: &finding.Finding{Status: finding.StatusRemediated, PullRequestState: finding.PRStateMerged, PullRequestURL: "u", Attempts: 2}, Reported: true}, Decision{Action: Dispatch, ResetAttempts: true, CountAttempt: true}},
		{"remediated no pr fields reported", Input{Finding: &finding.Finding{Status: finding.StatusRemediated, Attempts: 1}, Reported: true}, Decision{Action: Dispatch, ResetAttempts: true, CountAttempt: true}},
		{"needs attention nofix unseeded", Input{
			Finding:  &finding.Finding{Status: finding.StatusNeedsAttention, NoFix: true},
			Reported: true, Fixed: []string{"1.2"}}, Decision{Action: SeedFixed}},
		{"notaffected", Input{Finding: st(finding.StatusNotAffected), Reported: true}, Decision{Action: Skip}},
		{"pr closed", Input{Finding: st(finding.StatusPullRequestClosed), Reported: true}, Decision{Action: Skip}},
		{"exhausted", Input{Finding: st(finding.StatusExhausted), Reported: true, Nightly: true}, Decision{Action: Skip}},
		{"agent succeeded", Input{Finding: st(finding.StatusAgentSucceeded), Reported: true}, Decision{Action: Skip}},
		{"agent running", Input{Finding: st(finding.StatusAgentRunning), Reported: true}, Decision{Action: Skip}},
		{"pr merged before sbom nightly", Input{
			Finding: f(func(x *finding.Finding) {
				x.Status = finding.StatusPullRequestOpen
				x.PullRequestState = finding.PRStateMerged
				x.PullRequestMergedAt = t0
			}),
			Reported: true, Nightly: true, SbomUploaded: t0.Add(time.Hour)}, Decision{Action: Dispatch, CountAttempt: true}},
		{"pr merged before sbom daytime", Input{
			Finding: f(func(x *finding.Finding) {
				x.Status = finding.StatusPullRequestOpen
				x.PullRequestState = finding.PRStateMerged
				x.PullRequestMergedAt = t0
			}),
			Reported: true, SbomUploaded: t0.Add(time.Hour)}, Decision{Action: Fail}},
		{"pr merged after sbom", Input{
			Finding: f(func(x *finding.Finding) {
				x.Status = finding.StatusPullRequestOpen
				x.PullRequestState = finding.PRStateMerged
				x.PullRequestMergedAt = t0
			}),
			Reported: true, Nightly: true, SbomUploaded: t0.Add(-time.Hour)}, Decision{Action: Skip}},
		{"pr open", Input{Finding: &finding.Finding{Status: finding.StatusPullRequestOpen, PullRequestState: finding.PRStateOpen}, Reported: true, Nightly: true}, Decision{Action: Skip}},
		{"pr merged exhausted", Input{
			Finding: f(func(x *finding.Finding) {
				x.Status = finding.StatusPullRequestOpen
				x.PullRequestState = finding.PRStateMerged
				x.PullRequestMergedAt = t0
				x.Attempts = 3
			}),
			Reported: true, SbomUploaded: t0.Add(time.Hour)}, Decision{Action: Exhaust}},
		{"detected running", Input{Finding: st(finding.StatusDetected), Reported: true, TaskState: "Running"}, Decision{Action: Skip}},
		{"analyzing pending", Input{Finding: st(finding.StatusAnalyzing), Reported: true, TaskState: "Pending"}, Decision{Action: Skip}},
		{"detected failed task daytime", Input{Finding: st(finding.StatusDetected), Reported: true, TaskState: "Failed"}, Decision{Action: Fail}},
		{"analyzing canceled daytime", Input{Finding: st(finding.StatusAnalyzing), Reported: true, TaskState: "Canceled"}, Decision{Action: Fail}},
		{"detected succeeded daytime", Input{Finding: st(finding.StatusDetected), Reported: true, TaskState: "Succeeded"}, Decision{Action: Fail}},
		{"detected gone daytime", Input{Finding: &finding.Finding{Status: finding.StatusDetected, TaskID: 5}, Reported: true, TaskState: "Gone"}, Decision{Action: Fail}},
		{"detected gone nightly", Input{Finding: &finding.Finding{Status: finding.StatusDetected, TaskID: 5, Attempts: 1}, Reported: true, TaskState: "Gone", Nightly: true}, Decision{Action: Dispatch, CountAttempt: true}},
		{"needs attention nofix same", Input{
			Finding:  &finding.Finding{Status: finding.StatusNeedsAttention, NoFix: true, FixedSeen: []string{"1.9.1", "1.10.0"}},
			Reported: true, Fixed: []string{"1.10.0", "1.9.1"}}, Decision{Action: Skip}},
		{"needs attention nofix dup", Input{
			Finding:  &finding.Finding{Status: finding.StatusNeedsAttention, NoFix: true, FixedSeen: []string{"1.9.1", "1.9.1"}},
			Reported: true, Fixed: []string{"1.9.1"}}, Decision{Action: Skip}},
		{"needs attention nofix new", Input{
			Finding:  &finding.Finding{Status: finding.StatusNeedsAttention, NoFix: true, FixedSeen: []string{"1.9.1", "1.10.0"}},
			Reported: true, Fixed: []string{"1.10.0", "1.11.0"}}, Decision{Action: Dispatch}},
		{"needs attention nofix none to some", Input{
			Finding:  &finding.Finding{Status: finding.StatusNeedsAttention, NoFix: true, Attempts: 1, LastAttemptAt: t0},
			Reported: true, Fixed: []string{"1.0"}}, Decision{Action: Dispatch}},
		{"needs attention legacy nofix none", Input{
			Finding:  &finding.Finding{Status: finding.StatusNeedsAttention, NoFix: true},
			Reported: true, Nightly: true}, Decision{Action: Skip}},
		{"needs attention nofix none", Input{
			Finding:  &finding.Finding{Status: finding.StatusNeedsAttention, NoFix: true},
			Reported: true, Nightly: true}, Decision{Action: Skip}},
		{"needs attention with fix daytime", Input{Finding: &finding.Finding{Status: finding.StatusNeedsAttention, Attempts: 1}, Reported: true}, Decision{Action: Skip}},
		{"needs attention with fix nightly", Input{Finding: &finding.Finding{Status: finding.StatusNeedsAttention, Attempts: 1}, Reported: true, Nightly: true}, Decision{Action: Dispatch, CountAttempt: true}},
		{"failed daytime processed", Input{Finding: &finding.Finding{Status: finding.StatusFailed, Attempts: 1}, Reported: true}, Decision{Action: Skip}},
		{"failed unprocessed", Input{Finding: st(finding.StatusFailed), Reported: true}, Decision{Action: Skip}},
		{"agent failed nightly", Input{Finding: &finding.Finding{Status: finding.StatusAgentFailed, Attempts: 2}, Reported: true, Nightly: true}, Decision{Action: Dispatch, CountAttempt: true}},
		{"failed attempts 3 nightly", Input{Finding: &finding.Finding{Status: finding.StatusFailed, Attempts: 3}, Reported: true, Nightly: true}, Decision{Action: Exhaust}},
		{"failed attempts 3 daytime", Input{Finding: &finding.Finding{Status: finding.StatusFailed, Attempts: 3}, Reported: true}, Decision{Action: Exhaust}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Decide(tc.in); got != tc.want {
				t.Errorf("Decide() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestMigrate(t *testing.T) {
	tests := []struct {
		name        string
		in          finding.Finding
		want        finding.Finding
		wantChanged bool
	}{
		{"url", finding.Finding{Status: finding.StatusRemediated, PullRequestURL: "u"},
			finding.Finding{Status: finding.StatusPullRequestOpen, PullRequestURL: "u", PullRequestState: finding.PRStateOpen, Schema: 2, Source: finding.SourceFieldRHTPA}, true},
		{"branch", finding.Finding{Status: finding.StatusRemediated, Branch: "b"},
			finding.Finding{Status: finding.StatusPullRequestOpen, Branch: "b", Schema: 2, Source: finding.SourceFieldRHTPA}, true},
		{"plain remediated", finding.Finding{Status: finding.StatusRemediated},
			finding.Finding{Status: finding.StatusRemediated, Schema: 2, Source: finding.SourceFieldRHTPA}, true},
		{"agent failed", finding.Finding{Status: finding.StatusAgentFailed},
			finding.Finding{Status: finding.StatusAgentFailed, Attempts: 1, Schema: 2, Source: finding.SourceFieldRHTPA}, true},
		{"legacy no fix", finding.Finding{Status: finding.StatusNeedsAttention, Strategy: finding.StrategyNone,
			StrategyReason: "No fixed upstream version is published for this package."},
			finding.Finding{Status: finding.StatusNeedsAttention, Strategy: finding.StrategyNone, NoFix: true, Schema: 2, Source: finding.SourceFieldRHTPA}, true},
		{"legacy needs attention with fix", finding.Finding{Status: finding.StatusNeedsAttention, Strategy: finding.StrategyNone,
			FixedVersion: "1.2", StrategyReason: "No fixed upstream version is published for this package."},
			finding.Finding{Status: finding.StatusNeedsAttention, Strategy: finding.StrategyNone, Attempts: 1, Schema: 2, Source: finding.SourceFieldRHTPA}, true},
		{"already migrated", finding.Finding{Schema: 2, Status: finding.StatusRemediated, Branch: "b"},
			finding.Finding{Schema: 2, Status: finding.StatusRemediated, Branch: "b"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.in
			changed := Migrate(&got)
			if changed != tc.wantChanged {
				t.Errorf("changed = %v, want %v", changed, tc.wantChanged)
			}
			if got.Status != tc.want.Status || got.PullRequestState != tc.want.PullRequestState ||
				got.Attempts != tc.want.Attempts || got.Schema != tc.want.Schema || got.NoFix != tc.want.NoFix || got.Source != tc.want.Source {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestMassResolve(t *testing.T) {
	open := func(sbom string) *finding.Finding {
		return &finding.Finding{Status: finding.StatusDetected, SbomID: sbom}
	}
	tests := []struct {
		name     string
		findings map[string]*finding.Finding
		reported map[string]bool
		want     bool
	}{
		{"all unreported old", map[string]*finding.Finding{"A": open("s1"), "B": open("s1")}, map[string]bool{}, true},
		{"one reported", map[string]*finding.Finding{"A": open("s1"), "B": open("s1")}, map[string]bool{"A": true}, false},
		{"one on current sbom", map[string]*finding.Finding{"A": open("s1"), "B": open("s2")}, map[string]bool{}, false},
		{"only closed", map[string]*finding.Finding{
			"A": {Status: finding.StatusRemediated, SbomID: "s1"},
			"B": {Status: finding.StatusNotAffected, SbomID: "s1"},
			"C": {Status: finding.StatusPullRequestClosed, SbomID: "s1"},
			"D": {Status: finding.StatusExhausted, SbomID: "s1"}}, map[string]bool{}, false},
		{"closed ignored", map[string]*finding.Finding{"A": open("s1"), "B": {Status: finding.StatusRemediated, SbomID: "s2"}}, map[string]bool{}, true},
		{"none", map[string]*finding.Finding{}, map[string]bool{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := MassResolve(tc.findings, tc.reported, "s2"); got != tc.want {
				t.Errorf("MassResolve() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestActionString(t *testing.T) {
	for a, want := range map[Action]string{
		Skip: "Skip", Dispatch: "Dispatch", Resolve: "Resolve", Fail: "Fail",
		Exhaust: "Exhaust", RestorePR: "RestorePR", SeedFixed: "SeedFixed", Action(99): "Action(99)",
	} {
		if got := a.String(); got != want {
			t.Errorf("%d: %q, want %q", int(a), got, want)
		}
	}
}

func TestMigrateSchema2(t *testing.T) {
	f := &finding.Finding{Schema: 1, Status: finding.StatusDetected}
	if changed := Migrate(f); !changed {
		t.Fatal("v1 finding must be migrated")
	}
	if f.Schema != 2 {
		t.Errorf("schema = %d, want 2", f.Schema)
	}
	if f.Source != finding.SourceFieldRHTPA {
		t.Errorf("source = %q, want %q", f.Source, finding.SourceFieldRHTPA)
	}
	if changed := Migrate(f); changed {
		t.Error("schema-2 finding must not be migrated again")
	}
}

func TestMassResolveSkipsJIRA(t *testing.T) {
	findings := map[string]*finding.Finding{
		"A": {Status: finding.StatusDetected, SbomID: "s1", Source: finding.SourceFieldJIRA},
	}
	if MassResolve(findings, map[string]bool{}, "s2") {
		t.Error("JIRA findings must not take part in RHTPA mass resolution")
	}
	rhtpaOnly := map[string]*finding.Finding{
		"A": {Status: finding.StatusDetected, SbomID: "s1"},
	}
	if !MassResolve(rhtpaOnly, map[string]bool{}, "s2") {
		t.Error("RHTPA finding must still mass resolve")
	}
}
