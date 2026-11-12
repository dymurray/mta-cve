package finding

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestUnreachable(t *testing.T) {
	var none *Reachability
	if none.Unreachable() {
		t.Error("nil reachability (rgctl did not run) must not be unreachable")
	}
	if !(&Reachability{Verdict: VerdictUnreachable}).Unreachable() {
		t.Error("unreachable verdict")
	}
	if (&Reachability{Verdict: VerdictUnknown}).Unreachable() {
		t.Error("unknown must not be treated as unreachable")
	}
}

func TestFailedAttempt(t *testing.T) {
	for status, want := range map[string]bool{
		StatusFailed: true, StatusAgentFailed: true, StatusNeedsAttention: true,
		StatusRemediated: false, StatusPullRequestOpen: false, StatusExhausted: false,
	} {
		if got := (&Finding{Status: status}).FailedAttempt(); got != want {
			t.Errorf("%s: %v", status, got)
		}
	}
	if (&Finding{Status: StatusNeedsAttention, NoFix: true}).FailedAttempt() {
		t.Error("no published fix is not a failed attempt")
	}
}

func TestSeverityTagged(t *testing.T) {
	for _, s := range []string{StatusRemediated, StatusNotAffected} {
		if SeverityTagged(s) {
			t.Errorf("%s must drop the tag", s)
		}
	}
	for _, s := range []string{StatusPullRequestOpen, StatusPullRequestClosed, StatusExhausted, StatusAgentSucceeded, StatusFailed} {
		if !SeverityTagged(s) {
			t.Errorf("%s must keep the tag", s)
		}
	}
}

func TestResetAttemptOutputs(t *testing.T) {
	f := &Finding{Branch: "b", PullRequestURL: "u", AgentRun: "r", NoFix: true, Attempts: 2}
	f.ResetAttemptOutputs()
	if f.Branch != "" || f.PullRequestURL != "" || f.AgentRun != "" || f.NoFix {
		t.Errorf("%+v", f)
	}
	if f.Attempts != 2 {
		t.Error("attempts must be kept")
	}
}

func TestFromJIRA(t *testing.T) {
	f := &Finding{}
	if f.FromJIRA() {
		t.Error("empty source is not JIRA")
	}
	f.Source = SourceFieldJIRA
	if !f.FromJIRA() {
		t.Error("source jira is JIRA")
	}
}

func TestSourceRoundTrip(t *testing.T) {
	b, err := json.Marshal(&Finding{CVE: "CVE-1", Status: StatusDetected})
	if err != nil {
		t.Fatal(err)
	}
	f := &Finding{}
	if err := json.Unmarshal(b, f); err != nil {
		t.Fatal(err)
	}
	if f.Source != "" {
		t.Errorf("source = %q, want empty (RHTPA default)", f.Source)
	}
	if strings.Contains(string(b), "source") {
		t.Errorf("empty source must stay off the wire (v1 shape): %s", b)
	}
}
