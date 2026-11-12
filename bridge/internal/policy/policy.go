// Package policy is the single place that decides whether a CVE gets a
// remediation task. It is pure: no hub access and no I/O.
package policy

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/dymurray/mta-rhtpa-bridge/internal/finding"
)

// Action is what the watcher does for a CVE.
type Action int

const (
	// Skip does nothing.
	Skip Action = iota
	// Dispatch creates a cve-remediation task.
	Dispatch
	// Resolve sets Remediated ("no longer reported for the latest SBOM").
	Resolve
	// Fail sets Failed (dead or incomplete attempt) without a task.
	Fail
	// Exhaust sets Exhausted.
	Exhaust
	// RestorePR sets PullRequestOpen again for a Remediated finding whose
	// pull request is still open, without a task.
	RestorePR
	// SeedFixed records the CVE's current fixed versions on a legacy no-fix
	// finding, without a task.
	SeedFixed
)

var actionNames = [...]string{"Skip", "Dispatch", "Resolve", "Fail", "Exhaust", "RestorePR", "SeedFixed"}

// String returns the action name.
func (a Action) String() string {
	if a >= 0 && int(a) < len(actionNames) {
		return actionNames[a]
	}
	return fmt.Sprintf("Action(%d)", int(a))
}

// TaskGone is the TaskState for a task the hub no longer has.
const TaskGone = "Gone"

// Input is everything Decide needs to know about one CVE.
type Input struct {
	Finding      *finding.Finding // nil: no cve:<id> fact
	Reported     bool             // RHTPA reports the CVE for the current SBOM
	NewSBOM      bool             // Finding.SbomID != current SBOM id
	Nightly      bool             // the nightly refresh finished and hasn't been processed yet
	TaskState    string           // hub state of Finding.TaskID; "Gone" when missing
	Fixed        []string         // fixed versions for the CVE (nil when not reported)
	SbomUploaded time.Time        // current SBOM's Uploaded
}

// Decision is the outcome of Decide.
type Decision struct {
	Action        Action
	CountAttempt  bool // Attempts++ and LastAttemptAt = now
	ResetAttempts bool // Attempts = 0 before counting
}

// Decide applies the dispatch policy to one CVE.
func Decide(in Input) Decision {
	f := in.Finding
	if f == nil {
		if in.Reported {
			return Decision{Action: Dispatch, CountAttempt: true}
		}
		return Decision{Action: Skip}
	}
	if !in.Reported {
		if in.NewSBOM {
			switch f.Status {
			case finding.StatusRemediated, finding.StatusNotAffected, finding.StatusPullRequestClosed:
			default:
				return Decision{Action: Resolve}
			}
		}
		return Decision{Action: Skip}
	}
	switch f.Status {
	case finding.StatusRemediated:
		if f.PullRequestState == finding.PRStateOpen {
			return Decision{Action: RestorePR}
		}
		return Decision{Action: Dispatch, ResetAttempts: true, CountAttempt: true}
	case finding.StatusNotAffected, finding.StatusPullRequestClosed, finding.StatusExhausted,
		finding.StatusAgentSucceeded, finding.StatusAgentRunning:
		return Decision{Action: Skip}
	case finding.StatusPullRequestOpen:
		if f.PullRequestState == finding.PRStateMerged && f.PullRequestMergedAt.Before(in.SbomUploaded) {
			return failurePath(in)
		}
		return Decision{Action: Skip}
	case finding.StatusDetected, finding.StatusAnalyzing:
		switch in.TaskState {
		case "Failed", "Canceled", "Succeeded", TaskGone:
			return failurePath(in)
		}
		return Decision{Action: Skip}
	case finding.StatusNeedsAttention:
		if f.NoFix {
			if sameSet(in.Fixed, f.FixedSeen) {
				return Decision{Action: Skip}
			}
			// A legacy finding (no attempt recorded by this watcher) never
			// stored the fixed versions it saw: record them, don't retry.
			if len(f.FixedSeen) == 0 && f.LastAttemptAt.IsZero() {
				return Decision{Action: SeedFixed}
			}
			return Decision{Action: Dispatch}
		}
	}
	if f.FailedAttempt() {
		return failurePath(in)
	}
	return Decision{Action: Skip}
}

func failurePath(in Input) Decision {
	f := in.Finding
	switch {
	case f.Attempts >= finding.MaxAttempts:
		return Decision{Action: Exhaust}
	case in.Nightly:
		return Decision{Action: Dispatch, CountAttempt: true}
	case f.FailedAttempt():
		return Decision{Action: Skip}
	}
	return Decision{Action: Fail}
}

// sameSet compares two string slices as sorted, deduplicated sets.
func sameSet(a, b []string) bool {
	a, b = uniqSorted(a), uniqSorted(b)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func uniqSorted(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	n := 0
	for i, s := range out {
		if i == 0 || s != out[n-1] {
			out[n] = s
			n++
		}
	}
	return out[:n]
}

// Migrate upgrades a finding written by an older schema. It returns true
// when the schema was bumped.
func Migrate(f *finding.Finding) (changed bool) {
	if f.Schema >= finding.SchemaVersion {
		return false
	}
	if f.Status == finding.StatusRemediated && (f.PullRequestURL != "" || f.Branch != "") {
		f.Status = finding.StatusPullRequestOpen
		if f.PullRequestURL != "" {
			f.PullRequestState = finding.PRStateOpen
		}
	}
	if f.Status == finding.StatusNeedsAttention && f.Strategy == finding.StrategyNone &&
		f.FixedVersion == "" && strings.HasPrefix(f.StrategyReason, "No fixed upstream version") {
		f.NoFix = true
	}
	if f.FailedAttempt() {
		f.Attempts = 1
	}
	if f.Schema < 2 && f.Source == "" {
		f.Source = finding.SourceFieldRHTPA
	}
	f.Schema = finding.SchemaVersion
	return true
}

// MassResolve reports whether every open finding is unreported and belongs
// to an older SBOM than sbomID, with at least one open finding.
func MassResolve(findings map[string]*finding.Finding, reported map[string]bool, sbomID string) bool {
	open := false
	for id, f := range findings {
		if f.FromJIRA() {
			continue
		}
		switch f.Status {
		case finding.StatusRemediated, finding.StatusNotAffected,
			finding.StatusPullRequestClosed, finding.StatusExhausted:
			continue
		}
		open = true
		if reported[id] || f.SbomID == sbomID {
			return false
		}
	}
	return open
}
