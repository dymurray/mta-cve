// Package finding defines the CVE finding model shared by the watcher, the
// cve-remediation addon and the MTA UI. Findings are stored as application
// facts so they are visible through the standard hub API:
//
//	GET /applications/:id/facts/cve:            -> {"CVE-2022-42889": Finding, ...}
//	GET /applications/:id/facts/rhtpa:sbom      -> SBOM
package finding

import (
	"encoding/json"
	"strings"
	"time"
)

// Fact sources and keys.
const (
	SourceCVE   = "cve"
	SourceRHTPA = "rhtpa"
	KeySBOM     = "sbom"
	KeyNightly  = "nightly"
)

// Nightly refresh limits and schema.
const (
	// MaxAttempts is the number of failed remediation attempts after which
	// a finding is Exhausted.
	MaxAttempts = 3
	// SchemaVersion is the current Finding schema.
	SchemaVersion = 2
)

// Pull request states.
const (
	PRStateOpen   = "open"
	PRStateMerged = "merged"
	PRStateClosed = "closed"
)

// Task kinds.
const (
	KindSBOM        = "sbom-discovery"
	KindRemediation = "cve-remediation"
)

// Finding status values.
const (
	StatusDetected       = "Detected"
	StatusAnalyzing      = "Analyzing"
	StatusRemediated     = "Remediated"
	StatusNotAffected    = "NotAffected"
	StatusAgentRunning   = "AgentRunning"
	StatusAgentSucceeded = "AgentSucceeded"
	StatusAgentFailed    = "AgentFailed"
	StatusNeedsAttention = "NeedsAttention"
	StatusFailed         = "Failed"
	// StatusPullRequestOpen: a PR is open and awaiting merge.
	StatusPullRequestOpen = "PullRequestOpen"
	// StatusPullRequestClosed: the PR was closed without merging.
	StatusPullRequestClosed = "PullRequestClosed"
	// StatusExhausted: MaxAttempts failed attempts; no further retries.
	StatusExhausted = "Exhausted"
)

// Task actions (cve-remediation task data "action").
const (
	ActionRemediate   = ""
	ActionPullRequest = "pull-request"
)

// Remediation strategies.
const (
	StrategyAutoBump = "auto-bump"
	StrategyAgentic  = "agentic"
	StrategyNone     = "none"
)

// Finding sources (Finding.Source; empty means RHTPA, the only v1 source).
const (
	SourceFieldJIRA  = "jira"
	SourceFieldRHTPA = "rhtpa"
)

// Remediation modes (Finding.RemediationMode; empty means agent, the
// current default behavior).
const (
	RemediationReport = "report"
	RemediationScript = "script"
	RemediationAgent  = "agent"
)

// SBOM is the rhtpa:sbom fact written by the sbom-discovery addon.
type SBOM struct {
	ID         string `json:"id"`
	DocumentID string `json:"documentId,omitempty"`
	Name       string `json:"name,omitempty"`
	Packages   int    `json:"packages"`
	// Purls are the document's component purls (deduplicated, Go-normalized),
	// used to check whether a package is present in this SBOM.
	Purls      []string  `json:"purls,omitempty"`
	Generator  string    `json:"generator"`
	Uploaded   time.Time `json:"uploaded"`
	ConsoleURL string    `json:"consoleUrl,omitempty"`
	TaskID     uint      `json:"taskId,omitempty"`
	// Commit is the source revision the SBOM was generated from.
	Commit string `json:"commit,omitempty"`
	// NightlyAt is when the nightly refresh last regenerated the SBOM.
	NightlyAt time.Time `json:"nightlyAt,omitempty"`
}

// Nightly is the rhtpa:nightly fact: the watcher's marker of the last
// nightly refresh.
type Nightly struct {
	ProcessedAt time.Time `json:"processedAt"`
}

// Finding is a cve:<CVE-ID> fact.
type Finding struct {
	CVE         string     `json:"cve"`
	Title       string     `json:"title,omitempty"`
	Description string     `json:"description,omitempty"`
	Severity    string     `json:"severity,omitempty"`
	Score       float64    `json:"score,omitempty"`
	Vector      string     `json:"vector,omitempty"`
	Advisories  []Advisory `json:"advisories,omitempty"`
	Package     Package    `json:"package"`
	// FixedVersion is the version selected for remediation.
	FixedVersion string `json:"fixedVersion,omitempty"`
	// FixedModule is set when the fix lives in a different module path
	// (Go major version: example.com/mod -> example.com/mod/v5).
	FixedModule string `json:"fixedModule,omitempty"`
	// RedHatFix is a Red Hat build that also resolves the CVE, when one
	// is published in a Red Hat CSAF advisory.
	RedHatFix      string        `json:"redHatFix,omitempty"`
	Status         string        `json:"status"`
	Strategy       string        `json:"strategy,omitempty"`
	StrategyReason string        `json:"strategyReason,omitempty"`
	Reachability   *Reachability `json:"reachability,omitempty"`
	BuildLog       string        `json:"buildLog,omitempty"`
	Branch         string        `json:"branch,omitempty"`
	// Fork is the repository ("owner/name") the branch was pushed to when
	// it is a fork of the application's repository; empty for upstream.
	Fork       string `json:"fork,omitempty"`
	BranchURL  string `json:"branchUrl,omitempty"`
	CompareURL string `json:"compareUrl,omitempty"`
	// CommitStyle is "gitmoji" (Konveyor repositories) or "conventional".
	CommitStyle       string `json:"commitStyle,omitempty"`
	PullRequestURL    string `json:"pullRequestUrl,omitempty"`
	PullRequestNumber int    `json:"pullRequestNumber,omitempty"`
	// PullRequestTaskID is the task opening the PR for an agent\'s branch.
	PullRequestTaskID uint      `json:"pullRequestTaskId,omitempty"`
	AgentRun          string    `json:"agentRun,omitempty"`
	AgentRunPhase     string    `json:"agentRunPhase,omitempty"`
	TaskID            uint      `json:"taskId,omitempty"`
	SbomID            string    `json:"sbomId,omitempty"`
	ConsoleURL        string    `json:"consoleUrl,omitempty"`
	Message           string    `json:"message,omitempty"`
	DetectedAt        time.Time `json:"detectedAt"`
	UpdatedAt         time.Time `json:"updatedAt"`
	// Attempts counts failed remediation attempts.
	Attempts      int       `json:"attempts,omitempty"`
	LastAttemptAt time.Time `json:"lastAttemptAt,omitempty"`
	// NoFix is set when no published fix exists for the CVE.
	NoFix bool `json:"noFix,omitempty"`
	// FixedSeen lists the fixed versions already seen for the CVE.
	FixedSeen           []string  `json:"fixedSeen,omitempty"`
	PullRequestState    string    `json:"pullRequestState,omitempty"`
	PullRequestMergedAt time.Time `json:"pullRequestMergedAt,omitempty"`
	// Schema is the SchemaVersion the finding was written with.
	Schema int `json:"schema,omitempty"`
	// Source is the vulnerability source: "jira" or "rhtpa" (empty: v1
	// finding, written by the RHTPA watcher).
	Source string `json:"source,omitempty"`
	// JiraKey is the ticket the finding came from (JIRA source only).
	JiraKey string `json:"jiraKey,omitempty"`
	// Component is the pscomponent image that triggered the finding.
	Component string `json:"component,omitempty"`
	// RemediationMode caps the remediation effort: "report", "script" or
	// "agent" (empty: agent).
	RemediationMode string `json:"remediationMode,omitempty"`
	// JiraCommentState is the finding status last announced on the ticket;
	// a comment is posted whenever it differs from Status.
	JiraCommentState string `json:"jiraCommentState,omitempty"`
	// Group lists every CVE (this one included) remediated by the same
	// dependency update, task, branch and pull request. Empty when the
	// finding was remediated alone.
	Group []string `json:"group,omitempty"`
}

// FromJIRA reports whether the finding came from the JIRA source.
func (f *Finding) FromJIRA() bool { return f.Source == SourceFieldJIRA }

// ShareOutcome copies the remediation outcome of the primary finding of a
// group (the dependency update, task, branch, pull request and agent run)
// to f, keeping f's own vulnerability details, reachability and attempts.
func (f *Finding) ShareOutcome(primary *Finding) {
	f.Package = primary.Package
	f.FixedVersion = primary.FixedVersion
	f.FixedModule = primary.FixedModule
	f.RedHatFix = primary.RedHatFix
	f.Status = primary.Status
	f.Strategy = primary.Strategy
	f.StrategyReason = primary.StrategyReason
	f.BuildLog = primary.BuildLog
	f.Branch = primary.Branch
	f.Fork = primary.Fork
	f.BranchURL = primary.BranchURL
	f.CompareURL = primary.CompareURL
	f.CommitStyle = primary.CommitStyle
	f.PullRequestURL = primary.PullRequestURL
	f.PullRequestNumber = primary.PullRequestNumber
	f.PullRequestTaskID = primary.PullRequestTaskID
	f.PullRequestState = primary.PullRequestState
	f.PullRequestMergedAt = primary.PullRequestMergedAt
	f.AgentRun = primary.AgentRun
	f.AgentRunPhase = primary.AgentRunPhase
	f.TaskID = primary.TaskID
	f.SbomID = primary.SbomID
	f.Message = primary.Message
	f.NoFix = primary.NoFix
	f.Group = append([]string(nil), primary.Group...)
}

// PackageKey identifies an affected dependency by its purl without
// qualifiers or subpath (pkg:maven/org.yaml/snakeyaml@1.33). Findings with
// the same key are remediated by one task.
func PackageKey(purl string) string {
	if i := strings.IndexAny(purl, "?#"); i >= 0 {
		purl = purl[:i]
	}
	return purl
}

// FailedAttempt reports whether the finding's last attempt failed. A
// NeedsAttention finding with no published fix is not a failed attempt.
func (f *Finding) FailedAttempt() bool {
	switch f.Status {
	case StatusFailed, StatusAgentFailed:
		return true
	case StatusNeedsAttention:
		return !f.NoFix
	}
	return false
}

// ResetAttemptOutputs clears the outputs of the previous attempt, keeping
// the attempt counters.
func (f *Finding) ResetAttemptOutputs() {
	f.Branch = ""
	f.Fork = ""
	f.BranchURL = ""
	f.CompareURL = ""
	f.PullRequestURL = ""
	f.PullRequestNumber = 0
	f.PullRequestTaskID = 0
	f.PullRequestState = ""
	f.PullRequestMergedAt = time.Time{}
	f.AgentRun = ""
	f.AgentRunPhase = ""
	f.BuildLog = ""
	f.NoFix = false
	f.Strategy = ""
	f.StrategyReason = ""
}

// SeverityTagged reports whether findings in the status keep their
// "<Severity> CVE" tag on the application.
func SeverityTagged(status string) bool {
	switch status {
	case StatusRemediated, StatusNotAffected:
		return false
	}
	return true
}

// Advisory is an RHTPA advisory that reports the CVE against the SBOM.
type Advisory struct {
	ID            string   `json:"id"`
	Title         string   `json:"title,omitempty"`
	Source        string   `json:"source,omitempty"`
	URL           string   `json:"url,omitempty"`
	FixedVersions []string `json:"fixedVersions,omitempty"`
}

// Package is the affected component.
type Package struct {
	Purl    string `json:"purl"`
	Group   string `json:"group,omitempty"`
	Name    string `json:"name"`
	Version string `json:"version"`
	// Direct is true when the app declares the dependency itself.
	Direct bool `json:"direct"`
	// Ecosystem is the purl type: "maven", "golang" or "pypi".
	Ecosystem string `json:"ecosystem,omitempty"`
}

// Ecosystems.
const (
	EcosystemMaven  = "maven"
	EcosystemGolang = "golang"
	EcosystemPyPI   = "pypi"
)

// Coordinate is the package identifier used by its ecosystem
// (group:artifact for Maven, the module path for Go, the project name for
// PyPI).
func (p Package) Coordinate() string {
	if p.Group == "" {
		return p.Name
	}
	return p.Group + ":" + p.Name
}

// Reachability verdicts derived from rgctl `vuln analyze`.
const (
	// VerdictExploitable: a path from external input reaches a vulnerable method.
	VerdictExploitable = "exploitable"
	// VerdictReachable: vulnerable methods are called, but no external input path.
	VerdictReachable = "reachable"
	// VerdictUnreachable: method-level data is known and nothing calls it.
	VerdictUnreachable = "unreachable"
	// VerdictUnknown: rgctl could not decide (no method-level data, dependency
	// not visible in manifests, or analysis failed).
	VerdictUnknown = "unknown"
)

// Reachability is the rgctl OSV analysis (`rgctl vuln analyze`) of the
// vulnerability against the application source, including the OpenVEX
// statement it produced.
type Reachability struct {
	Tool             string          `json:"tool"`
	OsvID            string          `json:"osvId"`
	Verdict          string          `json:"verdict"`
	VerdictReason    string          `json:"verdictReason,omitempty"`
	DepsVerdict      string          `json:"depsVerdict,omitempty"`
	Exploitability   string          `json:"exploitability,omitempty"`
	Notes            string          `json:"notes,omitempty"`
	MethodData       string          `json:"methodData"`
	AffectedClasses  []string        `json:"affectedClasses,omitempty"`
	AffectedMethods  []string        `json:"affectedMethods,omitempty"`
	TriggerCondition string          `json:"triggerCondition,omitempty"`
	Sink             string          `json:"sink,omitempty"`
	SinkResolution   string          `json:"sinkResolution,omitempty"`
	CfgAvailable     bool            `json:"cfgAvailable"`
	Callers          []string        `json:"callers,omitempty"`
	CallSites        []CallSite      `json:"callSites,omitempty"`
	Paths            []TaintPath     `json:"paths,omitempty"`
	DepsMatches      []DepsMatch     `json:"depsMatches,omitempty"`
	Vex              VexStatement    `json:"vex"`
	OpenVEX          json.RawMessage `json:"openvex,omitempty"`
	// VexAdjusted is set when the effective VEX status differs from rgctl's
	// (rgctl's not_affected is not trusted without method-level data).
	VexAdjusted bool `json:"vexAdjusted,omitempty"`
}

// CallSite is an application call into a vulnerable library method.
type CallSite struct {
	Caller       string `json:"caller"`
	TargetMethod string `json:"targetMethod"`
	File         string `json:"file"`
	Line         int    `json:"line"`
}

// TaintPath is an external-input -> vulnerable-method path.
type TaintPath struct {
	From string `json:"from"`
	To   string `json:"to"`
	Hops int    `json:"hops"`
}

// DepsMatch is a manifest declaration matched against the advisory range.
type DepsMatch struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	InRange    bool   `json:"inRange"`
	Provenance string `json:"provenance,omitempty"`
}

// VexStatement is the effective OpenVEX statement for the application.
type VexStatement struct {
	Status          string   `json:"status"`
	Justification   string   `json:"justification,omitempty"`
	ImpactStatement string   `json:"impactStatement,omitempty"`
	ActionStatement string   `json:"actionStatement,omitempty"`
	Products        []string `json:"products,omitempty"`
}

// Unreachable reports whether rgctl had method-level data and found no
// application code calling the vulnerable methods.
func (r *Reachability) Unreachable() bool {
	return r != nil && r.Verdict == VerdictUnreachable
}
