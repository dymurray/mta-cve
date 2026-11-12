// Package osv prepares OSV documents for rgctl and interprets
// `rgctl vuln analyze` (reachability + OpenVEX) for a finding.
package osv

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/dymurray/mta-rhtpa-bridge/internal/finding"
)

// Method data sources.
const (
	SourceAdvisory = "advisory"
	SourceCatalog  = "catalog"
	SourceNone     = "none"
)

//go:embed catalog.yaml
var catalogYAML []byte

// Entry is a catalog entry.
type Entry struct {
	IDs              []string `yaml:"ids"`
	Package          string   `yaml:"package"`
	AffectedClasses  []string `yaml:"affected_classes"`
	AffectedMethods  []string `yaml:"affected_methods"`
	TriggerCondition string   `yaml:"trigger_condition"`
}

// Catalog returns the embedded method-level catalog.
func Catalog() (entries []Entry, err error) {
	err = yaml.Unmarshal(catalogYAML, &entries)
	return
}

func lookup(entries []Entry, ids []string, pkg string) *Entry {
	for i := range entries {
		e := &entries[i]
		if e.Package != pkg {
			continue
		}
		for _, want := range e.IDs {
			for _, id := range ids {
				if strings.EqualFold(want, id) {
					return e
				}
			}
		}
	}
	return nil
}

// Synthesize builds a minimal OSV document when RHTPA has no OSV advisory
// for the CVE (e.g. it is only known from Red Hat CSAF).
func Synthesize(cve, summary, details string, pkg finding.Package, fixed string) []byte {
	events := []map[string]string{{"introduced": "0"}}
	if fixed != "" {
		events = append(events, map[string]string{"fixed": fixed})
	}
	ecosystem := "Maven"
	if pkg.Ecosystem == finding.EcosystemPyPI {
		ecosystem = "PyPI"
	}
	if pkg.Ecosystem == finding.EcosystemGolang {
		ecosystem = "Go"
		if fixed != "" {
			fixed = strings.TrimPrefix(fixed, "v")
		}
		events = []map[string]string{{"introduced": "0"}}
		if fixed != "" {
			events = append(events, map[string]string{"fixed": fixed})
		}
	}
	doc := map[string]any{
		"schema_version": "1.4.0",
		"id":             cve,
		"aliases":        []string{cve},
		"summary":        summary,
		"details":        details,
		"affected": []map[string]any{{
			"package": map[string]string{
				"ecosystem": ecosystem,
				"name":      pkg.Coordinate(),
			},
			"ranges": []map[string]any{{"type": "ECOSYSTEM", "events": events}},
		}},
	}
	b, _ := json.MarshalIndent(doc, "", "  ")
	return b
}

// Enrich merges catalog method data into the OSV document for pkg. It
// returns the (possibly unchanged) document, the method data source and the
// matched catalog entry.
func Enrich(doc []byte, cve, pkg string) (out []byte, source string, entry *Entry, err error) {
	var v map[string]any
	err = json.Unmarshal(doc, &v)
	if err != nil {
		return
	}
	ids := []string{cve}
	if id, ok := v["id"].(string); ok {
		ids = append(ids, id)
	}
	if aliases, ok := v["aliases"].([]any); ok {
		for _, a := range aliases {
			if s, ok := a.(string); ok {
				ids = append(ids, s)
			}
		}
	}
	affected, _ := v["affected"].([]any)
	converted := false
	for _, a := range affected {
		m, _ := a.(map[string]any)
		es, _ := m["ecosystem_specific"].(map[string]any)
		if methods, ok := es["affected_methods"].([]any); ok && len(methods) > 0 {
			out, source = doc, SourceAdvisory
			return
		}
		// Go vulnerability database format: imports[].{path,symbols}.
		if methods := goSymbols(es); len(methods) > 0 {
			es["affected_methods"] = methods
			converted = true
		}
	}
	if converted {
		out, err = json.MarshalIndent(v, "", "  ")
		source = SourceAdvisory
		return
	}
	entries, err := Catalog()
	if err != nil {
		return
	}
	entry = lookup(entries, ids, pkg)
	if entry == nil {
		out, source = doc, SourceNone
		return
	}
	for _, a := range affected {
		m, _ := a.(map[string]any)
		p, _ := m["package"].(map[string]any)
		if name, _ := p["name"].(string); name != pkg {
			continue
		}
		es, _ := m["ecosystem_specific"].(map[string]any)
		if es == nil {
			es = map[string]any{}
		}
		es["affected_classes"] = entry.AffectedClasses
		es["affected_methods"] = entry.AffectedMethods
		if entry.TriggerCondition != "" {
			es["trigger_condition"] = entry.TriggerCondition
		}
		m["ecosystem_specific"] = es
	}
	out, err = json.MarshalIndent(v, "", "  ")
	source = SourceCatalog
	return
}

// goSymbols converts Go vulndb ecosystem_specific.imports to rgctl
// affected_methods ("<import path>.<Symbol>").
func goSymbols(es map[string]any) (methods []string) {
	imports, _ := es["imports"].([]any)
	for _, i := range imports {
		imp, _ := i.(map[string]any)
		path, _ := imp["path"].(string)
		symbols, _ := imp["symbols"].([]any)
		for _, sym := range symbols {
			if name, ok := sym.(string); ok && path != "" {
				methods = append(methods, path+"."+name)
			}
		}
	}
	return
}

var majorSuffixRe = regexp.MustCompile(`/v(\d+)$`)

// MajorUpgrade finds a fix that lives in another major version of a Go
// module (example.com/mod -> example.com/mod/v5). It returns the module
// path and "v"-prefixed fixed version of the newest (or lowest) higher major
// that has a fix in the OSV document.
func MajorUpgrade(doc []byte, module string, newest bool) (target, version string) {
	var v struct {
		Affected []struct {
			Package struct {
				Name string `json:"name"`
			} `json:"package"`
			Ranges []struct {
				Events []map[string]string `json:"events"`
			} `json:"ranges"`
		} `json:"affected"`
	}
	if json.Unmarshal(doc, &v) != nil {
		return
	}
	base, current := module, 1
	if m := majorSuffixRe.FindStringSubmatch(module); m != nil {
		base = strings.TrimSuffix(module, m[0])
		current, _ = strconv.Atoi(m[1])
	}
	best := 0
	for _, a := range v.Affected {
		m := majorSuffixRe.FindStringSubmatch(a.Package.Name)
		if m == nil || strings.TrimSuffix(a.Package.Name, m[0]) != base {
			continue
		}
		major, _ := strconv.Atoi(m[1])
		if major <= current {
			continue
		}
		fixed := ""
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if f := e["fixed"]; f != "" {
					fixed = f
				}
			}
		}
		if fixed == "" {
			continue
		}
		if best == 0 || (newest && major > best) || (!newest && major < best) {
			best, target, version = major, a.Package.Name, "v"+strings.TrimPrefix(fixed, "v")
		}
	}
	return
}

// analyzeResult is the `rgctl -f json vuln analyze` output.
type analyzeResult struct {
	OsvID          string          `json:"osv_id"`
	DepsVerdict    string          `json:"deps_verdict"`
	Exploitability string          `json:"exploitability"`
	Notes          string          `json:"notes"`
	OpenVEX        json.RawMessage `json:"openvex"`
	SinkTaint      struct {
		CfgAvailable   bool     `json:"cfg_available"`
		Sink           string   `json:"sink"`
		SinkResolution string   `json:"sink_resolution"`
		SinkCallers    []string `json:"sink_callers"`
		CallSites      []struct {
			Caller       string `json:"caller"`
			TargetMethod string `json:"target_method"`
			File         string `json:"file"`
			Line         int    `json:"line"`
		} `json:"call_sites"`
		Paths []finding.TaintPath `json:"paths"`
	} `json:"sink_taint"`
}

type depsResult struct {
	Verdict string `json:"verdict"`
	Matched []struct {
		Name       string `json:"name"`
		Version    string `json:"version"`
		InRange    bool   `json:"in_range"`
		Provenance string `json:"provenance"`
	} `json:"matched"`
}

type openVEX struct {
	Statements []struct {
		Status          string   `json:"status"`
		Justification   string   `json:"justification"`
		ImpactStatement string   `json:"impact_statement"`
		ActionStatement string   `json:"action_statement"`
		Products        []string `json:"products"`
	} `json:"statements"`
}

// Rgctl runs rgctl in a repository.
type Rgctl struct {
	Bin  string
	Repo string
	// MemLimit is the resident memory (bytes) rgctl may use; 0 is no limit.
	MemLimit int64
}

// Discover indexes the repository with CFG/PDG so reachability and
// sink-first taint are available (required by the rgctl vuln workflow).
func (r *Rgctl) Discover() (out []byte, err error) {
	cmd := exec.Command(r.Bin, "discover", ".", "--with-cfg", "--with-taint")
	cmd.Dir = r.Repo
	out, err = r.run(cmd, true)
	return
}

func (r *Rgctl) json(out any, args ...string) (raw []byte, err error) {
	cmd := exec.Command(r.Bin, append([]string{"-f", "json"}, args...)...)
	cmd.Dir = r.Repo
	raw, err = r.run(cmd, false)
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			err = fmt.Errorf("rgctl %s: %w: %s", strings.Join(args, " "), err, ee.Stderr)
		}
		return
	}
	err = json.Unmarshal(raw, out)
	return
}

// Analyze runs `deps check` and `vuln analyze` for the OSV document at path.
// externalCalls reports whether rgctl records calls into external packages
// for the ecosystem; without them, "no callers" proves nothing.
func (r *Rgctl) Analyze(osvPath, methodSource string, entry *Entry, externalCalls bool) (re *finding.Reachability, raw []byte, err error) {
	var deps depsResult
	_, err = r.json(&deps, "deps", "check", "--osv", osvPath)
	if err != nil {
		return
	}
	var res analyzeResult
	raw, err = r.json(&res, "vuln", "analyze", "--osv", osvPath)
	if err != nil {
		return
	}
	re = &finding.Reachability{
		Tool:           "rgctl vuln analyze",
		OsvID:          res.OsvID,
		DepsVerdict:    res.DepsVerdict,
		Exploitability: res.Exploitability,
		Notes:          res.Notes,
		MethodData:     methodSource,
		Sink:           res.SinkTaint.Sink,
		SinkResolution: res.SinkTaint.SinkResolution,
		CfgAvailable:   res.SinkTaint.CfgAvailable,
		Callers:        res.SinkTaint.SinkCallers,
		Paths:          res.SinkTaint.Paths,
		OpenVEX:        res.OpenVEX,
	}
	if entry != nil {
		re.AffectedClasses = entry.AffectedClasses
		re.AffectedMethods = entry.AffectedMethods
		re.TriggerCondition = entry.TriggerCondition
	}
	for _, c := range res.SinkTaint.CallSites {
		re.CallSites = append(re.CallSites, finding.CallSite{
			Caller: c.Caller, TargetMethod: c.TargetMethod, File: c.File, Line: c.Line,
		})
	}
	for _, m := range deps.Matched {
		re.DepsMatches = append(re.DepsMatches, finding.DepsMatch{
			Name: m.Name, Version: m.Version, InRange: m.InRange, Provenance: m.Provenance,
		})
	}
	var vex openVEX
	if json.Unmarshal(res.OpenVEX, &vex) == nil && len(vex.Statements) > 0 {
		st := vex.Statements[0]
		re.Vex = finding.VexStatement{
			Status:          st.Status,
			Justification:   st.Justification,
			ImpactStatement: st.ImpactStatement,
			ActionStatement: st.ActionStatement,
			Products:        st.Products,
		}
	}
	Interpret(re, externalCalls)
	return
}

// Interpret sets the verdict. rgctl's not_affected is only trusted when it
// had method-level data and analyzed the call graph; otherwise the effective
// VEX status is downgraded to under_investigation.
//
// externalCalls is false for ecosystems where rgctl does not record calls
// into external packages (Go in rgctl 0.4.21): a missing caller is then not
// evidence and the verdict is unknown rather than unreachable.
func Interpret(re *finding.Reachability, externalCalls bool) {
	called := len(re.Callers) > 0 || len(re.CallSites) > 0
	switch {
	case re.Exploitability == "exploitable" || len(re.Paths) > 0:
		re.Verdict = finding.VerdictExploitable
		re.VerdictReason = "A path from external input reaches the vulnerable code."
	case re.MethodData == SourceNone:
		re.Verdict = finding.VerdictUnknown
		re.VerdictReason = "The advisory does not name the vulnerable methods, so reachability cannot be determined."
	case re.DepsVerdict == "not_affected":
		re.Verdict = finding.VerdictUnknown
		re.VerdictReason = "The dependency is not declared in the project manifests (transitive); RHTPA's resolved SBOM still lists it, so call analysis was skipped."
	case !called && !externalCalls:
		re.Verdict = finding.VerdictUnknown
		re.VerdictReason = "rgctl does not record calls into external packages for this language, so reachability of the vulnerable code cannot be determined."
	case called:
		re.Verdict = finding.VerdictReachable
		re.VerdictReason = "The vulnerable methods are called, but no path from external input reaches them."
	default:
		re.Verdict = finding.VerdictUnreachable
		re.VerdictReason = "No application code calls the vulnerable methods."
	}
	if re.Verdict == finding.VerdictUnknown && re.Vex.Status == "not_affected" {
		re.VexAdjusted = true
		re.Vex.Status = "under_investigation"
		re.Vex.Justification = ""
		re.Vex.ImpactStatement = re.VerdictReason
	}
}
