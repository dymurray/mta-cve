package osv

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dymurray/mta-rhtpa-bridge/internal/finding"
)

const ghsa = `{"id":"GHSA-mjmj-j48q-9wg2","aliases":["CVE-2022-1471"],
 "affected":[{"package":{"ecosystem":"Maven","name":"org.yaml:snakeyaml"},
 "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0"}]}]}]}`

func TestEnrichCatalog(t *testing.T) {
	out, src, entry, err := Enrich([]byte(ghsa), "CVE-2022-1471", "org.yaml:snakeyaml")
	if err != nil || src != SourceCatalog || entry == nil {
		t.Fatalf("src=%s entry=%v err=%v", src, entry, err)
	}
	if !strings.Contains(string(out), "org.yaml.snakeyaml.Yaml.load") {
		t.Errorf("methods not merged: %s", out)
	}
	_, src, _, _ = Enrich([]byte(ghsa), "CVE-2022-1471", "other:pkg")
	if src != SourceNone {
		t.Errorf("wrong package should not match, got %s", src)
	}
	var v map[string]any
	_ = json.Unmarshal(out, &v)
	_, src, _, _ = Enrich(out, "CVE-2022-1471", "org.yaml:snakeyaml")
	if src != SourceAdvisory {
		t.Errorf("already-enriched doc should be advisory, got %s", src)
	}
}

func TestSynthesize(t *testing.T) {
	doc := Synthesize("CVE-1", "s", "d", finding.Package{Group: "g", Name: "a"}, "2.0")
	if !strings.Contains(string(doc), `"g:a"`) || !strings.Contains(string(doc), `"fixed": "2.0"`) {
		t.Errorf("synthesized: %s", doc)
	}
}

func TestInterpret(t *testing.T) {
	notAffected := finding.VexStatement{Status: "not_affected", Justification: "vulnerable_code_not_in_execute_path"}
	cases := []struct {
		name     string
		re       finding.Reachability
		verdict  string
		vex      string
		adjusted bool
		noCalls  bool
	}{
		{"exploitable", finding.Reachability{MethodData: SourceCatalog, Exploitability: "exploitable",
			Paths: []finding.TaintPath{{From: "a", To: "b"}}, Vex: finding.VexStatement{Status: "affected"}},
			finding.VerdictExploitable, "affected", false, false},
		{"called, no external path", finding.Reachability{MethodData: SourceCatalog, Exploitability: "not_exploitable",
			Callers: []string{"main"}, Vex: notAffected}, finding.VerdictReachable, "not_affected", false, false},
		{"never called", finding.Reachability{MethodData: SourceCatalog, Exploitability: "not_exploitable",
			Vex: notAffected}, finding.VerdictUnreachable, "not_affected", false, false},
		{"no method data", finding.Reachability{MethodData: SourceNone, Exploitability: "not_exploitable",
			Vex: notAffected}, finding.VerdictUnknown, "under_investigation", true, false},
		{"transitive", finding.Reachability{MethodData: SourceCatalog, DepsVerdict: "not_affected",
			Vex: notAffected}, finding.VerdictUnknown, "under_investigation", true, false},
		{"go: no external call graph", finding.Reachability{MethodData: SourceCatalog, Exploitability: "not_exploitable",
			Vex: notAffected}, finding.VerdictUnknown, "under_investigation", true, true},
	}
	for _, c := range cases {
		re := c.re
		Interpret(&re, !c.noCalls)
		if re.Verdict != c.verdict || re.Vex.Status != c.vex || re.VexAdjusted != c.adjusted {
			t.Errorf("%s: verdict=%s vex=%s adjusted=%v", c.name, re.Verdict, re.Vex.Status, re.VexAdjusted)
		}
	}
}

const goJwt = `{"id":"GHSA-mh63-6h87-95cp","aliases":["CVE-2025-30204"],"affected":[
 {"package":{"ecosystem":"Go","name":"github.com/golang-jwt/jwt/v5"},"ranges":[{"type":"SEMVER","events":[{"introduced":"5.0.0-rc.1"},{"fixed":"5.2.2"}]}]},
 {"package":{"ecosystem":"Go","name":"github.com/golang-jwt/jwt/v4"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.5.2"}]}]},
 {"package":{"ecosystem":"Go","name":"github.com/golang-jwt/jwt"},"ranges":[{"type":"SEMVER","events":[{"introduced":"3.2.0"},{"last_affected":"3.2.2"}]}]}]}`

func TestMajorUpgrade(t *testing.T) {
	if m, v := MajorUpgrade([]byte(goJwt), "github.com/golang-jwt/jwt", true); m != "github.com/golang-jwt/jwt/v5" || v != "v5.2.2" {
		t.Errorf("newest: %s %s", m, v)
	}
	if m, v := MajorUpgrade([]byte(goJwt), "github.com/golang-jwt/jwt", false); m != "github.com/golang-jwt/jwt/v4" || v != "v4.5.2" {
		t.Errorf("lowest: %s %s", m, v)
	}
	if m, _ := MajorUpgrade([]byte(goJwt), "github.com/golang-jwt/jwt/v5", true); m != "" {
		t.Errorf("no higher major than v5: %s", m)
	}
}

func TestGoSymbols(t *testing.T) {
	doc := `{"id":"GO-2022-1059","affected":[{"package":{"ecosystem":"Go","name":"golang.org/x/text"},
	 "ecosystem_specific":{"imports":[{"path":"golang.org/x/text/language","symbols":["ParseAcceptLanguage","MatchStrings"]}]}}]}`
	out, src, _, err := Enrich([]byte(doc), "CVE-2022-32149", "golang.org/x/text")
	if err != nil || src != SourceAdvisory || !strings.Contains(string(out), `"ParseAcceptLanguage"`) || strings.Contains(string(out), "language.ParseAcceptLanguage") {
		t.Errorf("src=%s err=%v out=%s", src, err, out)
	}
}

func TestBareGoSymbol(t *testing.T) {
	for in, want := range map[string]string{
		"github.com/golang-jwt/jwt.ParseWithClaims":      "ParseWithClaims",
		"golang.org/x/text/language.ParseAcceptLanguage": "ParseAcceptLanguage",
		"ParseAcceptLanguage":                            "ParseAcceptLanguage",
		"github.com/golang-jwt/jwt/v5.ParseWithClaims":   "ParseWithClaims",
	} {
		if got := BareGoSymbol(in); got != want {
			t.Errorf("BareGoSymbol(%q)=%q want %q", in, got, want)
		}
	}
}

func TestGoCatalogEntries(t *testing.T) {
	cases := []struct{ cve, pkg, method string }{
		{"CVE-2022-32149", "golang.org/x/text", "ParseAcceptLanguage"},
		{"CVE-2026-56851", "golang.org/x/text", "ParseAcceptLanguage"},
		{"CVE-2026-56852", "golang.org/x/text", "ParseAcceptLanguage"},
		{"CVE-2025-30204", "github.com/golang-jwt/jwt", "ParseWithClaims"},
		{"CVE-2020-8908", "com.google.guava:guava", "com.google.common.io.Files.createTempDir"},
	}
	entries, err := Catalog()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		e := lookup(entries, []string{c.cve}, c.pkg)
		if e == nil || len(e.AffectedMethods) != 1 || e.AffectedMethods[0] != c.method {
			t.Errorf("%s: entry=%+v", c.cve, e)
		}
	}
}

func TestInterpretNotExploitableReason(t *testing.T) {
	re := finding.Reachability{MethodData: SourceCatalog, Exploitability: "not_exploitable", Callers: []string{"main"}}
	Interpret(&re, true)
	if re.Verdict != finding.VerdictReachable || !strings.Contains(re.VerdictReason, "not exploitable") {
		t.Errorf("reachable: %s / %s", re.Verdict, re.VerdictReason)
	}
	re = finding.Reachability{MethodData: SourceCatalog, Exploitability: "not_exploitable"}
	Interpret(&re, true)
	if re.Verdict != finding.VerdictUnreachable || !strings.Contains(re.VerdictReason, "not exploitable") {
		t.Errorf("unreachable: %s / %s", re.Verdict, re.VerdictReason)
	}
}

func TestAdvisoryGoMethodsNormalized(t *testing.T) {
	doc := `{"id":"X-1","affected":[{"package":{"ecosystem":"Go","name":"golang.org/x/text"},
	 "ecosystem_specific":{"affected_methods":["golang.org/x/text/language.ParseAcceptLanguage","MatchStrings"]}}]}`
	out, src, _, err := Enrich([]byte(doc), "CVE-2022-32149", "golang.org/x/text")
	if err != nil || src != SourceAdvisory {
		t.Fatalf("src=%s err=%v", src, err)
	}
	var v struct {
		Affected []struct {
			ES struct {
				M []string `json:"affected_methods"`
			} `json:"ecosystem_specific"`
		} `json:"affected"`
	}
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatal(err)
	}
	m := v.Affected[0].ES.M
	if len(m) != 2 || m[0] != "ParseAcceptLanguage" || m[1] != "MatchStrings" {
		t.Errorf("methods not bare: %v", m)
	}
	// Non-Go advisories keep fully-qualified names.
	java := `{"id":"X-2","affected":[{"package":{"ecosystem":"Maven","name":"g:a"},
	 "ecosystem_specific":{"affected_methods":["a.b.C.m"]}}]}`
	out, _, _, _ = Enrich([]byte(java), "CVE-1", "g:a")
	if !strings.Contains(string(out), "a.b.C.m") {
		t.Errorf("java methods altered: %s", out)
	}
}

func TestGoUnresolvedSinkProvesNothing(t *testing.T) {
	// rgctl honours .gitignore: a Go repo that gitignores vendor/ has its
	// vendored dependencies unindexed, the sink comes back unresolved, and
	// zero callers is not evidence. The verdict must be unknown, not
	// unreachable (which would mark the CVE not affected).
	re := finding.Reachability{
		MethodData:     SourceCatalog,
		Exploitability: "not_exploitable",
		SinkResolution: "unresolved",
	}
	Interpret(&re, trustedNoCallers(&re, true, finding.EcosystemGolang))
	if re.Verdict != finding.VerdictUnknown {
		t.Errorf("verdict %s, want unknown (sink unresolved)", re.Verdict)
	}
	// The same shape with a resolved sink keeps proving non-impact.
	re = finding.Reachability{
		MethodData:     SourceCatalog,
		Exploitability: "not_exploitable",
		SinkResolution: "resolved",
	}
	Interpret(&re, trustedNoCallers(&re, true, finding.EcosystemGolang))
	if re.Verdict != finding.VerdictUnreachable {
		t.Errorf("verdict %s, want unreachable (sink resolved)", re.Verdict)
	}
	// Java is unaffected: dependency jars resolve sinks independently and
	// an unresolved sink with zero callers still proves non-impact there.
	re = finding.Reachability{
		MethodData:     SourceCatalog,
		Exploitability: "not_exploitable",
		SinkResolution: "unresolved",
	}
	Interpret(&re, trustedNoCallers(&re, true, finding.EcosystemMaven))
	if re.Verdict != finding.VerdictUnreachable {
		t.Errorf("java verdict %s, want unreachable", re.Verdict)
	}
}
