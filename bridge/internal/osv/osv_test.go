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
	if err != nil || src != SourceAdvisory || !strings.Contains(string(out), "golang.org/x/text/language.ParseAcceptLanguage") {
		t.Errorf("src=%s err=%v out=%s", src, err, out)
	}
}
