package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dymurray/mta-rhtpa-bridge/internal/finding"
	"github.com/dymurray/mta-rhtpa-bridge/internal/github"
)

// TestCleanSyft uses a real syft CycloneDX document of the Go demo app when
// SYFT_BOM points at one.
func TestCleanSyft(t *testing.T) {
	path := os.Getenv("SYFT_BOM")
	if path == "" {
		t.Skip("SYFT_BOM not set")
	}
	doc, _ := os.ReadFile(path)
	out, err := cleanSyft(doc, "inventory-api")
	if err != nil {
		t.Fatal(err)
	}
	var bom struct {
		Metadata struct {
			Component struct{ Name string } `json:"component"`
		} `json:"metadata"`
		Components []struct {
			Purl   string `json:"purl"`
			BomRef string `json:"bom-ref"`
		} `json:"components"`
		Dependencies []struct {
			Ref       string   `json:"ref"`
			DependsOn []string `json:"dependsOn"`
		} `json:"dependencies"`
	}
	_ = json.Unmarshal(out, &bom)
	if bom.Metadata.Component.Name != "inventory-api" {
		t.Errorf("root name %q", bom.Metadata.Component.Name)
	}
	refs := map[string]bool{bom.Metadata.Component.Name: true}
	purls := map[string]bool{}
	for _, c := range bom.Components {
		if purls[c.Purl] {
			t.Errorf("duplicate %s", c.Purl)
		}
		if len(c.Purl) > 18 && c.Purl[:18] == "pkg:golang/stdlib@" {
			t.Errorf("stdlib not removed")
		}
		purls[c.Purl] = true
		refs[c.BomRef] = true
	}
	for _, d := range bom.Dependencies {
		for _, on := range d.DependsOn {
			if !refs[on] {
				t.Errorf("dangling dependsOn %s", on)
			}
		}
	}
	t.Logf("%d components: %v", len(bom.Components), purls)
}

func TestGoMajorPurl(t *testing.T) {
	cases := map[string]string{
		"pkg:golang/github.com/golang-jwt/jwt@v4.5.0#v4":             "pkg:golang/github.com/golang-jwt/jwt/v4@v4.5.0",
		"pkg:golang/github.com/go-chi/chi@v5.2.5?type=module#v5":     "pkg:golang/github.com/go-chi/chi/v5@v5.2.5?type=module",
		"pkg:golang/golang.org/x/net@v0.57.0":                        "pkg:golang/golang.org/x/net@v0.57.0",
		"pkg:golang/github.com/golang-jwt/jwt@v3.2.2%2Bincompatible": "pkg:golang/github.com/golang-jwt/jwt@v3.2.2%2Bincompatible",
		"pkg:golang/github.com/x/y@v1.0.0#sub/dir":                   "pkg:golang/github.com/x/y@v1.0.0#sub/dir",
		"pkg:maven/org.yaml/snakeyaml@1.33#v4":                       "pkg:maven/org.yaml/snakeyaml@1.33#v4",
	}
	for in, want := range cases {
		if got := goMajorPurl(in); got != want {
			t.Errorf("goMajorPurl(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGoVersionPurl(t *testing.T) {
	cases := map[string]string{
		"pkg:golang/golang.org/x/net@v0.57.0":                        "pkg:golang/golang.org/x/net@0.57.0",
		"pkg:golang/github.com/golang-jwt/jwt/v4@v4.5.0?type=module": "pkg:golang/github.com/golang-jwt/jwt/v4@4.5.0?type=module",
		"pkg:golang/github.com/golang-jwt/jwt@v3.2.2%2Bincompatible": "pkg:golang/github.com/golang-jwt/jwt@3.2.2%2Bincompatible",
		"pkg:golang/github.com/dymurray/app@(devel)":                 "pkg:golang/github.com/dymurray/app@(devel)",
		"pkg:maven/org.yaml/snakeyaml@1.33":                          "pkg:maven/org.yaml/snakeyaml@1.33",
	}
	for in, want := range cases {
		if got := goVersionPurl(goMajorPurl(in)); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
	if got := goVersionPurl(goMajorPurl("pkg:golang/github.com/go-chi/chi@v5.2.5#v5")); got != "pkg:golang/github.com/go-chi/chi/v5@5.2.5" {
		t.Errorf("combined: %q", got)
	}
}

func TestApplyPRState(t *testing.T) {
	merged := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	f := &finding.Finding{Status: finding.StatusPullRequestOpen}
	if applyPRState(f, github.PullRequest{State: "open"}) {
		t.Error("open must not change the finding")
	}
	if !applyPRState(f, github.PullRequest{State: "closed", MergedAt: &merged}) {
		t.Fatal("merged must change the finding")
	}
	if f.PullRequestState != finding.PRStateMerged || f.Status != finding.StatusPullRequestOpen || !f.PullRequestMergedAt.Equal(merged) {
		t.Errorf("merged: %+v", f)
	}
	if applyPRState(f, github.PullRequest{State: "closed", MergedAt: &merged}) {
		t.Error("already recorded merge must not change the finding")
	}
	f = &finding.Finding{Status: finding.StatusPullRequestOpen}
	if !applyPRState(f, github.PullRequest{State: "closed"}) {
		t.Fatal("closed must change the finding")
	}
	if f.Status != finding.StatusPullRequestClosed || f.PullRequestState != finding.PRStateClosed || f.Message == "" {
		t.Errorf("closed: %+v", f)
	}
}

func TestSBOMPurlsWritten(t *testing.T) {
	doc := []byte(`{"components":[
		{"purl":"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
		{"purl":"pkg:golang/github.com/x/y@v4.5.0#v4"},
		{"purl":"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
		{"purl":""},
		{"name":"no-purl"}],
		"packages":[{"purl":"pkg:golang/github.com/a/b@v1.2.3"},{"purl":""}]}`)
	want := []string{
		"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
		"pkg:golang/github.com/x/y/v4@4.5.0",
		"pkg:golang/github.com/a/b@1.2.3",
	}
	got := sbomPurls(doc)
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	raw, err := json.Marshal(finding.SBOM{ID: "s", Purls: got})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	if _, ok := m["purls"]; !ok {
		t.Fatalf("purls key missing: %s", raw)
	}
	var back finding.SBOM
	if err := json.Unmarshal(raw, &back); err != nil || len(back.Purls) != 3 {
		t.Fatalf("round trip: %v %v", err, back.Purls)
	}
	empty, _ := json.Marshal(finding.SBOM{ID: "s"})
	if strings.Contains(string(empty), "purls") {
		t.Fatalf("empty purls should be omitted: %s", empty)
	}
}
