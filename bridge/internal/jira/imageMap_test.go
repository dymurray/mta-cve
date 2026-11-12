package jira

import (
	"testing"
)

func TestParseConfigSingleRepo(t *testing.T) {
	cfg, err := ParseConfig([]byte(`
products:
  mta:
    images:
      mta/mta-solution-server-rhel9:
        repo: https://github.com/example/app.git
        remediation: script
        autoClose: true
`))
	if err != nil {
		t.Fatal(err)
	}
	e, ok := cfg.Products["mta"].Images["mta/mta-solution-server-rhel9"]
	if !ok {
		t.Fatalf("config = %+v", cfg)
	}
	if len(e.Repos) != 1 || e.Repos[0] != "https://github.com/example/app.git" || e.Repo != "" {
		t.Errorf("repos = %v repo = %q", e.Repos, e.Repo)
	}
	if e.Remediation != "script" || !e.AutoClose {
		t.Errorf("entry = %+v", e)
	}
	if e.Branch != "" {
		t.Errorf("branch = %q, want empty default", e.Branch)
	}
}

func TestParseConfigRepoListAndDefaults(t *testing.T) {
	cfg, err := ParseConfig([]byte(`
products:
  p:
    images:
      image/a:
        repos:
          - https://github.com/example/one.git
          - https://github.com/example/two.git
        branch: release-2.1
`))
	if err != nil {
		t.Fatal(err)
	}
	e := cfg.Products["p"].Images["image/a"]
	if len(e.Repos) != 2 {
		t.Errorf("repos = %v", e.Repos)
	}
	if e.Branch != "release-2.1" || e.Remediation != "" || e.AutoClose {
		t.Errorf("entry = %+v", e)
	}
}

func TestParseConfigInvalid(t *testing.T) {
	if _, err := ParseConfig([]byte(":\tnot yaml")); err == nil {
		t.Error("invalid YAML must error")
	}
}

func TestParseConfigRejectsBadRemediation(t *testing.T) {
	_, err := ParseConfig([]byte(`
products:
  p:
    images:
      image/a:
        repo: https://github.com/example/one.git
        remediation: yolo
`))
	if err == nil {
		t.Error("unknown remediation must error")
	}
}

func TestParseConfigProducts(t *testing.T) {
	cfg, err := ParseConfig([]byte(`
products:
  mta:
    jiraProject: MTA
    owner: owner@example.com
    streams:
      mta-8.2:
        branch: release-0.10
        fixVersion: MTA 8.2.4
        owner: stream-owner@example.com
    images:
      mta/mta-a-rhel9:
        repo: https://github.com/example/a.git
      mta/mta-b-rhel9:
        repo: https://github.com/example/b.git
        mainBranch: master
`))
	if err != nil {
		t.Fatal(err)
	}
	p := cfg.Products["mta"]
	if p.JiraProject != "MTA" || p.Owner != "owner@example.com" {
		t.Errorf("product = %+v", p)
	}
	s := p.Streams["mta-8.2"]
	if s.Branch != "release-0.10" || s.FixVersion != "MTA 8.2.4" || s.Owner != "stream-owner@example.com" {
		t.Errorf("stream = %+v", s)
	}
	a := p.Images["mta/mta-a-rhel9"]
	if len(a.Repos) != 1 {
		t.Errorf("repos = %v", a.Repos)
	}
	if got := p.MainRefOf(a); got != "main" {
		t.Errorf("MainRefOf default = %q, want main", got)
	}
	if got := p.MainRefOf(p.Images["mta/mta-b-rhel9"]); got != "master" {
		t.Errorf("MainRefOf image override = %q, want master", got)
	}
	p.MainBranch = "trunk"
	if got := p.MainRefOf(a); got != "trunk" {
		t.Errorf("MainRefOf product = %q, want trunk", got)
	}
}

func TestStreamFromSummary(t *testing.T) {
	for in, want := range map[string]string{
		"CVE-2024-1 foo: mta/tasks [mta-8.2]":   "mta-8.2",
		"CVE-2024-2 bar: cnv/frames [cnv-4.22]": "cnv-4.22",
		"[urgent] CVE-1 x [mta-8.2]":            "mta-8.2",
		"CVE-1 no stream":                       "",
		"CVE-1 trailing [not-a-stream":          "",
	} {
		if got := StreamFromSummary(in); got != want {
			t.Errorf("StreamFromSummary(%q) = %q, want %q", in, got, want)
		}
	}
}

func ticket(key string, labels ...string) Ticket {
	return Ticket{Key: key, Labels: labels}
}

func TestDispatchesFanOut(t *testing.T) {
	prod := Product{Images: map[string]ImageEntry{
		"img/a": {Repos: []string{"https://r/one.git", "https://r/two.git"}},
		"img/b": {Repos: []string{"https://r/three.git"}, Remediation: "script"},
	}}
	tickets := []Ticket{
		ticket("MTA-1", "pscomponent:img/a", "pscomponent:img/b"),
		ticket("MTA-2", "pscomponent:img/none"),
	}
	cves := func(Ticket) ([]string, error) { return []string{"CVE-2024-1", "CVE-2024-2"}, nil }
	work := Dispatches(tickets, prod, cves)
	// 2 images on MTA-1 (2 + 1 repos) + 0 for the unmapped MTA-2 = 3 works,
	// each carrying both CVEs.
	if len(work) != 3 {
		t.Fatalf("work = %d, want 3: %+v", len(work), work)
	}
	for _, w := range work {
		if len(w.CVEs) != 2 {
			t.Errorf("work %s/%s cves = %v", w.Ticket.Key, w.RepoURL, w.CVEs)
		}
	}
	if work[0].Image != "img/a" || work[0].Ticket.Key != "MTA-1" {
		t.Errorf("work[0] = %+v", work[0])
	}
	if work[2].Entry.Remediation != "script" {
		t.Errorf("entry not carried: %+v", work[2])
	}
}

func TestDispatchesCarriesStream(t *testing.T) {
	prod := Product{
		Name:    "mta",
		Streams: map[string]Stream{"mta-8.2": {Branch: "release-0.10", FixVersion: "MTA 8.2.4"}},
		Images:  map[string]ImageEntry{"img/a": {Repos: []string{"https://r/one.git"}}},
	}
	tk := Ticket{Key: "MTA-1", Summary: "CVE-2024-1 x [mta-8.2]", Labels: []string{"pscomponent:img/a"}}
	cves := func(Ticket) ([]string, error) { return []string{"CVE-2024-1"}, nil }
	work := Dispatches([]Ticket{tk}, prod, cves)
	if len(work) != 1 {
		t.Fatalf("work = %+v", work)
	}
	w := work[0]
	if w.Product != "mta" || w.Stream != "mta-8.2" || w.StreamCfg.Branch != "release-0.10" {
		t.Errorf("stream not carried: %+v", w)
	}
}

func TestDispatchesSkipsTicketsWithoutCVEs(t *testing.T) {
	prod := Product{Images: map[string]ImageEntry{"img/a": {Repos: []string{"https://r/one.git"}}}}
	cves := func(Ticket) ([]string, error) { return nil, nil }
	if work := Dispatches([]Ticket{ticket("MTA-1", "pscomponent:img/a")}, prod, cves); len(work) != 0 {
		t.Errorf("work = %+v, want none", work)
	}
}

func TestUnmapped(t *testing.T) {
	prod := Product{Images: map[string]ImageEntry{"img/a": {Repos: []string{"https://r/one.git"}}}}
	tickets := []Ticket{
		ticket("MTA-1", "pscomponent:img/a"),
		ticket("MTA-2", "pscomponent:img/none", "pscomponent:img/a"),
		ticket("MTA-3", "other"),
	}
	got := Unmapped(tickets, prod)
	if len(got) != 1 || got[0].Key != "MTA-2" {
		t.Errorf("unmapped = %+v, want [MTA-2]", got)
	}
}

func TestParseConfigRejectsFlatMap(t *testing.T) {
	if _, err := ParseConfig([]byte("img/a:\n  repo: https://github.com/example/a.git\n")); err == nil {
		t.Error("a pre-migration flat map (no products) must error")
	}
}

func TestParseConfigSetsProductName(t *testing.T) {
	cfg, err := ParseConfig([]byte("products:\n  mta:\n    jiraProject: MTA\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Products["mta"].Name; got != "mta" {
		t.Errorf("Name = %q, want mta", got)
	}
}
