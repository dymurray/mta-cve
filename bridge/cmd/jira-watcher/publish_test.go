package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dymurray/mta-rhtpa-bridge/internal/jira"
	"github.com/konveyor/tackle2-hub/shared/api"
)

const markerFactKey = "1:bridge:component-map"

type publishedFact struct {
	UpdatedAt time.Time `json:"updatedAt"`
	UpdatedBy string    `json:"updatedBy"`
	Products  map[string]struct {
		MainBranch string `json:"mainBranch"`
		Streams    map[string]struct {
			Branch string `json:"branch"`
		} `json:"streams"`
	} `json:"products"`
}

func publishEnv(t *testing.T, mapData string) (*Watcher, *fakeHub, *atomic.Int32) {
	t.Helper()
	fh := &fakeHub{facts: map[string]any{}}
	var puts atomic.Int32
	hubSrv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			puts.Add(1)
		}
		fh.ServeHTTP(rw, r)
	}))
	t.Cleanup(hubSrv.Close)
	fj := &fakeJIRA{issueDesc: map[string]string{}}
	w, _, _ := newTestWatcher(t, hubSrv, fj.srv(t), mapData)
	return w, fh, &puts
}

func decodeFact(t *testing.T, fh *fakeHub) publishedFact {
	t.Helper()
	fh.mu.Lock()
	defer fh.mu.Unlock()
	v, ok := fh.facts[markerFactKey]
	if !ok {
		t.Fatalf("fact %s not written; facts=%v", markerFactKey, fh.facts)
	}
	b, _ := json.Marshal(v)
	var pf publishedFact
	if err := json.Unmarshal(b, &pf); err != nil {
		t.Fatal(err)
	}
	return pf
}

func TestPublishComponentMapWritesFact(t *testing.T) {
	w, fh, _ := publishEnv(t, imageMap)
	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, a := range fh.apps {
		if a.Name == "cve-remediation-config" {
			n++
			if a.Repository != nil {
				t.Errorf("marker app has repository %+v", a.Repository)
			}
		}
	}
	if n != 1 {
		t.Fatalf("marker apps = %d, want 1", n)
	}
	pf := decodeFact(t, fh)
	if got := pf.Products["demo"].Streams["demo-1"].Branch; got != "release-1" {
		t.Errorf("branch = %q", got)
	}
	if got := pf.Products["demo"].MainBranch; got != "main" {
		t.Errorf("mainBranch = %q, want resolved default main", got)
	}
	if pf.UpdatedAt.IsZero() {
		t.Error("updatedAt is zero")
	}
}

func TestPublishedFactIgnoresConfigMapChange(t *testing.T) {
	w, fh, puts := publishEnv(t, imageMap)
	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	b := []byte(`
products:
  demo:
    jiraProject: MTA
    streams:
      demo-1:
        branch: release-2
    images:
      img/demo:
        repo: https://github.com/example/demo.git
`)
	if err := os.WriteFile(w.imagePath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	// The fact is authoritative: a ConfigMap edit must neither override
	// nor rewrite it.
	if got := decodeFact(t, fh).Products["demo"].Streams["demo-1"].Branch; got != "release-1" {
		t.Errorf("branch = %q, want fact value release-1", got)
	}
	if got := w.cfg.Products["demo"].Streams["demo-1"].Branch; got != "release-1" {
		t.Errorf("cfg branch = %q, want release-1", got)
	}
	if puts.Load() != 1 {
		t.Errorf("fact PUTs = %d, want 1 (seed only)", puts.Load())
	}
}

func TestPublishComponentMapDryRun(t *testing.T) {
	w, fh, _ := publishEnv(t, imageMap)
	w.dryRun = true
	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	if len(fh.apps) != 0 || len(fh.facts) != 0 {
		t.Errorf("dry run wrote apps=%d facts=%d", len(fh.apps), len(fh.facts))
	}
	if len(w.lastMapJSON) == 0 {
		t.Error("lastMapJSON not set in dry run; would re-log every poll")
	}
}

func TestPublishComponentMapFailureNonFatal(t *testing.T) {
	w, fh, _ := publishEnv(t, imageMap)
	fh.failFactPut = true
	if err := w.poll(); err != nil {
		t.Fatalf("poll error: %v", err)
	}
	found := false
	for _, a := range fh.apps {
		found = found || a.Name == "cve-remediation-config"
	}
	if !found {
		t.Error("marker app not created")
	}
}

// repoApps returns the hub's applications minus the bridge's own
// cve-remediation-config marker app.
func (h *fakeHub) repoApps() []*api.Application {
	var out []*api.Application
	for _, a := range h.apps {
		if a.Name != markerAppName {
			out = append(out, a)
		}
	}
	return out
}

func sampleCfg() *jira.Config {
	return &jira.Config{Products: map[string]jira.Product{
		"mta": {
			Name: "mta", JiraProject: "MTA", Owner: "team",
			Streams: map[string]jira.Stream{"mta-8.2": {Branch: "release-8.2", FixVersion: "8.2.0", Owner: "bob"}},
			Images:  map[string]jira.ImageEntry{"img": {Repos: []string{"https://a/x", "https://a/y"}}},
		},
	}}
}

func TestToPublishedStampsUpdated(t *testing.T) {
	b, err := json.Marshal(toPublished(sampleCfg()))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"updatedAt", "updatedBy", "products"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing key %s", k)
		}
	}
	if _, ok := m["publishedAt"]; ok {
		t.Error("publishedAt must be gone")
	}
}

func TestFromPublishedRoundTrip(t *testing.T) {
	cfg := sampleCfg()
	got := fromPublished(toPublished(cfg))
	p, ok := got.Products["mta"]
	if !ok {
		t.Fatal("mta missing")
	}
	if p.Name != "mta" || p.JiraProject != "MTA" || p.Owner != "team" {
		t.Errorf("product fields: %+v", p)
	}
	if p.MainBranch != "main" {
		t.Errorf("mainBranch = %q, want main", p.MainBranch)
	}
	if !reflect.DeepEqual(p.Streams, cfg.Products["mta"].Streams) {
		t.Errorf("streams: %+v", p.Streams)
	}
	if !reflect.DeepEqual(p.Images, cfg.Products["mta"].Images) {
		t.Errorf("images: %+v", p.Images)
	}
}

func TestFromPublishedNilAndEmpty(t *testing.T) {
	for _, d := range []*publishedConfig{nil, {}} {
		c := fromPublished(d)
		if c == nil || c.Products == nil || len(c.Products) != 0 {
			t.Errorf("got %+v", c)
		}
	}
}
