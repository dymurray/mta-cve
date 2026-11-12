package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/konveyor/tackle2-hub/shared/api"
)

const mtaMap = `
products:
  mta:
    jiraProject: MTA
    streams:
      mta-1:
        branch: release-1
    images:
      img/mta:
        repo: https://github.com/example/mta.git
`

func addMarker(fh *fakeHub) {
	fh.nextAppID++
	fh.apps = append(fh.apps, &api.Application{Resource: api.Resource{ID: fh.nextAppID}, Name: markerAppName})
}

func cnvFact() map[string]any {
	return map[string]any{
		"updatedAt": time.Now().UTC().Format(time.RFC3339),
		"updatedBy": "admin",
		"products": map[string]any{
			"cnv": map[string]any{"jiraProject": "CNV", "mainBranch": "main",
				"streams": map[string]any{}, "images": map[string]any{}},
		},
	}
}

func TestResolveConfigUsesFactWhenPresent(t *testing.T) {
	w, fh, puts := publishEnv(t, mtaMap)
	addMarker(fh)
	fh.facts[markerFactKey] = cnvFact()
	cfg, err := w.resolveConfig()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.Products["cnv"]; !ok || len(cfg.Products) != 1 {
		t.Errorf("products = %+v, want only cnv", cfg.Products)
	}
	if puts.Load() != 0 {
		t.Errorf("fact PUTs = %d, want 0", puts.Load())
	}
}

func TestResolveConfigSeedsWhenFactAbsent(t *testing.T) {
	w, fh, _ := publishEnv(t, mtaMap)
	cfg, err := w.resolveConfig()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.Products["mta"]; !ok {
		t.Errorf("products = %+v, want mta", cfg.Products)
	}
	pf := decodeFact(t, fh)
	if pf.UpdatedBy != "bridge" {
		t.Errorf("updatedBy = %q", pf.UpdatedBy)
	}
	if _, ok := pf.Products["mta"]; !ok {
		t.Errorf("seeded fact lacks mta: %+v", pf)
	}
}

func TestResolveConfigSeedsWhenMarkerAppExistsButFactAbsent(t *testing.T) {
	w, fh, _ := publishEnv(t, mtaMap)
	addMarker(fh)
	if _, err := w.resolveConfig(); err != nil {
		t.Fatal(err)
	}
	if len(fh.apps) != 1 {
		t.Errorf("apps = %d, want 1", len(fh.apps))
	}
	if decodeFact(t, fh).UpdatedBy != "bridge" {
		t.Error("not seeded")
	}
}

func TestResolveConfigBadFactReseeds(t *testing.T) {
	cases := map[string]any{
		"invalid json":  "garbage",
		"zero products": map[string]any{"updatedBy": "admin", "products": map[string]any{}},
	}
	for name, bad := range cases {
		t.Run(name, func(t *testing.T) {
			w, fh, _ := publishEnv(t, mtaMap)
			addMarker(fh)
			fh.facts[markerFactKey] = bad
			cfg, err := w.resolveConfig()
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := cfg.Products["mta"]; !ok {
				t.Errorf("products = %+v, want mta", cfg.Products)
			}
			pf := decodeFact(t, fh)
			if _, ok := pf.Products["mta"]; !ok || pf.UpdatedBy != "bridge" {
				t.Errorf("fact not replaced: %+v", pf)
			}
		})
	}
}

func TestPollBadFactReseedBypassesCache(t *testing.T) {
	w, fh, _ := publishEnv(t, mtaMap)
	if err := w.poll(); err != nil { // seeds; lastMapJSON set
		t.Fatal(err)
	}
	if _, ok := decodeFact(t, fh).Products["mta"]; !ok {
		t.Fatal("not seeded")
	}
	fh.mu.Lock()
	fh.facts[markerFactKey] = "corrupt"
	fh.mu.Unlock()
	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	if _, ok := decodeFact(t, fh).Products["mta"]; !ok {
		t.Error("fact not restored; cache skipped recovery write")
	}
}

func TestResolveConfigDryRunNeverWrites(t *testing.T) {
	w, fh, puts := publishEnv(t, mtaMap)
	w.dryRun = true
	cfg, err := w.resolveConfig()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.Products["mta"]; !ok {
		t.Errorf("products = %+v", cfg.Products)
	}
	if len(fh.apps) != 0 || len(fh.facts) != 0 || puts.Load() != 0 {
		t.Errorf("dry run wrote apps=%d facts=%d puts=%d", len(fh.apps), len(fh.facts), puts.Load())
	}
}

func TestResolveConfigNoFactNoConfigMap(t *testing.T) {
	w, _, _ := publishEnv(t, mtaMap)
	if err := os.Remove(w.imagePath); err != nil {
		t.Fatal(err)
	}
	if _, err := w.resolveConfig(); err == nil {
		t.Error("want error")
	}
}

func TestPollReseedsAfterFactDeleted(t *testing.T) {
	w, fh, _ := publishEnv(t, mtaMap)
	if err := w.poll(); err != nil { // seeds; lastMapJSON set
		t.Fatal(err)
	}
	fh.mu.Lock()
	delete(fh.facts, markerFactKey)
	fh.mu.Unlock()
	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	if _, ok := decodeFact(t, fh).Products["mta"]; !ok {
		t.Error("fact not restored after deletion")
	}
}

func TestPollReseedsAfterMarkerAppDeleted(t *testing.T) {
	w, fh, _ := publishEnv(t, mtaMap)
	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	fh.mu.Lock()
	fh.apps = nil
	delete(fh.facts, markerFactKey)
	fh.nextAppID = 0
	fh.mu.Unlock()
	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	if _, ok := decodeFact(t, fh).Products["mta"]; !ok {
		t.Error("fact not restored after marker app deletion")
	}
}

func TestResolveConfigFactTransportErrorFails(t *testing.T) {
	fh := &fakeHub{facts: map[string]any{}}
	addMarker(fh)
	hubSrv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/facts/bridge:component-map") {
			rw.WriteHeader(http.StatusBadGateway)
			return
		}
		fh.ServeHTTP(rw, r)
	}))
	t.Cleanup(hubSrv.Close)
	fj := &fakeJIRA{issueDesc: map[string]string{}}
	w, _, _ := newTestWatcher(t, hubSrv, fj.srv(t), mtaMap)
	if _, err := w.resolveConfig(); err == nil {
		t.Error("want error on fact GET transport failure, got nil (stale ConfigMap fallback)")
	}
	if err := w.poll(); err == nil {
		t.Error("poll: want error")
	}
	if len(fh.facts) != 0 {
		t.Errorf("facts written on transport error: %v", fh.facts)
	}
}
