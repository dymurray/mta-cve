package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dymurray/mta-rhtpa-bridge/internal/finding"
	"github.com/dymurray/mta-rhtpa-bridge/internal/scope"
	"github.com/konveyor/tackle2-hub/shared/binding"
)

func TestParseLsRemote(t *testing.T) {
	if got := parseLsRemote("abc123\tHEAD\n"); got != "abc123" {
		t.Error(got)
	}
	if got := parseLsRemote(""); got != "" {
		t.Error(got)
	}
}

func TestLsRemoteRef(t *testing.T) {
	if got := lsRemoteRef("main"); got != "refs/heads/main" {
		t.Error(got)
	}
	if got := lsRemoteRef(""); got != "HEAD" {
		t.Error(got)
	}
}

func TestSkip(t *testing.T) {
	if !skip(finding.SBOM{Commit: "a"}, "a") {
		t.Error("same")
	}
	if skip(finding.SBOM{Commit: "a"}, "b") {
		t.Error("different")
	}
	if skip(finding.SBOM{Commit: "a"}, "") {
		t.Error("empty head")
	}
	if skip(finding.SBOM{}, "a") {
		t.Error("empty recorded commit")
	}
}

func TestResetFinding(t *testing.T) {
	f := &finding.Finding{Status: finding.StatusExhausted, Attempts: 3}
	resetFinding(f)
	if f.Status != finding.StatusFailed || f.Attempts != 0 || f.Message == "" {
		t.Errorf("%+v", f)
	}
}

func fakeHub(t *testing.T, archetypes any) *binding.RichClient {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/archetypes" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(archetypes)
	}))
	t.Cleanup(srv.Close)
	return binding.New(srv.URL)
}

func noGit(url, ref string) (string, error) {
	return "", errors.New("lsRemote must not be called")
}

func TestRefreshNoArchetype(t *testing.T) {
	hub := fakeHub(t, []any{})
	_, _, err := refresh(hub, "konveyor-cves", noGit)
	if !errors.Is(err, scope.ErrNoArchetype) {
		t.Errorf("err = %v", err)
	}
}

func TestRefreshNoMembers(t *testing.T) {
	hub := fakeHub(t, []map[string]any{{"id": 1, "name": "konveyor-cves"}})
	created, _, err := refresh(hub, "konveyor-cves", noGit)
	if err != nil || created != 0 {
		t.Errorf("created=%d err=%v", created, err)
	}
}
