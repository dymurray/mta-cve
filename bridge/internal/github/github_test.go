package github

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseRepo(t *testing.T) {
	cases := map[string][2]string{
		"https://github.com/konveyor/tackle2-hub":      {"konveyor", "tackle2-hub"},
		"https://github.com/dymurray/mta-cve-demo.git": {"dymurray", "mta-cve-demo"},
		"git@github.com:dymurray/mta-cve-demo-go.git":  {"dymurray", "mta-cve-demo-go"},
		"https://github.com/dymurray/app/":             {"dymurray", "app"},
	}
	for in, want := range cases {
		o, r, ok := ParseRepo(in)
		if !ok || o != want[0] || r != want[1] {
			t.Errorf("ParseRepo(%q) = %s/%s %v", in, o, r, ok)
		}
	}
	if _, _, ok := ParseRepo("https://gitlab.com/x/y"); ok {
		t.Error("non-GitHub remote must not parse")
	}
}

func TestOpenPullRequestExisting(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("missing auth")
		}
		switch {
		case r.Method == http.MethodPost:
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte(`{"message":"Validation Failed","errors":[{"message":"A pull request already exists for o:b."}]}`))
		case r.URL.Query().Get("head") == "o:b":
			_ = json.NewEncoder(w).Encode([]PullRequest{{Number: 7, HTMLURL: "https://github.com/o/r/pull/7"}})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL)
		}
	}))
	defer srv.Close()
	c := New("tok")
	c.BaseURL = srv.URL
	pr, err := c.OpenPullRequest("o", "r", "main", "b", "t", "body")
	if err != nil || pr.Number != 7 {
		t.Fatalf("pr=%+v err=%v", pr, err)
	}
}

func TestPullRequestGet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/repos/o/r/pulls/7" {
			t.Errorf("unexpected %s %s", r.Method, r.URL)
		}
		_, _ = w.Write([]byte(`{"number":7,"state":"closed","merged_at":"2026-11-01T10:00:00Z","html_url":"u"}`))
	}))
	defer srv.Close()
	c := New("tok")
	c.BaseURL = srv.URL
	pr, err := c.PullRequest("o", "r", 7)
	if err != nil || pr.State != "closed" || pr.MergedAt == nil {
		t.Fatalf("pr=%+v err=%v", pr, err)
	}
}

func TestCompareFiles(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ahead_by":1,"commits":[],"files":[{"filename":"go.mod"},{"filename":"go.sum"}]}`))
	}))
	defer srv.Close()
	c := New("t")
	c.BaseURL = srv.URL
	cmp, err := c.Compare("o", "r", "main", "fix")
	if err != nil {
		t.Fatal(err)
	}
	if len(cmp.Files) != 2 || cmp.Files[0].Filename != "go.mod" || cmp.Files[1].Filename != "go.sum" {
		t.Errorf("files=%+v", cmp.Files)
	}
}
