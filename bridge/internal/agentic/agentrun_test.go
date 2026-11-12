package agentic

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCreatePushURL(t *testing.T) {
	var got AgentRun
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(got)
	}))
	defer srv.Close()
	c := New(srv.URL, "t")
	for _, push := range []string{"", "https://github.com/dymurray/kubevirt.git"} {
		if _, err := c.Create(Request{Name: "r", Agent: "a", CVE: "CVE-1", PushURL: push}); err != nil {
			t.Fatal(err)
		}
		found := ""
		for _, e := range got.Spec.Env {
			if e.Name == "HARNESS_PUSH_URL" {
				found = e.Value
			}
		}
		if found != push {
			t.Errorf("HARNESS_PUSH_URL = %q, want %q", found, push)
		}
	}
}
