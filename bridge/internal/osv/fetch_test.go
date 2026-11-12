package osv

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchFrom(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/vulns/CVE-2024-1234" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"id":"CVE-2024-1234","summary":"a thing"}`))
	}))
	t.Cleanup(srv.Close)
	doc, err := FetchFrom(srv.URL, "CVE-2024-1234")
	if err != nil {
		t.Fatal(err)
	}
	if string(doc) != `{"id":"CVE-2024-1234","summary":"a thing"}` {
		t.Errorf("doc = %s", doc)
	}
	if _, err := FetchFrom(srv.URL, "CVE-0000-0000"); err == nil {
		t.Error("404 must error")
	}
}
