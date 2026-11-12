package jira

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newFakeJIRA serves the REST v3 endpoints the client uses and records
// requests (method + path) and posted bodies.
type fakeJIRA struct {
	t           *testing.T
	requests    []string
	bodies      []map[string]any
	authSeen    bool
	srvURL      string
	searchRes   string // raw /rest/api/3/search response body
	issue       string // raw issue response (description)
	commentsRes string // raw GET comment response
	usersRes    string // raw GET user/search response
	putStatus   int    // status for issue PUTs (default 204)
}

func newFakeJIRA(t *testing.T) *fakeJIRA {
	f := &fakeJIRA{t: t}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /rest/api/3/search/jql", func(w http.ResponseWriter, r *http.Request) {
		_, _, f.authSeen = r.BasicAuth()
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.bodies = append(f.bodies, body)
		f.requests = append(f.requests, "POST /rest/api/3/search/jql")
		w.Header().Set("Content-Type", "application/json")
		res := f.searchRes
		if res == "" {
			res = `{"issues":[]}`
		}
		_, _ = w.Write([]byte(res))
	})
	mux.HandleFunc("GET /rest/api/3/issue/", func(w http.ResponseWriter, r *http.Request) {
		f.requests = append(f.requests, "GET "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		res := f.issue
		if res == "" {
			res = `{"fields":{}}`
		}
		_, _ = w.Write([]byte(res))
	})
	mux.HandleFunc("GET /rest/api/3/issue/{key}/comment", func(w http.ResponseWriter, r *http.Request) {
		f.requests = append(f.requests, "GET "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		res := f.commentsRes
		if res == "" {
			res = `{"comments":[],"total":0}`
		}
		_, _ = w.Write([]byte(res))
	})
	mux.HandleFunc("POST /rest/api/3/issue/{key}/comment", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.bodies = append(f.bodies, body)
		f.requests = append(f.requests, "POST "+r.URL.Path)
		w.WriteHeader(http.StatusCreated)
	})
	mux.HandleFunc("GET /rest/api/3/issue/{key}/transitions", func(w http.ResponseWriter, r *http.Request) {
		f.requests = append(f.requests, "GET "+r.URL.Path)
		_, _ = w.Write([]byte(`{"transitions":[{"id":"31","name":"Done"},{"id":"11","name":"Start"}]}`))
	})
	mux.HandleFunc("POST /rest/api/3/issue/{key}/transitions", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.bodies = append(f.bodies, body)
		f.requests = append(f.requests, "POST "+r.URL.Path)
		w.WriteHeader(http.StatusNoContent)
	})
	putIssue := func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.bodies = append(f.bodies, body)
		f.requests = append(f.requests, "PUT "+r.URL.Path)
		if f.putStatus != 0 {
			w.WriteHeader(f.putStatus)
			_, _ = w.Write([]byte(`{"errorMessages":["rejected"]}`))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
	mux.HandleFunc("PUT /rest/api/3/issue/{key}", putIssue)
	mux.HandleFunc("PUT /rest/api/3/issue/{key}/assignee", putIssue)
	mux.HandleFunc("GET /rest/api/3/user/search", func(w http.ResponseWriter, r *http.Request) {
		f.requests = append(f.requests, "GET "+r.URL.Path+"?query="+r.URL.Query().Get("query"))
		w.Header().Set("Content-Type", "application/json")
		res := f.usersRes
		if res == "" {
			res = `[]`
		}
		_, _ = w.Write([]byte(res))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	f.srvURL = srv.URL
	return f
}

func TestSearchParsesTickets(t *testing.T) {
	f := newFakeJIRA(t)
	f.searchRes = `{"issues":[{"key":"MTA-7641",
		"fields":{"summary":"CVE-2024-1234 in mta",
		"labels":["pscomponent:mta/mta-solution-server-rhel9","other"],
		"status":{"name":"In Progress"},
		"updated":"2026-11-06T10:00:00.000-0500",
		"assignee":{"accountId":"acc-9","emailAddress":"dev@example.com"}}}]}`
	c := New(f.srvURL, "user@example.com", "tok")
	tickets, err := c.Search(`labels = "pscomponent:mta/mta-solution-server-rhel9"`)
	if err != nil {
		t.Fatal(err)
	}
	if len(tickets) != 1 {
		t.Fatalf("tickets = %d, want 1", len(tickets))
	}
	tk := tickets[0]
	if tk.Key != "MTA-7641" || tk.Summary != "CVE-2024-1234 in mta" || tk.Status != "In Progress" {
		t.Errorf("ticket = %+v", tk)
	}
	if !f.authSeen {
		t.Error("basic auth not sent")
	}
	if got := tk.PsComponents(); len(got) != 1 || got[0] != "mta/mta-solution-server-rhel9" {
		t.Errorf("PsComponents() = %v", got)
	}
	if tk.AssigneeID != "acc-9" || tk.AssigneeEmail != "dev@example.com" {
		t.Errorf("assignee = %q/%q", tk.AssigneeID, tk.AssigneeEmail)
	}
	if tk.Updated.IsZero() {
		t.Error("updated not parsed")
	}
	// the JQL must reach the server
	if f.bodies[0]["jql"] != `labels = "pscomponent:mta/mta-solution-server-rhel9"` {
		t.Errorf("jql = %v", f.bodies[0]["jql"])
	}
}

func TestPsComponentsNoLabels(t *testing.T) {
	if got := (Ticket{Labels: []string{"pscomponent:", "x", "pscomponent:a"}}).PsComponents(); len(got) != 1 || got[0] != "a" {
		t.Errorf("PsComponents() = %v, want [a]", got)
	}
}

func TestCVEIDsFromSummaryAndDescription(t *testing.T) {
	f := newFakeJIRA(t)
	f.issue = `{"fields":{"description":{"type":"doc","version":1,
		"content":[{"type":"paragraph","content":[{"type":"text","text":"See CVE-2024-1234 and CVE-2023-5678 again CVE-2024-1234"}]}]}}}`
	c := New(f.srvURL, "u", "t")
	ids, err := c.CVEIDs(Ticket{Key: "MTA-1", Summary: "fix CVE-2024-1234"})
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || ids[0] != "CVE-2023-5678" || ids[1] != "CVE-2024-1234" {
		t.Errorf("ids = %v, want [CVE-2023-5678 CVE-2024-1234]", ids)
	}
}

func TestCommentPostsADF(t *testing.T) {
	f := newFakeJIRA(t)
	c := New(f.srvURL, "u", "t")
	if err := c.Comment("MTA-1", "line one\nline two"); err != nil {
		t.Fatal(err)
	}
	body := f.bodies[0]
	// JIRA Cloud REST v3 wraps the ADF document in a "body" field; a bare
	// document is rejected with "Comment body can not be empty!".
	inner, ok := body["body"].(map[string]any)
	if !ok {
		t.Fatalf("payload %v has no body-wrapped ADF document", body)
	}
	if inner["type"] != "doc" {
		t.Errorf("type = %v, want doc", inner["type"])
	}
	b, _ := json.Marshal(body)
	for _, want := range []string{`"text":"line one"`, `"text":"line two"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("body %s lacks %s", b, want)
		}
	}
	if err := c.Comment("MTA-1", ""); err != nil {
		t.Errorf("empty comment must be a no-op: %v", err)
	}
	if len(f.requests) != 1 {
		t.Errorf("requests = %v", f.requests)
	}
}

func TestTransitionUsesNamedTransition(t *testing.T) {
	f := newFakeJIRA(t)
	c := New(f.srvURL, "u", "t")
	if err := c.Transition("MTA-1", "Done"); err != nil {
		t.Fatal(err)
	}
	last := f.bodies[len(f.bodies)-1]
	tr, _ := last["transition"].(map[string]any)
	if tr["id"] != "31" {
		t.Errorf("transition = %v, want id 31 (Done)", last)
	}
	if err := c.Transition("MTA-1", "Nope"); err == nil {
		t.Error("unknown transition must error")
	}
}

func TestCommentsParsesBodies(t *testing.T) {
	f := newFakeJIRA(t)
	f.commentsRes = `{"total":2,"comments":[
		{"body":{"type":"doc","content":[{"type":"paragraph","content":[{"type":"text","text":"hello"}]}]}},
		{"body":{"type":"doc","content":[{"type":"paragraph","content":[{"type":"text","text":"world [mta-bridge-note:nocve]"}]}]}}]}`
	c := New(f.srvURL, "user@example.com", "tok")
	bodies, err := c.Comments("MTA-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(bodies) != 2 || strings.TrimSpace(bodies[0]) != "hello" || !strings.Contains(bodies[1], "mta-bridge-note:nocve") {
		t.Errorf("bodies = %q", bodies)
	}
}

func TestSetFixVersionIdempotent(t *testing.T) {
	f := newFakeJIRA(t)
	f.issue = `{"fields":{"fixVersions":[{"name":"MTA 8.2.4"}]}}`
	c := New(f.srvURL, "u", "t")
	if err := c.SetFixVersion("MTA-1", "MTA 8.2.4"); err != nil {
		t.Fatal(err)
	}
	for _, r := range f.requests {
		if strings.HasPrefix(r, "PUT") {
			t.Fatalf("unexpected PUT when version present: %v", f.requests)
		}
	}

	if err := c.SetFixVersion("MTA-1", "MTA 8.2.5"); err != nil {
		t.Fatal(err)
	}
	var puts int
	for _, r := range f.requests {
		if r == "PUT /rest/api/3/issue/MTA-1" {
			puts++
		}
	}
	if puts != 1 {
		t.Fatalf("PUTs = %d, want 1 (%v)", puts, f.requests)
	}
	b, _ := json.Marshal(f.bodies[len(f.bodies)-1])
	if string(b) != `{"fields":{"fixVersions":[{"name":"MTA 8.2.4"},{"name":"MTA 8.2.5"}]}}` {
		t.Errorf("body = %s", b)
	}
}

func TestSetFixVersionEditFailureIsNonFatal(t *testing.T) {
	f := newFakeJIRA(t)
	f.putStatus = http.StatusBadRequest
	c := New(f.srvURL, "u", "t")
	err := c.SetFixVersion("MTA-1", "MTA 8.2.5")
	if err == nil || !strings.Contains(err.Error(), "400") {
		t.Fatalf("err = %v, want one containing 400", err)
	}
}

func TestAssignUsesAccountID(t *testing.T) {
	f := newFakeJIRA(t)
	c := New(f.srvURL, "u", "t")
	if err := c.Assign("MTA-1", "123"); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(f.bodies[0])
	if string(b) != `{"accountId":"123"}` || f.requests[0] != "PUT /rest/api/3/issue/MTA-1/assignee" {
		t.Errorf("request = %v body = %s", f.requests, b)
	}
}

func TestAccountIDSearch(t *testing.T) {
	f := newFakeJIRA(t)
	f.usersRes = `[{"accountId":"other","emailAddress":"other@example.com"},
		{"accountId":"abc","emailAddress":"dev@example.com"}]`
	c := New(f.srvURL, "u", "t")
	id, err := c.AccountID("dev@example.com")
	if err != nil || id != "abc" {
		t.Fatalf("id = %q err = %v", id, err)
	}
	f.usersRes = `[]`
	if _, err := c.AccountID("dev@example.com"); err == nil || !strings.Contains(err.Error(), "no user found for dev@example.com") {
		t.Errorf("err = %v", err)
	}
}
