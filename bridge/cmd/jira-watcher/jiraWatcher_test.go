package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/dymurray/mta-rhtpa-bridge/internal/finding"
	"github.com/dymurray/mta-rhtpa-bridge/internal/jira"
	"github.com/konveyor/tackle2-hub/shared/api"
	"github.com/konveyor/tackle2-hub/shared/binding"
)

// fakeHub is a minimal hub (applications, facts, tasks, tags) recording
// every mutation.
type fakeHub struct {
	mu         sync.Mutex
	apps       []*api.Application
	nextAppID  uint
	facts      map[string]any // "appID:source:key"
	tasks      []*api.Task
	nextTaskID uint
	comments   []string
	// failFactPut makes fact PUTs return 502 (save-failure injection).
	failFactPut bool
	// canceled records task ids canceled via PUT /tasks/{id}/cancel.
	canceled []uint
}

func (h *fakeHub) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()
	reply := func(status int, v any) {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(status)
		if v != nil {
			_ = json.NewEncoder(rw).Encode(v)
		}
	}
	path := r.URL.Path
	switch {
	case path == "/applications" && r.Method == http.MethodGet:
		reply(http.StatusOK, h.apps)
	case path == "/applications" && r.Method == http.MethodPost:
		app := &api.Application{}
		_ = json.NewDecoder(r.Body).Decode(app)
		h.nextAppID++
		app.Resource = api.Resource{ID: h.nextAppID}
		h.apps = append(h.apps, app)
		reply(http.StatusCreated, app)
	case strings.HasPrefix(path, "/applications/") && strings.Contains(path, "/facts/"):
		// /applications/{id}/facts/{source}:{key} (list: {source}:)
		rest := strings.TrimPrefix(path, "/applications/")
		id, key, _ := strings.Cut(rest, "/facts/")
		source, name, _ := strings.Cut(key, ":")
		fk := id + ":" + source + ":" + name
		switch r.Method {
		case http.MethodGet:
			if name == "" { // list facts of the source
				list := map[string]any{}
				prefix := id + ":" + source + ":"
				for k, v := range h.facts {
					if strings.HasPrefix(k, prefix) {
						list[strings.TrimPrefix(k, prefix)] = v
					}
				}
				reply(http.StatusOK, list)
				return
			}
			if v, ok := h.facts[fk]; ok {
				reply(http.StatusOK, v)
				return
			}
			reply(http.StatusNotFound, nil)
		case http.MethodPut:
			if h.failFactPut {
				reply(http.StatusBadGateway, nil)
				return
			}
			var v any
			_ = json.NewDecoder(r.Body).Decode(&v)
			h.facts[fk] = v
			reply(http.StatusNoContent, nil)
		}
	case path == "/tasks" && r.Method == http.MethodGet:
		reply(http.StatusOK, h.tasks)
	case path == "/tasks" && r.Method == http.MethodPost:
		task := &api.Task{}
		_ = json.NewDecoder(r.Body).Decode(task)
		h.nextTaskID++
		task.Resource = api.Resource{ID: h.nextTaskID}
		h.tasks = append(h.tasks, task)
		reply(http.StatusCreated, task)
	case strings.HasPrefix(path, "/tasks/") && strings.HasSuffix(path, "/cancel") && r.Method == http.MethodPut:
		var id uint
		_, _ = fmt.Sscanf(path, "/tasks/%d/", &id)
		h.canceled = append(h.canceled, id)
		for _, t := range h.tasks {
			if t.ID == id {
				t.State = "Canceled"
			}
		}
		reply(http.StatusNoContent, nil)
	case strings.HasPrefix(path, "/tasks/") && r.Method == http.MethodGet:
		var id uint
		_, _ = fmt.Sscanf(path, "/tasks/%d", &id)
		for _, t := range h.tasks {
			if t.ID == id {
				reply(http.StatusOK, t)
				return
			}
		}
		reply(http.StatusNotFound, nil)
	case path == "/tagcategories" || path == "/tags":
		reply(http.StatusOK, map[string]any{"id": 1})
	case strings.Contains(path, "/tags/"):
		reply(http.StatusNoContent, nil)
	default:
		reply(http.StatusNotFound, nil)
	}
}

// fakeJIRA serves Search and the issue/comment endpoints the watcher uses.
type fakeJIRA struct {
	mu        sync.Mutex
	tickets   []jira.Ticket
	issueDesc map[string]string // key -> description text
	comments  []string          // "key: body"
	closed    []string
	jqls      []string // recorded search JQL
	// byProject, when set, serves tickets per `project = X` clause of the
	// search JQL instead of the flat tickets list.
	byProject map[string][]jira.Ticket
	// fixVersions holds each ticket's fixVersion names (key -> names);
	// fixEdits records the fixVersion PUTs ("key: names").
	fixVersions map[string][]string
	fixEdits    []string
	// users maps email -> accountId for user search; userSearches counts
	// the lookups; assigned records assignee PUTs ("key: accountId").
	users        map[string]string
	userSearches int
	userStatus   int // when set, user search fails with this HTTP status
	assigned     []string
}

var jqlProject = regexp.MustCompile(`project = (\w+)`)

func (f *fakeJIRA) srv(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /rest/api/3/search/jql", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if q, ok := body["jql"].(string); ok {
			f.jqls = append(f.jqls, q)
		}
		tickets := f.tickets
		if f.byProject != nil {
			tickets = nil
			if m := jqlProject.FindStringSubmatch(fmt.Sprint(body["jql"])); m != nil {
				tickets = f.byProject[m[1]]
			}
		}
		issues := make([]map[string]any, len(tickets))
		for i, tk := range tickets {
			fields := map[string]any{
				"summary": tk.Summary,
				"labels":  tk.Labels,
				"status":  map[string]any{"name": tk.Status},
			}
			if tk.AssigneeID != "" || tk.AssigneeEmail != "" {
				fields["assignee"] = map[string]any{"accountId": tk.AssigneeID, "emailAddress": tk.AssigneeEmail}
			}
			issues[i] = map[string]any{"key": tk.Key, "fields": fields}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"issues": issues})
	})
	mux.HandleFunc("GET /rest/api/3/issue/{key}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		key := r.PathValue("key")
		text := f.issueDesc[key]
		var versions []map[string]string
		for _, n := range f.fixVersions[key] {
			versions = append(versions, map[string]string{"name": n})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"fields": map[string]any{
			"fixVersions": versions,
			"description": map[string]any{"type": "doc", "content": []any{
				map[string]any{"type": "paragraph", "content": []any{
					map[string]any{"type": "text", "text": text}}}}}}})
	})
	mux.HandleFunc("GET /rest/api/3/issue/{key}/comment", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		key := r.PathValue("key")
		var comments []map[string]any
		for _, c := range f.comments {
			if k, body, ok := strings.Cut(c, ": "); ok && k == key {
				comments = append(comments, map[string]any{"body": map[string]any{
					"type": "doc", "content": []any{
						map[string]any{"type": "paragraph", "content": []any{
							map[string]any{"type": "text", "text": body}}}}}})
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"comments": comments, "total": len(comments)})
	})
	mux.HandleFunc("POST /rest/api/3/issue/{key}/comment", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		// REST v3 wraps the ADF document in a "body" field.
		adf, _ := body["body"].(map[string]any)
		f.comments = append(f.comments, r.PathValue("key")+": "+commentText(adf))
		w.WriteHeader(http.StatusCreated)
	})
	mux.HandleFunc("GET /rest/api/3/issue/{key}/transitions", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"transitions":[{"id":"31","name":"Done"},{"id":"41","name":"POST"}]}`))
	})
	mux.HandleFunc("POST /rest/api/3/issue/{key}/transitions", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var body struct {
			Transition struct {
				ID string `json:"id"`
			} `json:"transition"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.closed = append(f.closed, r.PathValue("key")+":"+body.Transition.ID)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("PUT /rest/api/3/issue/{key}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var body struct {
			Fields struct {
				FixVersions []struct {
					Name string `json:"name"`
				} `json:"fixVersions"`
			} `json:"fields"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		var names []string
		for _, v := range body.Fields.FixVersions {
			names = append(names, v.Name)
		}
		key := r.PathValue("key")
		if f.fixVersions == nil {
			f.fixVersions = map[string][]string{}
		}
		f.fixVersions[key] = names
		f.fixEdits = append(f.fixEdits, key+": "+strings.Join(names, ","))
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("PUT /rest/api/3/issue/{key}/assignee", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var body struct {
			AccountID string `json:"accountId"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.assigned = append(f.assigned, r.PathValue("key")+": "+body.AccountID)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /rest/api/3/user/search", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.userSearches++
		if f.userStatus != 0 {
			w.WriteHeader(f.userStatus)
			return
		}
		q := r.URL.Query().Get("query")
		var users []map[string]string
		if id, ok := f.users[q]; ok {
			users = append(users, map[string]string{"accountId": id, "emailAddress": q})
		}
		_ = json.NewEncoder(w).Encode(users)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func commentText(adf map[string]any) string {
	var out []string
	if content, ok := adf["content"].([]any); ok {
		for _, p := range content {
			if pm, ok := p.(map[string]any); ok {
				if nodes, ok := pm["content"].([]any); ok {
					for _, n := range nodes {
						if nm, ok := n.(map[string]any); ok {
							if t, ok := nm["text"].(string); ok {
								out = append(out, t)
							}
						}
					}
				}
			}
		}
	}
	return strings.Join(out, "\n")
}

const imageMap = `
products:
  demo:
    jiraProject: MTA
    streams:
      demo-1:
        branch: release-1
    images:
      img/demo:
        repo: https://github.com/example/demo.git
        autoClose: true
`

func newTestWatcher(t *testing.T, hubSrv, jiraSrv *httptest.Server, mapData string) (w *Watcher, hub *fakeHub, fj *fakeJIRA) {
	hub = &fakeHub{facts: map[string]any{}}
	fj = &fakeJIRA{issueDesc: map[string]string{}}
	dir := t.TempDir()
	path := filepath.Join(dir, "map.yaml")
	if err := os.WriteFile(path, []byte(mapData), 0o600); err != nil {
		t.Fatal(err)
	}
	w = &Watcher{
		hub:       binding.New(hubSrv.URL),
		jira:      jira.New(jiraSrv.URL, "u", "t"),
		imagePath: path,
		noted:     map[string]bool{},
	}
	return
}

func startHub(t *testing.T, h *fakeHub) *httptest.Server {
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func ticket(key string, labels ...string) jira.Ticket {
	return jira.Ticket{Key: key, Summary: "fix " + key + " [demo-1]", Labels: labels, Status: "In Progress"}
}

func (h *fakeHub) taskKinds() (kinds []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, t := range h.tasks {
		kinds = append(kinds, fmt.Sprintf("%s:%s", t.Kind, t.Name))
	}
	return
}

func (h *fakeHub) fact(appID uint, source, key string) *finding.Finding {
	h.mu.Lock()
	defer h.mu.Unlock()
	v, ok := h.facts[fmt.Sprintf("%d:%s:%s", appID, source, key)]
	if !ok {
		return nil
	}
	b, _ := json.Marshal(v)
	f := &finding.Finding{}
	_ = json.Unmarshal(b, f)
	return f
}

func TestDispatchCreatesFindingAndTask(t *testing.T) {
	fh := &fakeHub{facts: map[string]any{}}
	fh.apps = append(fh.apps, &api.Application{
		Resource:   api.Resource{ID: 1},
		Name:       "demo",
		Repository: &api.Repository{Kind: "git", URL: "https://github.com/example/demo.git", Branch: "release-1"},
	})
	fh.facts["1:rhtpa:sbom"] = map[string]any{"id": "sbom-1"}
	hubSrv := startHub(t, fh)
	fj := &fakeJIRA{issueDesc: map[string]string{"MTA-1": "CVE-2024-1234 affects commons-text"}}
	fj.tickets = []jira.Ticket{ticket("MTA-1", "pscomponent:img/demo")}
	jiraSrv := fj.srv(t)
	w, _, _ := newTestWatcher(t, hubSrv, jiraSrv, imageMap)

	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	kinds := fh.taskKinds()
	if len(kinds) != 1 || !strings.Contains(kinds[0], "cve-remediation") {
		t.Fatalf("tasks = %v, want one cve-remediation task", kinds)
	}
	f := fh.fact(1, "cve", "CVE-2024-1234")
	if f == nil {
		t.Fatal("finding not created")
	}
	if f.JiraKey != "MTA-1" || !f.FromJIRA() || f.Component != "img/demo" || f.Status != finding.StatusDetected {
		t.Errorf("finding = %+v", f)
	}
	if f.TaskID == 0 {
		t.Error("finding must record the task id")
	}
	if f.JiraCommentState != finding.StatusDetected {
		t.Errorf("jiraCommentState = %q, want Detected", f.JiraCommentState)
	}

	// Second poll over identical state: no duplicate task, no comment.
	before := len(fh.tasks)
	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	if len(fh.tasks) != before {
		t.Errorf("tasks = %d, want %d (no duplicate dispatch)", len(fh.tasks), before)
	}
	if len(fj.comments) != 0 {
		t.Errorf("comments = %v, want none (no state change)", fj.comments)
	}
}

func TestBootstrapDefersWithoutSBOM(t *testing.T) {
	fh := &fakeHub{facts: map[string]any{}}
	fh.apps = append(fh.apps, &api.Application{
		Resource:   api.Resource{ID: 1},
		Name:       "demo",
		Repository: &api.Repository{Kind: "git", URL: "https://github.com/example/demo.git", Branch: "release-1"},
	})
	hubSrv := startHub(t, fh)
	fj := &fakeJIRA{issueDesc: map[string]string{"MTA-1": "CVE-2024-1234"}}
	fj.tickets = []jira.Ticket{ticket("MTA-1", "pscomponent:img/demo")}
	jiraSrv := fj.srv(t)
	w, _, _ := newTestWatcher(t, hubSrv, jiraSrv, imageMap)

	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	kinds := fh.taskKinds()
	if len(kinds) != 1 || !strings.Contains(kinds[0], "sbom-discovery") {
		t.Fatalf("tasks = %v, want one sbom-discovery bootstrap task", kinds)
	}
	if fh.fact(1, "cve", "CVE-2024-1234") != nil {
		t.Error("remediation finding must not exist before the SBOM")
	}
	// Second poll while still bootstrapping: no second bootstrap task.
	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	if len(fh.tasks) != 1 {
		t.Errorf("tasks = %d, want 1 (no duplicate bootstrap)", len(fh.tasks))
	}

	// SBOM appears: the remediation dispatch happens.
	fh.mu.Lock()
	fh.facts["1:rhtpa:sbom"] = map[string]any{"id": "sbom-1"}
	fh.mu.Unlock()
	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	kinds = fh.taskKinds()
	if len(kinds) != 2 || !strings.Contains(kinds[1], "cve-remediation") {
		t.Fatalf("tasks = %v, want bootstrap + remediation", kinds)
	}
}

func TestCreatesMissingApplication(t *testing.T) {
	fh := &fakeHub{facts: map[string]any{}}
	hubSrv := startHub(t, fh)
	fj := &fakeJIRA{issueDesc: map[string]string{"MTA-1": "CVE-2024-1234"}}
	fj.tickets = []jira.Ticket{ticket("MTA-1", "pscomponent:img/demo")}
	jiraSrv := fj.srv(t)
	w, _, _ := newTestWatcher(t, hubSrv, jiraSrv, imageMap)

	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	if len(fh.repoApps()) != 1 || fh.repoApps()[0].Repository == nil || fh.repoApps()[0].Repository.URL != "https://github.com/example/demo.git" {
		t.Fatalf("apps = %+v, want one for the mapped repo", fh.repoApps())
	}
}

func TestCommentReconcileAndAutoClose(t *testing.T) {
	fh := &fakeHub{facts: map[string]any{}}
	fh.apps = append(fh.apps, &api.Application{
		Resource:   api.Resource{ID: 1},
		Name:       "demo",
		Repository: &api.Repository{Kind: "git", URL: "https://github.com/example/demo.git", Branch: "release-1"},
	})
	fh.facts["1:rhtpa:sbom"] = map[string]any{"id": "sbom-1"}
	hubSrv := startHub(t, fh)
	fj := &fakeJIRA{issueDesc: map[string]string{"MTA-1": "CVE-2024-1234"}}
	fj.tickets = []jira.Ticket{ticket("MTA-1", "pscomponent:img/demo")}
	jiraSrv := fj.srv(t)
	w, _, _ := newTestWatcher(t, hubSrv, jiraSrv, imageMap)
	w.closeTransition = "Done"

	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	// Simulate the addon's verdict on the finding.
	f := fh.fact(1, "cve", "CVE-2024-1234")
	f.Status = finding.StatusNotAffected
	f.Reachability = &finding.Reachability{Verdict: finding.VerdictUnreachable}
	f.Reachability.Vex = finding.VexStatement{
		Status:        "not_affected",
		Justification: "vulnerable_code_not_in_execute_path",
	}
	fh.mu.Lock()
	fh.facts["1:cve:CVE-2024-1234"] = f
	fh.mu.Unlock()

	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	if len(fj.comments) != 1 {
		t.Fatalf("comments = %v, want one", fj.comments)
	}
	if !strings.Contains(fj.comments[0], "NotAffected") || !strings.Contains(fj.comments[0], "vulnerable_code_not_in_execute_path") {
		t.Errorf("comment = %q, want verdict + VEX justification", fj.comments[0])
	}
	f = fh.fact(1, "cve", "CVE-2024-1234")
	if f.JiraCommentState != finding.StatusNotAffected {
		t.Errorf("jiraCommentState = %q, want NotAffected", f.JiraCommentState)
	}
	// autoClose is on for img/demo: the ticket must be closed.
	if len(fj.closed) != 1 || fj.closed[0] != "MTA-1:31" {
		t.Errorf("closed = %v, want [MTA-1:31]", fj.closed)
	}
	// Third poll: no further comment (state unchanged).
	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	if len(fj.comments) != 1 {
		t.Errorf("comments = %v, want no duplicate", fj.comments)
	}
}

// TestPROpenTransitionsTicket: a finding reaching PullRequestOpen must
// move the ticket through the configured PR transition (prodsec "POST").
func TestPROpenTransitionsTicket(t *testing.T) {
	fh := &fakeHub{facts: map[string]any{}}
	fh.apps = append(fh.apps, &api.Application{
		Resource:   api.Resource{ID: 1},
		Name:       "demo",
		Repository: &api.Repository{Kind: "git", URL: "https://github.com/example/demo.git", Branch: "release-1"},
	})
	fh.facts["1:rhtpa:sbom"] = map[string]any{"id": "sbom-1"}
	hubSrv := startHub(t, fh)
	fj := &fakeJIRA{issueDesc: map[string]string{"MTA-1": "CVE-2024-1234"}}
	fj.tickets = []jira.Ticket{ticket("MTA-1", "pscomponent:img/demo")}
	jiraSrv := fj.srv(t)
	w, _, _ := newTestWatcher(t, hubSrv, jiraSrv, imageMap)
	w.prTransition = "POST"

	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	// Simulate the addon opening the remediation PR.
	f := fh.fact(1, "cve", "CVE-2024-1234")
	f.Status = finding.StatusPullRequestOpen
	f.Strategy = finding.StrategyAutoBump
	f.PullRequestURL = "https://github.com/example/demo/pull/7"
	fh.mu.Lock()
	fh.facts["1:cve:CVE-2024-1234"] = f
	fh.mu.Unlock()

	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	if len(fj.comments) != 1 || !strings.Contains(fj.comments[0], "Pull request") {
		t.Errorf("comments = %v, want the PR comment", fj.comments)
	}
	// POST is transition id 41 in the fake; the ticket must have moved,
	// and only once (no duplicate on the next poll).
	if len(fj.closed) != 1 || fj.closed[0] != "MTA-1:41" {
		t.Errorf("transitions = %v, want [MTA-1:41]", fj.closed)
	}
	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	if len(fj.closed) != 1 {
		t.Errorf("transitions = %v, want no duplicate", fj.closed)
	}
}

func TestClosedTicketNotCommented(t *testing.T) {
	fh := &fakeHub{facts: map[string]any{}}
	fh.apps = append(fh.apps, &api.Application{
		Resource:   api.Resource{ID: 1},
		Name:       "demo",
		Repository: &api.Repository{Kind: "git", URL: "https://github.com/example/demo.git", Branch: "release-1"},
	})
	fh.facts["1:rhtpa:sbom"] = map[string]any{"id": "sbom-1"}
	// A finding whose ticket is closed (not returned by Search).
	fh.facts["1:cve:CVE-2024-1234"] = &finding.Finding{
		CVE: "CVE-2024-1234", Status: finding.StatusNotAffected,
		Source: finding.SourceFieldJIRA, JiraKey: "MTA-9", JiraCommentState: "",
	}
	hubSrv := startHub(t, fh)
	fj := &fakeJIRA{issueDesc: map[string]string{}}
	jiraSrv := fj.srv(t)
	w, _, _ := newTestWatcher(t, hubSrv, jiraSrv, imageMap)

	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	if len(fj.comments) != 0 {
		t.Errorf("comments = %v, want none for a closed ticket", fj.comments)
	}
}

func TestNoCVERadiusTicketCommentedOnce(t *testing.T) {
	fh := &fakeHub{facts: map[string]any{}}
	hubSrv := startHub(t, fh)
	fj := &fakeJIRA{issueDesc: map[string]string{"MTA-1": "no ids here"}}
	fj.tickets = []jira.Ticket{ticket("MTA-1", "pscomponent:img/demo")}
	jiraSrv := fj.srv(t)
	w, _, _ := newTestWatcher(t, hubSrv, jiraSrv, imageMap)

	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	if len(fj.comments) != 1 || !strings.Contains(fj.comments[0], "no CVE") {
		t.Fatalf("comments = %v, want one couldn't-parse comment", fj.comments)
	}
	if len(fh.tasks) != 0 || len(fh.repoApps()) != 0 {
		t.Errorf("tasks = %v apps = %v, want none", fh.taskKinds(), fh.repoApps())
	}
	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	if len(fj.comments) != 1 {
		t.Errorf("comments = %v, want no duplicate", fj.comments)
	}
}

func TestUnmappedImageCommented(t *testing.T) {
	fh := &fakeHub{facts: map[string]any{}}
	hubSrv := startHub(t, fh)
	fj := &fakeJIRA{issueDesc: map[string]string{"MTA-1": "CVE-2024-1234"}}
	fj.tickets = []jira.Ticket{ticket("MTA-1", "pscomponent:img/other")}
	jiraSrv := fj.srv(t)
	w, _, _ := newTestWatcher(t, hubSrv, jiraSrv, imageMap)

	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	if len(fj.comments) != 1 || !strings.Contains(fj.comments[0], "no repo mapping") {
		t.Fatalf("comments = %v, want one unmapped comment", fj.comments)
	}
	if len(fh.tasks) != 0 {
		t.Errorf("tasks = %v, want none", fh.taskKinds())
	}
}

func TestDryRunWritesNothing(t *testing.T) {
	fh := &fakeHub{facts: map[string]any{}}
	fh.apps = append(fh.apps, &api.Application{
		Resource:   api.Resource{ID: 1},
		Name:       "demo",
		Repository: &api.Repository{Kind: "git", URL: "https://github.com/example/demo.git", Branch: "release-1"},
	})
	fh.facts["1:rhtpa:sbom"] = map[string]any{"id": "sbom-1"}
	hubSrv := startHub(t, fh)
	fj := &fakeJIRA{issueDesc: map[string]string{"MTA-1": "CVE-2024-1234"}}
	fj.tickets = []jira.Ticket{ticket("MTA-1", "pscomponent:img/demo")}
	jiraSrv := fj.srv(t)
	w, _, _ := newTestWatcher(t, hubSrv, jiraSrv, imageMap)
	w.dryRun = true

	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	if len(fh.tasks) != 0 || len(fj.comments) != 0 || fh.fact(1, "cve", "CVE-2024-1234") != nil {
		t.Errorf("dry run wrote: tasks=%v comments=%v finding=%v", fh.taskKinds(), fj.comments, fh.fact(1, "cve", "CVE-2024-1234"))
	}
}

// mainGateEnv builds a stream app (id 1, release-1, SBOM present) holding a
// stream finding in status, plus a main app (id 2). mainPurls nil means the
// main app has no SBOM.
func mainGateEnv(t *testing.T, status string, pkg finding.Package, mainPurls []string) (*Watcher, *fakeHub, *fakeJIRA) {
	t.Helper()
	fh := &fakeHub{facts: map[string]any{}}
	fh.apps = append(fh.apps,
		&api.Application{
			Resource:   api.Resource{ID: 1},
			Name:       "demo-release-1",
			Repository: &api.Repository{Kind: "git", URL: "https://github.com/example/demo.git", Branch: "release-1"},
		},
		&api.Application{
			Resource:   api.Resource{ID: 2},
			Name:       "demo-main",
			Repository: &api.Repository{Kind: "git", URL: "https://github.com/example/demo.git", Branch: "main"},
		})
	fh.nextAppID = 2
	fh.facts["1:rhtpa:sbom"] = map[string]any{"id": "sbom-1"}
	if mainPurls != nil {
		fh.facts["2:rhtpa:sbom"] = map[string]any{"id": "sbom-2", "purls": mainPurls}
	}
	fh.facts["1:cve:CVE-2024-1234"] = &finding.Finding{
		CVE: "CVE-2024-1234", Source: finding.SourceFieldJIRA, JiraKey: "MTA-1",
		Status: status, JiraCommentState: status, Package: pkg,
	}
	hubSrv := startHub(t, fh)
	fj := &fakeJIRA{issueDesc: map[string]string{"MTA-1": "CVE-2024-1234"}}
	fj.tickets = []jira.Ticket{ticket("MTA-1", "pscomponent:img/demo")}
	w, _, _ := newTestWatcher(t, hubSrv, fj.srv(t), imageMap)
	return w, fh, fj
}

var testPkg = finding.Package{
	Purl: "pkg:golang/github.com/foo/bar@v4.5.0#v4", Group: "github.com/foo", Name: "bar", Version: "4.5.0",
}

func countRemediation(fh *fakeHub, appID uint) (n int) {
	fh.mu.Lock()
	defer fh.mu.Unlock()
	for _, t := range fh.tasks {
		if t.Kind == finding.KindRemediation && t.Application != nil && t.Application.ID == appID {
			n++
		}
	}
	return
}

func countNotes(fj *fakeJIRA, sub string) (n int) {
	fj.mu.Lock()
	defer fj.mu.Unlock()
	for _, c := range fj.comments {
		if strings.Contains(c, sub) {
			n++
		}
	}
	return
}

func TestMainGateDispatchesWhenPurlPresent(t *testing.T) {
	// SBOM purls are Go-normalized; the finding's purl is not.
	w, fh, _ := mainGateEnv(t, finding.StatusPullRequestOpen, testPkg,
		[]string{"pkg:golang/github.com/foo/bar/v4@4.4.0", "pkg:golang/other/x@1.0.0"})
	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	if n := countRemediation(fh, 2); n != 1 {
		t.Fatalf("main remediation tasks = %d, want 1 (tasks %v)", n, fh.taskKinds())
	}
	if f := fh.fact(2, "cve", "CVE-2024-1234"); f == nil || f.JiraKey != "MTA-1" {
		t.Errorf("main finding = %+v", f)
	}
	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	if n := countRemediation(fh, 2); n != 1 {
		t.Errorf("main remediation tasks = %d after repoll, want 1", n)
	}
}

func TestMainGateCleanMainNotesOnce(t *testing.T) {
	w, fh, fj := mainGateEnv(t, finding.StatusRemediated, testPkg, []string{"pkg:golang/other/x@1.0.0"})
	for i := 0; i < 2; i++ {
		if err := w.poll(); err != nil {
			t.Fatal(err)
		}
	}
	if n := countNotes(fj, "main is not affected in https://github.com/example/demo.git: github.com/foo:bar is not in main's dependencies."); n != 1 {
		t.Errorf("clean-main notes = %d, want 1 (comments %v)", n, fj.comments)
	}
	if n := countRemediation(fh, 2); n != 0 {
		t.Errorf("main tasks = %d, want 0", n)
	}
}

func TestMainGateWaitsForSBOM(t *testing.T) {
	w, fh, _ := mainGateEnv(t, finding.StatusPullRequestOpen, testPkg, nil)
	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	if got := fh.taskKinds(); len(got) != 1 || !strings.Contains(got[0], "sbom-discovery") {
		t.Fatalf("tasks = %v, want one sbom-discovery", got)
	}
	if n := countRemediation(fh, 2); n != 0 {
		t.Fatalf("remediation before SBOM = %d", n)
	}
	fh.mu.Lock()
	fh.tasks[0].State = "Succeeded"
	fh.facts["2:rhtpa:sbom"] = map[string]any{"id": "sbom-2", "purls": []string{"pkg:golang/github.com/foo/bar/v4@4.5.0"}}
	fh.mu.Unlock()
	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	if n := countRemediation(fh, 2); n != 1 {
		t.Errorf("remediation after SBOM = %d, want 1", n)
	}
}

func TestMainGateSBOMFailedNotResubmitted(t *testing.T) {
	w, fh, fj := mainGateEnv(t, finding.StatusPullRequestOpen, testPkg, nil)
	fh.tasks = append(fh.tasks, &api.Task{
		Resource: api.Resource{ID: 9}, Kind: finding.KindSBOM, State: "Failed", Application: &api.Ref{ID: 2},
	})
	fh.nextTaskID = 9
	for i := 0; i < 2; i++ {
		if err := w.poll(); err != nil {
			t.Fatal(err)
		}
	}
	if len(fh.tasks) != 1 {
		t.Errorf("tasks = %v, want nothing new", fh.taskKinds())
	}
	if n := countNotes(fj, "SBOM discovery"); n != 1 {
		t.Errorf("sbom-failed notes = %d, want 1 (comments %v)", n, fj.comments)
	}
}

func TestMainGateNotBeforeVerdict(t *testing.T) {
	w, fh, fj := mainGateEnv(t, finding.StatusAnalyzing, testPkg, []string{"pkg:golang/github.com/foo/bar/v4@4.5.0"})
	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	if len(fh.tasks) != 0 || len(fj.comments) != 0 {
		t.Errorf("tasks %v comments %v, want nothing", fh.taskKinds(), fj.comments)
	}
}

func TestMainGateSkipsFailedRemediation(t *testing.T) {
	w, fh, _ := mainGateEnv(t, finding.StatusFailed, testPkg, []string{"pkg:golang/github.com/foo/bar/v4@4.5.0"})
	if err := w.poll(); err != nil {
		t.Fatal(err)
	}
	if len(fh.tasks) != 0 {
		t.Errorf("tasks = %v, want none", fh.taskKinds())
	}
}

func TestMainHasPackage(t *testing.T) {
	sbom := &finding.SBOM{Purls: []string{
		"pkg:maven/org.apache.commons/commons-text@1.9",
		"pkg:golang/github.com/foo/bar/v4@4.4.0",
	}}
	cases := []struct {
		name string
		pkg  finding.Package
		want bool
	}{
		{"go purl, other version, raw form", testPkg, true},
		{"go purl without major differs", finding.Package{Purl: "pkg:golang/github.com/foo/bar@v1.0.0"}, false},
		{"maven by purl", finding.Package{Purl: "pkg:maven/org.apache.commons/commons-text@1.10?type=jar"}, true},
		{"group+name fallback", finding.Package{Group: "org.apache.commons", Name: "commons-text"}, true},
		{"absent", finding.Package{Purl: "pkg:maven/a/b@1", Group: "a", Name: "b"}, false},
	}
	for _, c := range cases {
		if got := mainHasPackage(sbom, c.pkg); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
	if mainHasPackage(nil, testPkg) {
		t.Error("nil sbom must not contain anything")
	}
}
