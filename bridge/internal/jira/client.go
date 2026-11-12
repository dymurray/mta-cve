// Package jira is a minimal JIRA Cloud REST v3 client: issue search by
// JQL, comments, and workflow transitions, plus the ticket parsing the
// CVE bridge needs (pscomponent labels, CVE ids). It is hand-rolled
// net/http on purpose — the bridge adds no dependencies.
package jira

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Client talks to one JIRA Cloud instance with basic (email + token) auth.
type Client struct {
	baseURL string
	email   string
	token   string
	http    *http.Client
}

// New returns a client for baseURL (e.g. https://redhat.atlassian.net).
func New(baseURL, email, token string) *Client {
	return &Client{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		email:   email,
		token:   token,
		http:    &http.Client{Timeout: 30 * time.Second},
	}
}

// Ticket is the slice of an issue the bridge cares about.
type Ticket struct {
	Key     string
	Summary string
	Labels  []string
	Status  string
	Updated time.Time
	// AssigneeID and AssigneeEmail are empty when the ticket is unassigned
	// (or the email is hidden by the user's privacy settings).
	AssigneeID    string
	AssigneeEmail string
}

// PsComponents returns the ticket's pscomponent label values, with the
// "pscomponent:" prefix stripped.
func (t Ticket) PsComponents() []string {
	var out []string
	for _, l := range t.Labels {
		if v, ok := strings.CutPrefix(l, "pscomponent:"); ok && v != "" {
			out = append(out, v)
		}
	}
	return out
}

// Search returns the issues matching jql (fields: summary, labels,
// status, updated), following JIRA Cloud page tokens up to 50 issues.
func (c *Client) Search(jql string) (tickets []Ticket, err error) {
	body := map[string]any{
		"jql":        jql,
		"maxResults": 50,
		"fields":     []string{"summary", "labels", "status", "updated", "assignee"},
	}
	pageToken := ""
	for {
		if pageToken != "" {
			body["nextPageToken"] = pageToken
		}
		var page struct {
			Issues []struct {
				Key    string `json:"key"`
				Fields struct {
					Summary string   `json:"summary"`
					Labels  []string `json:"labels"`
					Status  struct {
						Name string `json:"name"`
					} `json:"status"`
					Updated  string `json:"updated"`
					Assignee *struct {
						AccountID    string `json:"accountId"`
						EmailAddress string `json:"emailAddress"`
					} `json:"assignee"`
				} `json:"fields"`
			} `json:"issues"`
			NextPageToken string `json:"nextPageToken"`
		}
		err = c.post("/rest/api/3/search/jql", body, &page)
		if err != nil {
			return
		}
		for _, issue := range page.Issues {
			t := Ticket{
				Key:     issue.Key,
				Summary: issue.Fields.Summary,
				Labels:  issue.Fields.Labels,
				Status:  issue.Fields.Status.Name,
			}
			if a := issue.Fields.Assignee; a != nil {
				t.AssigneeID, t.AssigneeEmail = a.AccountID, a.EmailAddress
			}
			t.Updated, _ = time.Parse("2006-01-02T15:04:05.000-0700", issue.Fields.Updated)
			tickets = append(tickets, t)
		}
		if page.NextPageToken == "" || len(tickets) >= 50 {
			return
		}
		pageToken = page.NextPageToken
	}
}

// CVEIDs returns the CVE ids in the ticket's summary and description,
// deduplicated and sorted.
func (c *Client) CVEIDs(t Ticket) (ids []string, err error) {
	var issue struct {
		Fields struct {
			Description json.RawMessage `json:"description"`
		} `json:"fields"`
	}
	err = c.get("/rest/api/3/issue/"+t.Key+"?fields=description", &issue)
	if err != nil {
		return
	}
	seen := map[string]bool{}
	for _, m := range cveRe.FindAllString(t.Summary+" "+adfText(issue.Fields.Description), -1) {
		seen[m] = true
	}
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return
}

// adfText collects the text of every text node in an ADF document.
func adfText(doc json.RawMessage) (out string) {
	var walk func(node any)
	walk = func(node any) {
		switch v := node.(type) {
		case map[string]any:
			if t, ok := v["text"].(string); ok {
				out += t + " "
			}
			if content, ok := v["content"].([]any); ok {
				for _, child := range content {
					walk(child)
				}
			}
		case []any:
			for _, child := range v {
				walk(child)
			}
		}
	}
	var node any
	if json.Unmarshal(doc, &node) == nil {
		walk(node)
	}
	return
}

var cveRe = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)

// Comment posts body on the ticket as an ADF comment built by CommentADF.
// An empty body is a no-op.
func (c *Client) Comment(key, body string) error {
	if body == "" {
		return nil
	}
	// REST v3 wraps the ADF document in a "body" field; a bare document
	// is rejected with "Comment body can not be empty!".
	return c.post("/rest/api/3/issue/"+key+"/comment", map[string]any{"body": CommentADF(body)}, nil)
}

// Comments returns the plain-text bodies of the ticket's comments (used to
// recognize the watcher's own one-time notes after a restart).
func (c *Client) Comments(key string) ([]string, error) {
	var res struct {
		Comments []struct {
			Body json.RawMessage `json:"body"`
		} `json:"comments"`
	}
	if err := c.get("/rest/api/3/issue/"+key+"/comment", &res); err != nil {
		return nil, err
	}
	bodies := make([]string, 0, len(res.Comments))
	for _, cm := range res.Comments {
		bodies = append(bodies, adfText(cm.Body))
	}
	return bodies, nil
}

// Transition moves the ticket through the workflow transition whose
// name matches target (e.g. "Done", "POST").
func (c *Client) Transition(key, target string) error {
	var list struct {
		Transitions []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"transitions"`
	}
	if err := c.get("/rest/api/3/issue/"+key+"/transitions", &list); err != nil {
		return err
	}
	for _, tr := range list.Transitions {
		if tr.Name == target {
			return c.post("/rest/api/3/issue/"+key+"/transitions", map[string]any{
				"transition": map[string]string{"id": tr.ID},
			}, nil)
		}
	}
	return fmt.Errorf("jira: ticket %s has no %q transition", key, target)
}

// SetFixVersion adds fixVersion to the ticket's fixVersions, keeping the
// existing ones. It is a no-op when the version is already present. The
// edit error is returned for the caller to log; it is not fatal.
func (c *Client) SetFixVersion(key, fixVersion string) error {
	var issue struct {
		Fields struct {
			FixVersions []struct {
				Name string `json:"name"`
			} `json:"fixVersions"`
		} `json:"fields"`
	}
	if err := c.get("/rest/api/3/issue/"+key+"?fields=fixVersions", &issue); err != nil {
		return err
	}
	versions := []map[string]string{}
	for _, v := range issue.Fields.FixVersions {
		if v.Name == fixVersion {
			return nil
		}
		versions = append(versions, map[string]string{"name": v.Name})
	}
	versions = append(versions, map[string]string{"name": fixVersion})
	return c.put("/rest/api/3/issue/"+key, map[string]any{
		"fields": map[string]any{"fixVersions": versions},
	})
}

// Assign sets the ticket's assignee to the user with accountID.
func (c *Client) Assign(key, accountID string) error {
	return c.put("/rest/api/3/issue/"+key+"/assignee", map[string]string{"accountId": accountID})
}

// ErrNoUser is returned (wrapped) by AccountID when the search succeeded but
// no user has that email; any other error is transient.
var ErrNoUser = errors.New("jira: no user found")

// AccountID resolves email to a JIRA accountId via user search, requiring
// an exact emailAddress match (the search is fuzzy).
func (c *Client) AccountID(email string) (string, error) {
	var users []struct {
		AccountID    string `json:"accountId"`
		EmailAddress string `json:"emailAddress"`
	}
	if err := c.get("/rest/api/3/user/search?query="+url.QueryEscape(email), &users); err != nil {
		return "", err
	}
	for _, u := range users {
		if u.EmailAddress == email {
			return u.AccountID, nil
		}
	}
	return "", fmt.Errorf("%w for %s", ErrNoUser, email)
}

func (c *Client) get(path string, out any) error {
	req, err := http.NewRequest(http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	return c.do(req, out)
}

func (c *Client) post(path string, body, out any) error {
	return c.send(http.MethodPost, path, body, out)
}

func (c *Client) put(path string, body any) error {
	return c.send(http.MethodPut, path, body, nil)
}

func (c *Client) send(method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = strings.NewReader(string(b))
	}
	req, err := http.NewRequest(method, c.baseURL+path, rd)
	if err != nil {
		return err
	}
	return c.do(req, out)
}

func (c *Client) do(req *http.Request, out any) error {
	req.Header.Set("Accept", "application/json")
	if req.Body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.SetBasicAuth(c.email, c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("jira: %s %s: %s: %s", req.Method, req.URL.Path, resp.Status, b)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
