// Package github opens pull requests for remediation branches using the
// application's source identity (a GitHub token).
package github

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Client for the GitHub REST API.
type Client struct {
	BaseURL string
	Token   string
	http    *http.Client
}

// New returns a client for api.github.com.
func New(token string) *Client {
	return &Client{
		BaseURL: "https://api.github.com",
		Token:   token,
		http:    &http.Client{Timeout: time.Minute},
	}
}

var repoRe = regexp.MustCompile(`github\.com[/:]([^/]+)/([^/]+?)(?:\.git)?/?$`)

// ParseRepo returns owner and repository from a GitHub remote URL.
func ParseRepo(remote string) (owner, repo string, ok bool) {
	m := repoRe.FindStringSubmatch(strings.TrimSpace(remote))
	if m == nil {
		return
	}
	return m[1], m[2], true
}

// PullRequest is a created or existing pull request.
type PullRequest struct {
	Number   int        `json:"number"`
	HTMLURL  string     `json:"html_url"`
	State    string     `json:"state"`
	MergedAt *time.Time `json:"merged_at"`
}

// PullRequest returns a pull request by number.
func (c *Client) PullRequest(owner, repo string, number int) (pr PullRequest, err error) {
	err = c.do(http.MethodGet, fmt.Sprintf("/repos/%s/%s/pulls/%d", owner, repo, number), nil, &pr)
	return
}

// Repo metadata.
type Repo struct {
	Name          string `json:"name"`
	FullName      string `json:"full_name"`
	DefaultBranch string `json:"default_branch"`
	Fork          bool   `json:"fork"`
	Parent        *struct {
		FullName string `json:"full_name"`
	} `json:"parent,omitempty"`
}

// Repository returns repository metadata.
func (c *Client) Repository(owner, repo string) (r Repo, err error) {
	err = c.do(http.MethodGet, fmt.Sprintf("/repos/%s/%s", owner, repo), nil, &r)
	return
}

// Comparison of base...head.
type Comparison struct {
	AheadBy int `json:"ahead_by"`
	Commits []struct {
		Commit struct {
			Message string `json:"message"`
		} `json:"commit"`
	} `json:"commits"`
	Files []struct {
		Filename string `json:"filename"`
	} `json:"files"`
}

// Compare returns the commits on head that are not on base.
func (c *Client) Compare(owner, repo, base, head string) (cmp Comparison, err error) {
	path := fmt.Sprintf("/repos/%s/%s/compare/%s...%s", owner, repo, url.PathEscape(base), url.PathEscape(head))
	err = c.do(http.MethodGet, path, nil, &cmp)
	return
}

// CreateFork forks owner/repo into the token's account (default branch
// only) and returns the fork. GitHub creates it asynchronously; when the
// account already has the fork, it is returned.
func (c *Client) CreateFork(owner, repo string) (r Repo, err error) {
	err = c.do(http.MethodPost, fmt.Sprintf("/repos/%s/%s/forks", owner, repo), map[string]any{"default_branch_only": true}, &r)
	return
}

// OpenPullRequest creates a pull request for head into base, or returns the
// open pull request that already exists for head. head is a branch of
// owner/repo, or "<fork owner>:<branch>" for a branch of a fork.
func (c *Client) OpenPullRequest(owner, repo, base, head, title, body string) (pr PullRequest, err error) {
	req := map[string]any{"title": title, "head": head, "base": base, "body": body, "maintainer_can_modify": true}
	err = c.do(http.MethodPost, fmt.Sprintf("/repos/%s/%s/pulls", owner, repo), req, &pr)
	if err == nil {
		return
	}
	if he, ok := err.(*HTTPError); ok && he.Status == http.StatusUnprocessableEntity && strings.Contains(he.Body, "already exists") {
		var open []PullRequest
		qualified := head
		if !strings.Contains(head, ":") {
			qualified = owner + ":" + head
		}
		q := url.Values{"head": {qualified}, "state": {"open"}}
		if lErr := c.do(http.MethodGet, fmt.Sprintf("/repos/%s/%s/pulls?%s", owner, repo, q.Encode()), nil, &open); lErr == nil && len(open) > 0 {
			return open[0], nil
		}
	}
	return
}

// HTTPError is a non-2xx response.
type HTTPError struct {
	Status int
	Body   string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("github: HTTP %d: %s", e.Status, e.Body)
}

func (c *Client) do(method, path string, in, out any) (err error) {
	var body io.Reader
	if in != nil {
		b, mErr := json.Marshal(in)
		if mErr != nil {
			return mErr
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.BaseURL+path, body)
	if err != nil {
		return
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		err = &HTTPError{Status: resp.StatusCode, Body: string(b)}
		return
	}
	if out != nil {
		err = json.Unmarshal(b, out)
	}
	return
}
