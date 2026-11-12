// Package rhtpa is a minimal client for the Red Hat Trusted Profile Analyzer
// (trustify) v3 REST API, authenticated with OIDC client credentials.
package rhtpa

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Environment.
const (
	EnvURL          = "RHTPA_URL"
	EnvConsoleURL   = "RHTPA_CONSOLE_URL"
	EnvTokenURL     = "RHTPA_TOKEN_URL"
	EnvClientID     = "RHTPA_CLIENT_ID"
	EnvClientSecret = "RHTPA_CLIENT_SECRET"
	EnvCAFile       = "RHTPA_CA_FILE"
)

// Client for the RHTPA API.
type Client struct {
	BaseURL      string
	ConsoleURL   string
	TokenURL     string
	ClientID     string
	ClientSecret string
	http         *http.Client
	mutex        sync.Mutex
	token        string
	expiry       time.Time
}

// FromEnv builds a client from the environment.
func FromEnv() (c *Client, err error) {
	c = &Client{
		BaseURL:      strings.TrimSuffix(os.Getenv(EnvURL), "/"),
		ConsoleURL:   strings.TrimSuffix(os.Getenv(EnvConsoleURL), "/"),
		TokenURL:     os.Getenv(EnvTokenURL),
		ClientID:     os.Getenv(EnvClientID),
		ClientSecret: os.Getenv(EnvClientSecret),
	}
	if c.BaseURL == "" || c.TokenURL == "" || c.ClientID == "" {
		err = fmt.Errorf("%s, %s and %s are required", EnvURL, EnvTokenURL, EnvClientID)
		return
	}
	if c.ConsoleURL == "" {
		c.ConsoleURL = c.BaseURL
	}
	tlsCfg := &tls.Config{}
	if caFile := os.Getenv(EnvCAFile); caFile != "" {
		pool, _ := x509.SystemCertPool()
		if pool == nil {
			pool = x509.NewCertPool()
		}
		// Optional: the service CA is only present when a token is mounted.
		if pem, rErr := os.ReadFile(caFile); rErr == nil {
			pool.AppendCertsFromPEM(pem)
		}
		tlsCfg.RootCAs = pool
	}
	c.http = &http.Client{
		Timeout:   2 * time.Minute,
		Transport: &http.Transport{TLSClientConfig: tlsCfg, Proxy: http.ProxyFromEnvironment},
	}
	return
}

// SbomURL returns the console URL for an SBOM.
func (c *Client) SbomURL(id string) string {
	return c.ConsoleURL + "/sboms/" + url.PathEscape(id)
}

// VulnerabilityURL returns the console URL for a vulnerability.
func (c *Client) VulnerabilityURL(id string) string {
	return c.ConsoleURL + "/vulnerabilities/" + url.PathEscape(id)
}

// AdvisoryURL returns the console URL for an advisory.
func (c *Client) AdvisoryURL(uuid string) string {
	return c.ConsoleURL + "/advisories/" + url.PathEscape(uuid)
}

// IngestResult is returned by uploads.
type IngestResult struct {
	ID         string   `json:"id"`
	DocumentID string   `json:"document_id"`
	Warnings   []string `json:"warnings"`
}

// UploadSBOM uploads an SBOM document with the given labels.
func (c *Client) UploadSBOM(doc []byte, labels map[string]string) (r IngestResult, err error) {
	q := url.Values{}
	for k, v := range labels {
		q.Set("labels."+k, v)
	}
	err = c.do(http.MethodPost, "/api/v3/sbom?"+q.Encode(), doc, &r)
	return
}

// UploadAdvisory uploads an advisory document (OSV, CSAF, CVE).
func (c *Client) UploadAdvisory(doc []byte, labels map[string]string) (r IngestResult, err error) {
	q := url.Values{}
	for k, v := range labels {
		q.Set("labels."+k, v)
	}
	err = c.do(http.MethodPost, "/api/v3/advisory?"+q.Encode(), doc, &r)
	return
}

// DownloadAdvisory returns an advisory's original document (OSV, CSAF, ...).
func (c *Client) DownloadAdvisory(uuid string) (doc []byte, err error) {
	var raw json.RawMessage
	err = c.do(http.MethodGet, "/api/v3/advisory/"+url.PathEscape(uuid)+"/download", nil, &raw)
	doc = raw
	return
}

// DeleteSBOM deletes an SBOM.
func (c *Client) DeleteSBOM(id string) error {
	return c.do(http.MethodDelete, "/api/v3/sbom/"+url.PathEscape(id), nil, nil)
}

// Score is a CVSS score.
type Score struct {
	Type     string  `json:"type"`
	Value    float64 `json:"value"`
	Severity string  `json:"severity"`
	Vector   string  `json:"vector"`
}

// Purl reference.
type Purl struct {
	Purl string `json:"purl"`
}

// SbomPackage is an affected package in the SBOM.
type SbomPackage struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Group   string `json:"group"`
	Version string `json:"version"`
	Purl    []Purl `json:"purl"`
}

// PurlString returns the first purl.
func (p *SbomPackage) PurlString() string {
	if len(p.Purl) > 0 {
		return p.Purl[0].Purl
	}
	return p.ID
}

// SbomStatus is a vulnerability status within an advisory.
type SbomStatus struct {
	Identifier    string        `json:"identifier"`
	Title         string        `json:"title"`
	Description   string        `json:"description"`
	Status        string        `json:"status"`
	FixedVersions []string      `json:"fixed_versions"`
	Packages      []SbomPackage `json:"packages"`
	Scores        []Score       `json:"scores"`
}

// SbomAdvisory is an advisory that applies to an SBOM.
type SbomAdvisory struct {
	UUID       string            `json:"uuid"`
	Identifier string            `json:"identifier"`
	DocumentID string            `json:"document_id"`
	Title      string            `json:"title"`
	Modified   string            `json:"modified"`
	Labels     map[string]string `json:"labels"`
	Status     []SbomStatus      `json:"status"`
}

// SbomAdvisories returns the advisories that apply to an SBOM.
func (c *Client) SbomAdvisories(sbomID string) (list []SbomAdvisory, err error) {
	err = c.do(http.MethodGet, "/api/v3/sbom/"+url.PathEscape(sbomID)+"/advisory", nil, &list)
	return
}

// Vulnerability details.
type Vulnerability struct {
	Identifier  string  `json:"identifier"`
	Title       string  `json:"title"`
	Description string  `json:"description"`
	Scores      []Score `json:"scores"`
}

// Vulnerability returns vulnerability details.
func (c *Client) Vulnerability(id string) (v Vulnerability, err error) {
	err = c.do(http.MethodGet, "/api/v3/vulnerability/"+url.PathEscape(id)+"?scores=true", nil, &v)
	return
}

// HTTPError is a non-2xx response.
type HTTPError struct {
	Status int
	Body   string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("rhtpa: HTTP %d: %s", e.Status, e.Body)
}

func (c *Client) do(method, path string, body []byte, out any) (err error) {
	token, err := c.bearer()
	if err != nil {
		return
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, c.BaseURL+path, rd)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	if resp.StatusCode/100 != 2 {
		err = &HTTPError{Status: resp.StatusCode, Body: string(b)}
		return
	}
	if out != nil && len(b) > 0 {
		err = json.Unmarshal(b, out)
	}
	return
}

// bearer returns a cached access token, refreshing it before expiry.
func (c *Client) bearer() (token string, err error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.token != "" && time.Now().Before(c.expiry) {
		token = c.token
		return
	}
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.ClientID},
		"client_secret": {c.ClientSecret},
	}
	resp, err := c.http.PostForm(c.TokenURL, form)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		err = &HTTPError{Status: resp.StatusCode, Body: string(b)}
		return
	}
	var t struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	err = json.Unmarshal(b, &t)
	if err != nil {
		return
	}
	c.token = t.AccessToken
	c.expiry = time.Now().Add(time.Duration(t.ExpiresIn)*time.Second - 30*time.Second)
	token = c.token
	return
}
