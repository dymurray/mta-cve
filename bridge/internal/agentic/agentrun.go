// Package agentic creates and inspects AgentRuns through the hub's
// /agentic/agentruns API. Creating runs through the hub (rather than the
// Kubernetes API) lets the hub mint the scoped HUB_TOKEN the harness needs.
package agentic

import (
	"fmt"
	"strings"
	"time"

	"github.com/konveyor/tackle2-hub/shared/binding"
	"github.com/konveyor/tackle2-hub/shared/binding/auth"
)

const route = "/agentic/agentruns"

// Labels applied to runs created by the bridge.
const (
	LabelApplication = "konveyor.io/application"
	LabelCVE         = "konveyor.io/cve"
	LabelManagedBy   = "app.kubernetes.io/managed-by"
)

// Client for hub agentic resources.
type Client struct {
	hub *binding.RichClient
}

// New builds a client for the hub at url authenticated with token.
func New(url, token string) (c *Client) {
	hub := binding.New(url)
	hub.Client.Use(auth.NewBearer(token))
	c = &Client{hub: hub}
	return
}

// EnvVar is a container env var.
type EnvVar struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Metadata is object metadata.
type Metadata struct {
	Name              string            `json:"name"`
	Labels            map[string]string `json:"labels,omitempty"`
	CreationTimestamp time.Time         `json:"creationTimestamp,omitempty"`
}

// Execution limits.
type Execution struct {
	MaxTurns int `json:"maxTurns,omitempty"`
}

// Spec of an AgentRun.
type Spec struct {
	AgentRef     string    `json:"agentRef"`
	Gateway      string    `json:"gateway,omitempty"`
	Instructions string    `json:"instructions,omitempty"`
	Env          []EnvVar  `json:"env,omitempty"`
	Execution    Execution `json:"execution,omitempty"`
}

// Status of an AgentRun.
type Status struct {
	Phase string `json:"phase,omitempty"`
}

// AgentRun resource.
type AgentRun struct {
	APIVersion string   `json:"apiVersion"`
	Kind       string   `json:"kind"`
	Metadata   Metadata `json:"metadata"`
	Spec       Spec     `json:"spec"`
	Status     Status   `json:"status,omitempty"`
}

// Request describes a CVE remediation run.
type Request struct {
	Name         string
	Agent        string
	Gateway      string
	AppID        uint
	CVE          string
	TargetBranch string
	// PushURL, when set, is where the agent pushes TargetBranch (a fork;
	// the harness still clones the application's repository).
	PushURL      string
	Instructions string
	Guide        string
	MaxTurns     int
}

// Create submits an AgentRun.
func (c *Client) Create(req Request) (run *AgentRun, err error) {
	run = &AgentRun{
		APIVersion: "konveyor.io/v1alpha1",
		Kind:       "AgentRun",
		Metadata: Metadata{
			Name: req.Name,
			Labels: map[string]string{
				LabelApplication: fmt.Sprint(req.AppID),
				LabelCVE:         strings.ToLower(req.CVE),
				LabelManagedBy:   "mta-rhtpa-bridge",
			},
		},
		Spec: Spec{
			AgentRef:     req.Agent,
			Gateway:      req.Gateway,
			Instructions: req.Instructions,
			Execution:    Execution{MaxTurns: req.MaxTurns},
			Env: []EnvVar{
				{Name: "APP_ID", Value: fmt.Sprint(req.AppID)},
				{Name: "TARGET_BRANCH", Value: req.TargetBranch},
				{Name: "KONVEYOR_WORKFLOW_GUIDE", Value: req.Guide},
				{Name: "KONVEYOR_WORKFLOW_STAGE", Value: "1"},
				{Name: "KONVEYOR_WORKFLOW_STAGE_COUNT", Value: "1"},
			},
		},
	}
	if req.PushURL != "" {
		run.Spec.Env = append(run.Spec.Env, EnvVar{Name: "HARNESS_PUSH_URL", Value: req.PushURL})
	}
	err = c.hub.Client.Post(route, run)
	return
}

// List returns the AgentRuns.
func (c *Client) List() (runs []AgentRun, err error) {
	err = c.hub.Client.Get(route, &runs)
	return
}

// Active returns the AgentRuns created by the bridge that have not
// finished (phase not Succeeded or Failed), ignoring runs created before
// staleAfter ago (stuck runs must not block new ones forever).
func Active(runs []AgentRun, now time.Time, staleAfter time.Duration) (active []AgentRun) {
	for _, run := range runs {
		if run.Metadata.Labels[LabelManagedBy] != "mta-rhtpa-bridge" {
			continue
		}
		switch run.Status.Phase {
		case "Succeeded", "Failed":
			continue
		}
		if !run.Metadata.CreationTimestamp.IsZero() && now.Sub(run.Metadata.CreationTimestamp) > staleAfter {
			continue
		}
		active = append(active, run)
	}
	return
}

// Get returns an AgentRun by name.
func (c *Client) Get(name string) (run *AgentRun, err error) {
	run = &AgentRun{}
	err = c.hub.Client.Get(route+"/"+name, run)
	return
}
