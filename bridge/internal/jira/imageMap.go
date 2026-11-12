package jira

import (
	"fmt"
	"regexp"
	"sort"

	"gopkg.in/yaml.v3"
)

// ImageEntry is one image of the cve-component-map: the source repos the
// image is built from, the ref to analyze, and the remediation policy.
type ImageEntry struct {
	// Repos lists the repository URLs the image is built from.
	Repos []string `yaml:"repos" json:"repos"`
	// Repo allows a single-repo shorthand (merged into Repos).
	Repo string `yaml:"repo" json:"repo,omitempty"`
	// Branch selects the initial clone/analysis ref (default branch when
	// empty). The addon derives its own fix-branch names.
	Branch string `yaml:"branch" json:"branch,omitempty"`
	// MainBranch overrides the product main-line ref for this image.
	MainBranch string `yaml:"mainBranch" json:"mainBranch,omitempty"`
	// Remediation caps the effort: "" (agent) | report | script | agent.
	Remediation string `yaml:"remediation" json:"remediation,omitempty"`
	// AutoClose closes the JIRA ticket when the verdict is NotAffected.
	AutoClose bool `yaml:"autoClose" json:"autoClose,omitempty"`
}

// Stream is one maintained release stream of a product: the branch fixes
// land on, the Jira fix version, and who owns it.
type Stream struct {
	Branch     string `yaml:"branch" json:"branch,omitempty"`
	FixVersion string `yaml:"fixVersion" json:"fixVersion,omitempty"`
	Owner      string `yaml:"owner" json:"owner,omitempty"`
}

// Product groups the streams and images of one Jira-tracked product.
type Product struct {
	// Name is the product's key in Config.Products (set by ParseConfig).
	Name        string                `yaml:"-" json:"-"`
	JiraProject string                `yaml:"jiraProject"`
	Owner       string                `yaml:"owner"`
	MainBranch  string                `yaml:"mainBranch"`
	Streams     map[string]Stream     `yaml:"streams"`
	Images      map[string]ImageEntry `yaml:"images"`
}

// Config is the cve-component-map document: products keyed by name.
type Config struct {
	Products map[string]Product `yaml:"products"`
}

// MainRefOf returns the ref that main-line analysis uses for the image: the
// image's mainBranch, else the product's, else "main".
func (p Product) MainRefOf(e ImageEntry) string {
	if e.MainBranch != "" {
		return e.MainBranch
	}
	if p.MainBranch != "" {
		return p.MainBranch
	}
	return "main"
}

// ParseConfig parses the mounted cve-component-map document. The single
// `repo:` shorthand is folded into Repos and remediation modes are validated.
func ParseConfig(data []byte) (*Config, error) {
	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("component map: %w", err)
	}
	if len(cfg.Products) == 0 {
		return nil, fmt.Errorf("component map: no products defined (is this a pre-migration flat map? entries now live under products.<name>.images)")
	}
	for name, prod := range cfg.Products {
		prod.Name = name
		for image, e := range prod.Images {
			if e.Repo != "" {
				e.Repos = append([]string{e.Repo}, e.Repos...)
				e.Repo = ""
			}
			switch e.Remediation {
			case "", "report", "script", "agent":
			default:
				return nil, fmt.Errorf("component map: %s: %s: unknown remediation mode %q", name, image, e.Remediation)
			}
			prod.Images[image] = e
		}
		cfg.Products[name] = prod
	}
	return cfg, nil
}

var streamSuffix = regexp.MustCompile(`\[([A-Za-z0-9][A-Za-z0-9._-]*)\]\s*$`)

// StreamFromSummary returns the trailing "[stream]" token of a ticket
// summary, or "" when there is none.
func StreamFromSummary(summary string) string {
	if m := streamSuffix.FindStringSubmatch(summary); m != nil {
		return m[1]
	}
	return ""
}

// Work is one dispatchable unit: a CVE ticket naming an image that maps
// to one repository, with the image's policy attached.
type Work struct {
	Ticket    Ticket
	CVEs      []string
	Image     string
	Entry     ImageEntry
	RepoURL   string
	Product   string
	Stream    string
	StreamCfg Stream
}

// Dispatches fans tickets out to per-repo work items: for each ticket,
// each mapped pscomponent image, each repo of the image, each CVE. A
// ticket whose pscomponents are all unmapped yields nothing (see
// Unmapped); a ticket with no CVE ids yields nothing (the caller reports
// it separately).
func Dispatches(tickets []Ticket, prod Product, cves func(Ticket) ([]string, error)) (work []Work) {
	for _, tk := range tickets {
		ids, err := cves(tk)
		if err != nil || len(ids) == 0 {
			continue
		}
		stream := StreamFromSummary(tk.Summary)
		for _, image := range sortedComponents(tk, prod) {
			e := prod.Images[image]
			for _, repo := range e.Repos {
				work = append(work, Work{
					Ticket: tk, CVEs: ids, Image: image, Entry: e, RepoURL: repo,
					Product: prod.Name, Stream: stream, StreamCfg: prod.Streams[stream],
				})
			}
		}
	}
	return
}

// Unmapped returns the tickets naming at least one pscomponent that has
// no image-map entry (and at least one unmapped one is not covered by a
// mapping elsewhere on the ticket).
func Unmapped(tickets []Ticket, prod Product) (out []Ticket) {
	for _, tk := range tickets {
		for _, image := range tk.PsComponents() {
			if _, ok := prod.Images[image]; !ok {
				out = append(out, tk)
				break
			}
		}
	}
	return
}

// sortedComponents returns the ticket's pscomponents that have mappings,
// sorted for deterministic dispatch order.
func sortedComponents(tk Ticket, prod Product) []string {
	var out []string
	for _, image := range tk.PsComponents() {
		if _, ok := prod.Images[image]; ok {
			out = append(out, image)
		}
	}
	sort.Strings(out)
	return out
}
