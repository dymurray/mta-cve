package main

import (
	"time"

	"github.com/dymurray/mta-rhtpa-bridge/internal/addonutil"
	"github.com/dymurray/mta-rhtpa-bridge/internal/finding"
	"github.com/dymurray/mta-rhtpa-bridge/internal/github"
	"github.com/dymurray/mta-rhtpa-bridge/internal/hubutil"
	"github.com/konveyor/tackle2-hub/shared/api"
)

// checkPullRequests refreshes the state of open remediation pull requests.
// Errors are logged and never fail the task.
func checkPullRequests(app *api.Application) {
	if app.Repository == nil {
		return
	}
	owner, repo, ok := github.ParseRepo(app.Repository.URL)
	if !ok {
		return
	}
	findings, err := hubutil.Findings(addon.Client(), app.ID)
	if err != nil {
		addon.Activity("Could not list findings: %s", err)
		return
	}
	var open []*finding.Finding
	for _, f := range findings {
		if f.Status == finding.StatusPullRequestOpen && f.PullRequestNumber > 0 {
			open = append(open, f)
		}
	}
	if len(open) == 0 {
		return
	}
	identity, err := addonutil.SourceIdentity(app)
	if err != nil {
		addon.Activity("Could not read source identity: %s", err)
		return
	}
	if identity == nil || identity.Password == "" {
		return
	}
	gh := github.New(identity.Password)
	facts := addon.Application.Select(app.ID).Fact.Source(finding.SourceCVE)
	// CVEs remediated together (finding.Group) share one pull request.
	prs := map[int]github.PullRequest{}
	for _, f := range open {
		pr, fetched := prs[f.PullRequestNumber]
		if !fetched {
			pr, err = gh.PullRequest(owner, repo, f.PullRequestNumber)
			if err != nil {
				addon.Activity("Could not fetch pull request #%d for %s: %s", f.PullRequestNumber, f.CVE, err)
				continue
			}
			prs[f.PullRequestNumber] = pr
		}
		if !applyPRState(f, pr) {
			continue
		}
		f.UpdatedAt = time.Now().UTC()
		err = facts.Set(f.CVE, f)
		if err != nil {
			addon.Activity("Could not save finding %s: %s", f.CVE, err)
			continue
		}
		addon.Activity("Pull request #%d for %s is %s.", f.PullRequestNumber, f.CVE, f.PullRequestState)
	}
}

// applyPRState records the pull request's state on the finding and reports
// whether the finding changed. A merged pull request keeps the finding in
// PullRequestOpen (the next SBOM refresh resolves it); one closed without
// merging ends the finding's remediation.
func applyPRState(f *finding.Finding, pr github.PullRequest) (changed bool) {
	if pr.State != "closed" {
		return
	}
	if pr.MergedAt != nil {
		if f.PullRequestState == finding.PRStateMerged && !f.PullRequestMergedAt.IsZero() {
			return
		}
		f.PullRequestState = finding.PRStateMerged
		f.PullRequestMergedAt = *pr.MergedAt
		return true
	}
	if f.Status == finding.StatusPullRequestClosed {
		return
	}
	f.Status = finding.StatusPullRequestClosed
	f.PullRequestState = finding.PRStateClosed
	f.Message = "Pull request closed without merging; no further action."
	return true
}
