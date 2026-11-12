package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/dymurray/mta-rhtpa-bridge/internal/finding"
	"github.com/dymurray/mta-rhtpa-bridge/internal/hubutil"
	"github.com/dymurray/mta-rhtpa-bridge/internal/jira"
	"github.com/konveyor/tackle2-hub/shared/api"
	"github.com/konveyor/tackle2-hub/shared/binding"
)

// productTicket is an open ticket tagged with the product whose search
// found it.
type productTicket struct {
	tk   jira.Ticket
	prod jira.Product
}

// poll re-reads the config, searches open tickets for every mapped image
// of every product, and reconciles them.
func (w *Watcher) poll() error {
	cfg, err := w.resolveConfig()
	if err != nil {
		return err
	}
	w.cfg = cfg
	names := make([]string, 0, len(cfg.Products))
	for name := range cfg.Products {
		names = append(names, name)
	}
	sort.Strings(names)
	open := map[string]productTicket{}
	for _, name := range names {
		prod := cfg.Products[name]
		if prod.JiraProject == "" {
			log.Printf("product %s: no jiraProject configured; skipped", name)
			continue
		}
		for image := range prod.Images {
			jql := fmt.Sprintf("project = %s AND labels = %q AND status not in (Closed, Done)", prod.JiraProject, "pscomponent:"+image)
			if w.jqlPrefix != "" {
				jql += " AND " + w.jqlPrefix
			}
			tickets, err := w.jira.Search(jql)
			if err != nil {
				return fmt.Errorf("search %s/%s: %w", name, image, err)
			}
			for _, tk := range tickets {
				if _, seen := open[tk.Key]; !seen {
					open[tk.Key] = productTicket{tk: tk, prod: prod}
				}
			}
		}
	}
	var list []productTicket
	for _, pt := range open {
		list = append(list, pt)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].tk.Key < list[j].tk.Key })
	for _, pt := range list {
		if err := w.handleTicket(pt.tk, pt.prod); err != nil {
			log.Printf("ticket %s: %v", pt.tk.Key, err)
		}
	}
	return nil
}

// handleTicket maps one ticket to repos, dispatches remediation for its
// CVEs on the stream's branch, and syncs comments.
func (w *Watcher) handleTicket(tk jira.Ticket, prod jira.Product) error {
	if unmapped := jira.Unmapped([]jira.Ticket{tk}, prod); len(unmapped) > 0 {
		fresh := w.noteOnce(tk, "unmapped", fmt.Sprintf(
			"MTA CVE bridge: no repo mapping is configured for image(s) %s; nothing will be analyzed.",
			strings.Join(tk.PsComponents(), ", ")))
		var ust *jira.Stream
		if st, ok := prod.Streams[jira.StreamFromSummary(tk.Summary)]; ok {
			ust = &st
		}
		w.assignOwner(tk, w.owner(prod, ust), fresh)
		return nil
	}
	stream := jira.StreamFromSummary(tk.Summary)
	st, ok := prod.Streams[stream]
	if !ok {
		detail := "no stream token (a trailing [stream] in the summary) was found"
		if stream != "" {
			detail = fmt.Sprintf("stream %q is not configured for product %s", stream, prod.Name)
		}
		fresh := w.noteOnce(tk, "unknown-stream", "MTA CVE bridge: "+detail+"; nothing will be analyzed.")
		w.assignOwner(tk, w.owner(prod, nil), fresh)
		return nil
	}
	cves, err := w.jira.CVEIDs(tk)
	if err != nil {
		return err
	}
	if len(cves) == 0 {
		fresh := w.noteOnce(tk, "nocve", "MTA CVE bridge: no CVE id could be parsed from this ticket; nothing will be analyzed.")
		w.assignOwner(tk, w.owner(prod, &st), fresh)
		return nil
	}
	works := jira.Dispatches([]jira.Ticket{tk}, prod, func(jira.Ticket) ([]string, error) { return cves, nil })
	for _, wk := range works {
		if err := w.dispatchWork(wk, prod); err != nil {
			log.Printf("ticket %s: %s: %v", tk.Key, wk.RepoURL, err)
		}
	}
	if err := w.reconcileComments(tk, prod); err != nil {
		return err
	}
	// Once a stream finding has its verdict, see whether main needs the
	// same remediation.
	for _, wk := range works {
		app, err := w.findApp(wk.RepoURL, wk.StreamCfg.Branch)
		if err != nil || app == nil {
			continue
		}
		findings, err := hubutil.Findings(w.hub, app.ID)
		if err != nil {
			continue
		}
		for _, cve := range wk.CVEs {
			if f := findings[cve]; f != nil && f.JiraKey == tk.Key {
				if err := w.reconcileMain(tk, prod, wk, app, f); err != nil {
					log.Printf("ticket %s: main %s: %v", tk.Key, cve, err)
				}
			}
		}
	}
	return nil
}

// reconcileMain dispatches the remediation of a stream finding's CVE
// against the main branch, but only once the stream finding has a verdict
// that names a package and main's SBOM contains that package. The main
// finding then flows through the normal dispatch path and comment sync
// (main findings never transition or close the ticket).
func (w *Watcher) reconcileMain(tk jira.Ticket, prod jira.Product, wk jira.Work, app *api.Application, f *finding.Finding) error {
	switch f.Status {
	case finding.StatusPullRequestOpen, finding.StatusRemediated, finding.StatusNeedsAttention:
	default:
		return nil
	}
	if f.Package.Name == "" {
		return nil
	}
	mainRef := prod.MainRefOf(wk.Entry)
	if mainRef == wk.StreamCfg.Branch {
		return nil // the stream app already is main
	}
	mainApp, err := w.ensureApp(wk.RepoURL, mainRef)
	if err != nil {
		return err
	}
	sbom, err := w.sbomFact(mainApp.ID)
	if err != nil {
		return err
	}
	if sbom == nil {
		if err := w.bootstrapSBOM(mainApp, tk, ""); err != nil {
			return err
		}
		log.Printf("app %s: SBOM bootstrap pending; main remediation of %s deferred", mainApp.Name, f.CVE)
		return nil
	}
	if len(sbom.Purls) == 0 {
		// No purls (older fact, malformed document, generator without
		// purls): main's contents are unknown, never "clean". Retry next poll.
		log.Printf("app %s: SBOM fact has no purls; main remediation of %s deferred", mainApp.Name, f.CVE)
		return nil
	}
	if !mainHasPackage(sbom, f.Package) {
		w.noteOnce(tk, "main-clean:"+f.CVE+":"+wk.RepoURL, fmt.Sprintf(
			"MTA CVE bridge: main is not affected in %s: %s is not in main's dependencies.", wk.RepoURL, f.Package.Coordinate()))
		return nil
	}
	mwk := wk
	mwk.Stream = "main"
	mwk.CVEs = []string{f.CVE}
	mwk.StreamCfg = jira.Stream{Branch: mainRef}
	return w.dispatchWork(mwk, prod)
}

var (
	goMajorSubpathRe = regexp.MustCompile(`^(pkg:golang/[^@?#]+)@([^?#]+)(\?[^#]*)?#(v\d+)$`)
	goVersionRe      = regexp.MustCompile(`^(pkg:golang/[^@?#]+)@v(\d[^?#]*)(.*)$`)
)

// mainHasPackage reports whether the SBOM contains pkg, ignoring versions
// (main may already carry a different one). The finding's purl is Go
// normalized like the SBOM's purls (sbom-discovery: no "v" version prefix,
// major version as a /vN path segment) before comparing; without a purl
// match it falls back to the group and name matching a purl's
// namespace/name segments.
func mainHasPackage(sbom *finding.SBOM, pkg finding.Package) bool {
	if sbom == nil {
		return false
	}
	// identity is "type/namespace/name" of a purl, without version.
	identity := func(purl string) string {
		purl = goMajorSubpathRe.ReplaceAllString(purl, "${1}/${4}@${2}${3}")
		purl = goVersionRe.ReplaceAllString(purl, "${1}@${2}${3}")
		purl = finding.PackageKey(purl)
		if i := strings.Index(purl, "@"); i >= 0 {
			purl = purl[:i]
		}
		return strings.ToLower(purl)
	}
	want := ""
	if pkg.Purl != "" {
		want = identity(pkg.Purl)
	}
	coord := strings.ToLower(pkg.Name)
	if pkg.Group != "" {
		coord = strings.ToLower(pkg.Group) + "/" + coord
	}
	for _, p := range sbom.Purls {
		id := identity(p)
		if want != "" && id == want {
			return true
		}
		if pkg.Name != "" {
			_, path, _ := strings.Cut(strings.TrimPrefix(id, "pkg:"), "/")
			if path == coord {
				return true
			}
		}
	}
	return false
}

// dispatchWork ensures the application for the work's repo exists (with
// the archetype tag and an SBOM) and creates the finding + remediation
// task for each of the work's CVEs.
func (w *Watcher) dispatchWork(wk jira.Work, prod jira.Product) error {
	app, err := w.ensureApp(wk.RepoURL, wk.StreamCfg.Branch)
	if err != nil {
		return err
	}
	sbomID, err := w.sbomID(app.ID)
	if err != nil {
		return err
	}
	if sbomID == "" {
		if err := w.bootstrapSBOM(app, wk.Ticket, w.owner(prod, &wk.StreamCfg)); err != nil {
			return err
		}
		log.Printf("app %s: SBOM bootstrap pending; %s deferred", app.Name, strings.Join(wk.CVEs, ", "))
		return nil
	}
	findings, err := hubutil.Findings(w.hub, app.ID)
	if err != nil {
		return err
	}
	for _, cve := range wk.CVEs {
		if f := findings[cve]; f != nil {
			if !f.FromJIRA() && f.JiraKey == "" {
				// RHTPA created this finding first: stamp the JIRA
				// identity and the image's remediation mode so comment
				// reconcile and the mode gates apply (JIRA wins).
				f.JiraKey = wk.Ticket.Key
				f.Component = wk.Image
				f.RemediationMode = wk.Entry.Remediation
				if !w.dryRun {
					if err := w.save(app.ID, f); err != nil {
						return err
					}
				}
				log.Printf("app %s: stamped %s from %s onto the RHTPA finding", app.Name, cve, wk.Ticket.Key)
			}
			continue // already dispatched; comment reconcile handles the rest
		}
		if w.liveTask(app.ID, cve) {
			// A task exists whose finding save failed (or is pending):
			// never run a second one alongside it.
			continue
		}
		if err := w.dispatchCVE(app, wk, cve, sbomID); err != nil {
			return err
		}
	}
	return nil
}

// liveTask reports whether a non-terminal cve-remediation task for cve
// already runs against the application.
func (w *Watcher) liveTask(appID uint, cve string) bool {
	tasks, err := w.hub.Task.List()
	if err != nil {
		return false // cannot tell: let dispatch try (it cancels on failure)
	}
	for _, t := range tasks {
		if t.Kind != finding.KindRemediation || t.Application == nil || t.Application.ID != appID {
			continue
		}
		var taskCVE string
		switch d := t.Data.(type) {
		case map[string]any:
			taskCVE, _ = d["cve"].(string)
		case api.Map:
			taskCVE, _ = d["cve"].(string)
		}
		if taskCVE != cve {
			continue
		}
		switch t.State {
		case "Succeeded", "Failed", "Canceled":
			continue
		}
		return true
	}
	return false
}

// dispatchCVE creates the finding and one cve-remediation task for cve.
func (w *Watcher) dispatchCVE(app *api.Application, wk jira.Work, cve, sbomID string) error {
	f := &finding.Finding{
		CVE:              cve,
		DetectedAt:       time.Now().UTC(),
		Schema:           finding.SchemaVersion,
		Source:           finding.SourceFieldJIRA,
		JiraKey:          wk.Ticket.Key,
		Component:        wk.Image,
		RemediationMode:  wk.Entry.Remediation,
		Status:           finding.StatusDetected,
		Message:          fmt.Sprintf("Reported in JIRA ticket %s (stream %s).", wk.Ticket.Key, wk.Stream),
		JiraCommentState: finding.StatusDetected,
	}
	task := &api.Task{
		Name:        fmt.Sprintf("%s-%s", app.Name, strings.ToLower(cve)),
		Kind:        finding.KindRemediation,
		Application: &api.Ref{ID: app.ID},
		State:       "Ready",
		Data:        api.Map{"cve": cve, "sbomId": sbomID},
	}
	if w.dryRun {
		log.Printf("DRY-RUN app %s: dispatch %s (%s) from %s", app.Name, cve, wk.Image, wk.Ticket.Key)
		if wk.StreamCfg.FixVersion != "" {
			log.Printf("DRY-RUN ticket %s: would set fixVersion %s", wk.Ticket.Key, wk.StreamCfg.FixVersion)
		}
		return nil
	}
	if err := w.hub.Task.Create(task); err != nil {
		return err
	}
	f.TaskID = task.ID
	if err := w.save(app.ID, f); err != nil {
		// Cancel the task so the next poll does not run a second one
		// alongside it (mirrors the cve-watcher's dispatch).
		if cErr := w.hub.Task.Cancel(task.ID); cErr != nil {
			return fmt.Errorf("save finding: %v (canceling task %d failed: %v)", err, task.ID, cErr)
		}
		return fmt.Errorf("save finding: %v (task %d canceled)", err, task.ID)
	}
	log.Printf("app %s: dispatch %s from %s (%s) -> task %d", app.Name, cve, wk.Ticket.Key, wk.Image, task.ID)
	// The fixVersion is written only when the finding is first created, so
	// the gate is the durable finding itself: a replaced value is never
	// re-appended, in this process or after a restart. Main dispatches carry
	// no fixVersion. A failed edit is logged, not fatal.
	if fv := wk.StreamCfg.FixVersion; fv != "" {
		if err := w.jira.SetFixVersion(wk.Ticket.Key, fv); err != nil {
			log.Printf("ticket %s: set fixVersion: %v", wk.Ticket.Key, err)
		}
	}
	return nil
}

// ensureApp returns the application whose repository matches repoURL on
// branch, creating it (with the archetype tag) when missing. Existing
// applications are never retargeted. The name is the repo base, suffixed
// with the branch when one is set.
func (w *Watcher) ensureApp(repoURL, branch string) (*api.Application, error) {
	apps, err := w.hub.Application.List()
	if err != nil {
		return nil, err
	}
	for i := range apps {
		if sameRepoBranch(apps[i], repoURL, branch) {
			return &apps[i], nil
		}
	}
	if w.dryRun {
		log.Printf("DRY-RUN: would create application for %s", repoURL)
		return nil, fmt.Errorf("dry run: application for %s not created", repoURL)
	}
	name := repoBase(repoURL)
	if branch != "" {
		name += "-" + branch
	}
	app := &api.Application{
		Name:       name,
		Repository: &api.Repository{Kind: "git", URL: repoURL, Branch: branch},
	}
	if err := w.hub.Application.Create(app); err != nil {
		return nil, err
	}
	// Add the archetype membership tag under our own source so the
	// finding tag refresh never wipes it.
	if err := hubutil.ReplaceTags(w.hub, app.ID, "jira-watcher", w.tagCategory, "#151481", []string{w.tagName}); err != nil {
		log.Printf("app %s: archetype tag: %v", app.Name, err)
	}
	log.Printf("created application %s (%d) for %s", app.Name, app.ID, repoURL)
	return app, nil
}

// sameRepoBranch reports whether app tracks repoURL on branch.
func sameRepoBranch(app api.Application, repoURL, branch string) bool {
	return app.Repository != nil &&
		normalizeRepo(app.Repository.URL) == normalizeRepo(repoURL) &&
		app.Repository.Branch == branch
}

// normalizeRepo strips .git and a trailing slash for repo comparison.
func normalizeRepo(url string) string {
	url = strings.TrimSuffix(strings.TrimSuffix(url, "/"), ".git")
	return url
}

func repoBase(repoURL string) string {
	base := path.Base(normalizeRepo(repoURL))
	if base == "." || base == "/" {
		return normalizeRepo(repoURL)
	}
	return base
}

// sbomFact returns the application's RHTPA SBOM fact (nil when none).
func (w *Watcher) sbomFact(appID uint) (*finding.SBOM, error) {
	sbom := &finding.SBOM{}
	err := w.hub.Application.Select(appID).Fact.Source(finding.SourceRHTPA).Get(finding.KeySBOM, sbom)
	if err != nil {
		var nf *binding.NotFound
		if errors.As(err, &nf) {
			return nil, nil
		}
		return nil, err
	}
	return sbom, nil
}

// sbomID returns the application's RHTPA SBOM id ("" when none).
func (w *Watcher) sbomID(appID uint) (string, error) {
	sbom, err := w.sbomFact(appID)
	if sbom == nil {
		return "", err
	}
	return sbom.ID, nil
}

// bootstrapSBOM submits one sbom-discovery task for the application,
// unless one already exists: a live one is waited on, a terminal one is
// never resubmitted automatically (a bad repo mapping would otherwise
// spawn a failing task every poll) — the ticket is told once instead.
func (w *Watcher) bootstrapSBOM(app *api.Application, tk jira.Ticket, owner string) error {
	tasks, err := w.hub.Task.List()
	if err != nil {
		return err
	}
	for _, t := range tasks {
		if t.Kind != finding.KindSBOM || t.Application == nil || t.Application.ID != app.ID {
			continue
		}
		switch t.State {
		case "Succeeded", "Failed", "Canceled":
			fresh := w.noteOnce(tk, "sbom-failed", fmt.Sprintf(
				"MTA CVE bridge: SBOM discovery for this application ended in state %s; remediation is deferred until it succeeds. Details: %s/applications/%d.",
				t.State, strings.TrimSuffix(w.uiURL, "/"), app.ID))
			w.assignOwner(tk, owner, fresh)
			return nil
		default:
			return nil // bootstrap already in flight
		}
	}
	if w.dryRun {
		log.Printf("DRY-RUN app %s: would submit sbom-discovery", app.Name)
		return nil
	}
	task := &api.Task{
		Name:        fmt.Sprintf("%s-sbom", app.Name),
		Kind:        finding.KindSBOM,
		Application: &api.Ref{ID: app.ID},
		State:       "Ready",
	}
	if err := w.hub.Task.Create(task); err != nil {
		return err
	}
	log.Printf("app %s: no SBOM; submitted sbom-discovery task %d", app.Name, task.ID)
	return nil
}

// reconcileComments posts a comment for every finding of the ticket whose
// announced state differs from its status, on both the stream app and the
// main-line app (when it exists). JIRA transitions and auto-close are
// driven by stream findings only; main-branch findings just comment.
func (w *Watcher) reconcileComments(tk jira.Ticket, prod jira.Product) error {
	stream := prod.Streams[jira.StreamFromSummary(tk.Summary)]
	for _, image := range tk.PsComponents() {
		entry, ok := prod.Images[image]
		if !ok {
			continue
		}
		mainRef := prod.MainRefOf(entry)
		for _, repoURL := range entry.Repos {
			if app, err := w.findApp(repoURL, stream.Branch); err == nil && app != nil {
				w.reconcileApp(tk, entry, app, false, w.owner(prod, &stream))
			}
			if mainRef == stream.Branch {
				continue // the stream app already is the main app
			}
			if app, err := w.findApp(repoURL, mainRef); err == nil && app != nil {
				w.reconcileApp(tk, entry, app, true, "")
			}
		}
	}
	return nil
}

// reconcileApp comments the ticket's changed findings of one application.
// isMain suppresses the JIRA transitions and owner assignment; owner is
// who the ticket goes to when a finding needs attention or failed.
func (w *Watcher) reconcileApp(tk jira.Ticket, entry jira.ImageEntry, app *api.Application, isMain bool, owner string) {
	findings, err := hubutil.Findings(w.hub, app.ID)
	if err != nil {
		return
	}
	for _, id := range sortedFindingIDs(findings) {
		f := findings[id]
		if f.JiraKey != tk.Key || f.JiraCommentState == f.Status {
			continue
		}
		body := commentBody(f, w.uiURL, app.ID)
		attention := !isMain && (f.Status == finding.StatusNeedsAttention || f.Status == finding.StatusFailed)
		if w.dryRun {
			log.Printf("DRY-RUN ticket %s: %s %s -> %s", tk.Key, f.CVE, f.JiraCommentState, f.Status)
			if attention {
				w.assignOwner(tk, owner, true)
			}
			continue
		}
		if err := w.jira.Comment(tk.Key, body); err != nil {
			log.Printf("ticket %s: comment: %v", tk.Key, err)
			continue
		}
		// The persisted JiraCommentState makes this once per status change,
		// across restarts, like the comment it accompanies.
		if attention {
			w.assignOwner(tk, owner, true)
		}
		f.JiraCommentState = f.Status
		if err := w.save(app.ID, f); err != nil {
			log.Printf("app %s: save %s: %v", app.Name, f.CVE, err)
		}
		if isMain {
			continue
		}
		// The remediation PR is the ticket's cue to move to POST
		// (fix posted, awaiting merge).
		if f.Status == finding.StatusPullRequestOpen && w.prTransition != "" {
			if err := w.jira.Transition(tk.Key, w.prTransition); err != nil {
				log.Printf("ticket %s: pr transition: %v", tk.Key, err)
			} else {
				log.Printf("ticket %s: transitioned %s (PullRequestOpen)", tk.Key, w.prTransition)
			}
		}
		if f.Status == finding.StatusNotAffected && entry.AutoClose && w.closeTransition != "" {
			if err := w.jira.Transition(tk.Key, w.closeTransition); err != nil {
				log.Printf("ticket %s: close: %v", tk.Key, err)
			} else {
				log.Printf("ticket %s: closed (NotAffected)", tk.Key)
			}
		}
	}
}

func (w *Watcher) findApp(repoURL, branch string) (*api.Application, error) {
	apps, err := w.hub.Application.List()
	if err != nil {
		return nil, err
	}
	for i := range apps {
		if sameRepoBranch(apps[i], repoURL, branch) {
			return &apps[i], nil
		}
	}
	return nil, nil
}

func sortedFindingIDs(findings map[string]*finding.Finding) (ids []string) {
	for id := range findings {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return
}

// noteOnce comments on the ticket once per reason. The marker tag appended
// to the body makes the note recognizable in the ticket's existing
// comments, so a watcher restart does not repost it.
// It reports whether this call posted (or, in DRY_RUN, would have posted)
// the note, i.e. whether the dead end is newly reported.
func (w *Watcher) noteOnce(tk jira.Ticket, reason, body string) bool {
	key := tk.Key + "|" + reason
	if !w.noted[key] {
		if comments, err := w.jira.Comments(tk.Key); err == nil {
			for _, c := range comments {
				if strings.Contains(c, noteMarker(reason)) {
					w.noted[key] = true
					break
				}
			}
		}
	}
	if w.noted[key] {
		return false
	}
	if w.dryRun {
		log.Printf("DRY-RUN ticket %s: %s", tk.Key, body)
		return true
	}
	if err := w.jira.Comment(tk.Key, body+" "+noteMarker(reason)); err != nil {
		log.Printf("ticket %s: comment: %v", tk.Key, err)
		return false
	}
	w.noted[key] = true
	return true
}

// noteMarker is the stable tag recognizing a one-off note on a ticket.
func noteMarker(reason string) string {
	return "[mta-bridge-note:" + reason + "]"
}

func (w *Watcher) save(appID uint, f *finding.Finding) error {
	f.UpdatedAt = time.Now().UTC()
	return w.hub.Application.Select(appID).Fact.Source(finding.SourceCVE).Set(f.CVE, f)
}

// commentBody renders the finding's state change for a JIRA comment.
func commentBody(f *finding.Finding, uiURL string, appID uint) string {
	var b strings.Builder
	fmt.Fprintf(&b, "MTA CVE bridge update for %s (%s): %s.", f.CVE, f.Component, f.Status)
	if f.Message != "" {
		fmt.Fprintf(&b, " %s", f.Message)
	}
	if f.Severity != "" {
		fmt.Fprintf(&b, " Severity: %s.", f.Severity)
	}
	if f.Reachability != nil {
		fmt.Fprintf(&b, " rgctl verdict: %s.", f.Reachability.Verdict)
		if f.Reachability.Vex.Justification != "" {
			fmt.Fprintf(&b, " VEX: %s (%s).", f.Reachability.Vex.Status, f.Reachability.Vex.Justification)
		}
		if n := len(f.Reachability.CallSites); n > 0 {
			fmt.Fprintf(&b, " %d affected call site(s) in the application source.", n)
		}
	}
	if f.Package.Name != "" {
		fmt.Fprintf(&b, " Component: %s (fixed in %s).", f.Package.Coordinate(), or(f.FixedVersion, "no published fix"))
	}
	if f.PullRequestURL != "" {
		fmt.Fprintf(&b, " Pull request: %s.", f.PullRequestURL)
	}
	if uiURL != "" {
		fmt.Fprintf(&b, " Details: %s/applications/%d.", strings.TrimSuffix(uiURL, "/"), appID)
	}
	switch f.Status {
	case finding.StatusNotAffected, finding.StatusRemediated:
		// terminal and positive: nothing more to ask
	default:
		b.WriteString(" This ticket needs a human decision in JIRA if it should not progress automatically.")
	}
	return b.String()
}

func or(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// owner returns the email the ticket is handed to on a dead end: the
// resolved stream's owner (falling back to the product's), or the
// product's owner when no stream resolved (st is nil).
func (w *Watcher) owner(prod jira.Product, st *jira.Stream) string {
	if st != nil && st.Owner != "" {
		return st.Owner
	}
	return prod.Owner
}

// assignOwner assigns the ticket to the user with email. It acts only when
// trigger is true (the caller just posted the durable comment this
// assignment accompanies, so a restart never reassigns over a human) or when
// an earlier attempt for this ticket and owner failed transiently in this
// process. It does nothing when email is empty or the ticket is already
// assigned to that user; failures are logged and never abort the poll. Only
// a definitive "no such user" is remembered per email; transient lookup
// errors are retried next poll.
func (w *Watcher) assignOwner(tk jira.Ticket, email string, trigger bool) {
	if email == "" {
		return
	}
	pending := "assign-pending:" + tk.Key + ":" + email
	if !trigger && !w.noted[pending] {
		return
	}
	if tk.AssigneeEmail == email {
		delete(w.noted, pending)
		return
	}
	id, ok := w.accountIDs[email]
	if !ok {
		if w.noted["nouser:"+email] {
			return
		}
		var err error
		if id, err = w.jira.AccountID(email); err != nil {
			log.Printf("ticket %s: owner %s: %v", tk.Key, email, err)
			if errors.Is(err, jira.ErrNoUser) {
				w.noted["nouser:"+email] = true
			} else {
				w.noted[pending] = true // transient: retry next poll
			}
			return
		}
		if w.accountIDs == nil {
			w.accountIDs = map[string]string{}
		}
		w.accountIDs[email] = id
	}
	if tk.AssigneeID == id {
		delete(w.noted, pending) // email hidden by privacy settings, but already the owner
		return
	}
	if w.dryRun {
		log.Printf("DRY-RUN ticket %s: would assign to %s", tk.Key, email)
		return
	}
	if err := w.jira.Assign(tk.Key, id); err != nil {
		log.Printf("ticket %s: assign %s: %v", tk.Key, email, err)
		w.noted[pending] = true
		return
	}
	delete(w.noted, pending)
	log.Printf("ticket %s: assigned to %s", tk.Key, email)
}

// markerAppName is the application that carries the component-map fact.
const markerAppName = "cve-remediation-config"

type publishedImage struct {
	Repos       []string `json:"repos"`
	Branch      string   `json:"branch"`
	MainBranch  string   `json:"mainBranch"`
	Remediation string   `json:"remediation"`
	AutoClose   bool     `json:"autoClose"`
}

type publishedStream struct {
	Branch     string `json:"branch"`
	FixVersion string `json:"fixVersion"`
	Owner      string `json:"owner"`
}

type publishedProduct struct {
	JiraProject string                     `json:"jiraProject"`
	Owner       string                     `json:"owner"`
	MainBranch  string                     `json:"mainBranch"`
	Streams     map[string]publishedStream `json:"streams"`
	Images      map[string]publishedImage  `json:"images"`
}

type publishedConfig struct {
	UpdatedAt time.Time                   `json:"updatedAt"`
	UpdatedBy string                      `json:"updatedBy"`
	Products  map[string]publishedProduct `json:"products"`
}

func toPublished(cfg *jira.Config) *publishedConfig {
	out := &publishedConfig{Products: map[string]publishedProduct{}}
	for name, p := range cfg.Products {
		pp := publishedProduct{
			JiraProject: p.JiraProject,
			Owner:       p.Owner,
			MainBranch:  p.MainRefOf(jira.ImageEntry{}),
			Streams:     map[string]publishedStream{},
			Images:      map[string]publishedImage{},
		}
		for sn, st := range p.Streams {
			pp.Streams[sn] = publishedStream{Branch: st.Branch, FixVersion: st.FixVersion, Owner: st.Owner}
		}
		for in, im := range p.Images {
			repos := im.Repos
			if repos == nil {
				repos = []string{}
			}
			pp.Images[in] = publishedImage{Repos: repos, Branch: im.Branch, MainBranch: im.MainBranch, Remediation: im.Remediation, AutoClose: im.AutoClose}
		}
		out.Products[name] = pp
	}
	return out
}

// fromPublished is the inverse of toPublished. Product.Name is set from the
// map key; the DTO never emits the yaml "repo" shorthand, so none is folded.
func fromPublished(dto *publishedConfig) *jira.Config {
	out := &jira.Config{Products: map[string]jira.Product{}}
	if dto == nil {
		return out
	}
	for name, pp := range dto.Products {
		p := jira.Product{
			Name:        name,
			JiraProject: pp.JiraProject,
			Owner:       pp.Owner,
			MainBranch:  pp.MainBranch,
			Streams:     map[string]jira.Stream{},
			Images:      map[string]jira.ImageEntry{},
		}
		for sn, st := range pp.Streams {
			p.Streams[sn] = jira.Stream{Branch: st.Branch, FixVersion: st.FixVersion, Owner: st.Owner}
		}
		for in, im := range pp.Images {
			p.Images[in] = jira.ImageEntry{Repos: im.Repos, Branch: im.Branch, MainBranch: im.MainBranch, Remediation: im.Remediation, AutoClose: im.AutoClose}
		}
		out.Products[name] = p
	}
	return out
}

// findMarkerApp looks up the repository-less application that holds the
// component-map fact without creating it.
func (w *Watcher) findMarkerApp() (*api.Application, bool, error) {
	apps, err := w.hub.Application.List()
	if err != nil {
		return nil, false, err
	}
	for i := range apps {
		if apps[i].Name == markerAppName {
			return &apps[i], true, nil
		}
	}
	return nil, false, nil
}

// ensureMarkerApp returns the marker application, creating it when absent.
func (w *Watcher) ensureMarkerApp() (*api.Application, error) {
	app, found, err := w.findMarkerApp()
	if err != nil {
		return nil, err
	}
	if found {
		return app, nil
	}
	if w.dryRun {
		log.Printf("DRY-RUN: would create application %s", markerAppName)
		return nil, fmt.Errorf("dry run: application %s not created", markerAppName)
	}
	app = &api.Application{Name: markerAppName}
	if err := w.hub.Application.Create(app); err != nil {
		return nil, err
	}
	log.Printf("created application %s (%d)", app.Name, app.ID)
	return app, nil
}

// readConfigMap parses the mounted ConfigMap (the seed config).
func (w *Watcher) readConfigMap() (*jira.Config, error) {
	data, err := os.ReadFile(w.imagePath)
	if err != nil {
		return nil, fmt.Errorf("image map: %w", err)
	}
	return jira.ParseConfig(data)
}

// resolveConfig returns the effective product config. The hub's
// bridge:component-map fact is authoritative; the ConfigMap only seeds it
// when the fact is absent or unusable. A valid fact is never written.
// Under DRY_RUN nothing is created or written.
func (w *Watcher) resolveConfig() (*jira.Config, error) {
	app, found, err := w.findMarkerApp()
	if err != nil {
		return nil, fmt.Errorf("find marker app: %w", err)
	}
	// Every path that reaches seeding means the fact is absent or unusable,
	// so the write must never be skipped by the lastMapJSON cache.
	if found {
		dto := &publishedConfig{}
		err := w.hub.Application.Select(app.ID).Fact.Source("bridge").Get("component-map", dto)
		var nf *binding.NotFound
		switch {
		case err == nil:
			if cfg := fromPublished(dto); len(cfg.Products) > 0 {
				return cfg, nil
			}
			log.Printf("component map fact is malformed/empty (%v); re-seeding from ConfigMap", errors.New("no products"))
		case errors.As(err, &nf):
			// absent: seed below
		default:
			if !isBadFact(err) {
				return nil, fmt.Errorf("get component map fact: %w", err)
			}
			log.Printf("component map fact is malformed/empty (%v); re-seeding from ConfigMap", err)
		}
	}
	cfg, err := w.readConfigMap()
	if err != nil {
		return nil, err
	}
	if w.dryRun {
		w.logDryRunSeed(cfg)
		return cfg, nil
	}
	if err := w.seedFact(cfg, true); err != nil {
		log.Printf("seed component map: %v", err)
	}
	return cfg, nil
}

// isBadFact reports whether a fact Get failed because the stored value was
// empty or could not be decoded (as opposed to a transport/hub error).
func isBadFact(err error) bool {
	var se *json.SyntaxError
	var te *json.UnmarshalTypeError
	var eb *binding.EmptyBody
	return errors.As(err, &se) || errors.As(err, &te) || errors.As(err, &eb)
}

func (w *Watcher) logDryRunSeed(cfg *jira.Config) {
	content, err := json.Marshal(toPublished(cfg))
	if err != nil || bytes.Equal(content, w.lastMapJSON) {
		return
	}
	log.Printf("DRY-RUN: would seed component map fact")
	w.lastMapJSON = content
}

// seedFact writes cfg as the marker app's bridge:component-map fact,
// stamped updatedBy "bridge". Unless bypassCache is set it skips the write
// when the content matches the last one written; the cache ignores
// updatedAt/updatedBy.
func (w *Watcher) seedFact(cfg *jira.Config, bypassCache bool) error {
	dto := toPublished(cfg)
	content, err := json.Marshal(dto) // zero updatedAt: stable cache key
	if err != nil {
		return err
	}
	if !bypassCache && bytes.Equal(content, w.lastMapJSON) {
		return nil
	}
	app, err := w.ensureMarkerApp()
	if err != nil {
		return err
	}
	dto.UpdatedAt = time.Now().UTC()
	dto.UpdatedBy = "bridge"
	if err := w.hub.Application.Select(app.ID).Fact.Source("bridge").Set("component-map", dto); err != nil {
		return err
	}
	w.lastMapJSON = content
	return nil
}
