// jira-watcher bridges JIRA and MTA: prodsec CVE tickets (found by their
// pscomponent label, which names the affected product image) are mapped to
// source repositories, ensured as MTA applications, and dispatched through
// the same cve-remediation pipeline the RHTPA watcher drives. Every
// finding state change is commented back on the ticket; not-affected
// tickets can be closed automatically.
//
// The image -> repo mapping lives in a ConfigMap (mounted file, re-read
// every poll). All state lives in hub facts and JIRA — the watcher keeps
// nothing beyond the current poll's dedup set.
package main

import (
	"log"
	"os"
	"strconv"
	"time"

	"github.com/dymurray/mta-rhtpa-bridge/internal/jira"
	"github.com/konveyor/tackle2-hub/shared/binding"
	"github.com/konveyor/tackle2-hub/shared/binding/auth"
)

// Watcher state.
type Watcher struct {
	hub  *binding.RichClient
	jira *jira.Client
	// imagePath is the mounted cve-component-map file.
	imagePath string
	// cfg is the product config, re-read every poll.
	cfg *jira.Config
	// jqlPrefix is an extra AND-clause applied to every product search.
	jqlPrefix string
	// uiURL links tickets back to the MTA UI.
	uiURL string
	// closeTransition names the JIRA transition for auto-close ("" = off).
	closeTransition string
	// prTransition names the JIRA transition applied when a finding's
	// remediation pull request opens (prodsec "POST"; "" = off).
	prTransition string
	// tagCategory/tagName add created applications to the CVE archetype.
	tagCategory string
	tagName     string
	// noted remembers one-off ticket comments (unmapped, no CVE) so they
	// are not repeated every poll.
	noted map[string]bool
	// accountIDs caches owner email -> JIRA accountId lookups.
	accountIDs map[string]string
	// dryRun logs decisions without writing to the hub or JIRA.
	dryRun bool
	// lastMapJSON caches the last published component map (sans
	// updatedAt) so unchanged maps are not rewritten.
	lastMapJSON []byte
}

func main() {
	hubURL := os.Getenv("HUB_BASE_URL")
	token := os.Getenv("HUB_BRIDGE_TOKEN")
	jiraURL := os.Getenv("JIRA_URL")
	email := os.Getenv("JIRA_EMAIL")
	jiraToken := os.Getenv("JIRA_TOKEN")
	if hubURL == "" || token == "" || jiraURL == "" || email == "" || jiraToken == "" {
		log.Fatal("HUB_BASE_URL, HUB_BRIDGE_TOKEN, JIRA_URL, JIRA_EMAIL and JIRA_TOKEN are required")
	}
	interval, err := time.ParseDuration(envOr("JIRA_POLL", "60s"))
	if err != nil {
		log.Fatal(err)
	}
	dryRun, err := strconv.ParseBool(envOr("DRY_RUN", "false"))
	if err != nil {
		log.Fatalf("DRY_RUN: %v", err)
	}
	hub := binding.New(hubURL)
	hub.Client.Use(auth.NewBearer(token))
	w := &Watcher{
		hub:             hub,
		jira:            jira.New(jiraURL, email, jiraToken),
		imagePath:       envOr("IMAGE_MAP_PATH", "/etc/jira-watch/image-map.yaml"),
		jqlPrefix:       os.Getenv("JIRA_JQL_PREFIX"),
		uiURL:           os.Getenv("MTA_UI_URL"),
		closeTransition: os.Getenv("JIRA_AUTOCLOSE_TRANSITION"),
		prTransition:    os.Getenv("JIRA_PR_TRANSITION"),
		tagCategory:     envOr("JIRA_TAG_CATEGORY", "Security"),
		tagName:         envOr("JIRA_TAG_NAME", "cve-remediation"),
		noted:           map[string]bool{},
		accountIDs:      map[string]string{},
		dryRun:          dryRun,
	}
	if dryRun {
		log.Printf("DRY_RUN: logging decisions without writing to the hub or JIRA")
	}
	log.Printf("watching %s (extra filter %q) every %s", jiraURL, w.jqlPrefix, interval)
	for {
		if err := w.poll(); err != nil {
			log.Printf("poll: %v", err)
		}
		time.Sleep(interval)
	}
}

func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}
