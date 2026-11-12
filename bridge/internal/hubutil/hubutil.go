// Package hubutil holds hub-client helpers shared by the addons and the
// watcher. It must not import the addon SDK (its init requires a task pod).
package hubutil

import (
	"encoding/json"
	"log"
	"strings"

	"github.com/konveyor/tackle2-hub/shared/api"
	"github.com/konveyor/tackle2-hub/shared/binding"

	"github.com/dymurray/mta-rhtpa-bridge/internal/finding"
)

// ReplaceTags ensures the named tags exist in category and makes them the
// application's tags for the given source.
func ReplaceTags(client *binding.RichClient, appID uint, source, category, colour string, names []string) (err error) {
	cat := &api.TagCategory{Name: category, Color: colour}
	err = client.TagCategory.Ensure(cat)
	if err != nil {
		return
	}
	var ids []uint
	for _, name := range names {
		tag := &api.Tag{Name: name, Category: api.Ref{ID: cat.ID}}
		err = client.Tag.Ensure(tag)
		if err != nil {
			return
		}
		ids = append(ids, tag.ID)
	}
	err = client.Application.Select(appID).Tag.Source(source).Replace(ids)
	return
}

// Findings returns the application's CVE findings keyed by CVE id.
func Findings(client *binding.RichClient, appID uint) (findings map[string]*finding.Finding, err error) {
	facts, err := client.Application.Select(appID).Fact.Source(finding.SourceCVE).List()
	if err != nil {
		return
	}
	findings = make(map[string]*finding.Finding)
	for k, v := range facts {
		b, _ := json.Marshal(v)
		f := &finding.Finding{}
		if err := json.Unmarshal(b, f); err != nil {
			log.Printf("app %d: finding %s: unmarshal: %v", appID, k, err)
			continue
		}
		findings[k] = f
	}
	return
}

// RefreshTags derives the application's Vulnerability tags from its findings:
// one "<Severity> CVE" tag per open severity plus remediation-strategy tags.
func RefreshTags(client *binding.RichClient, appID uint) (err error) {
	findings, err := Findings(client, appID)
	if err != nil {
		return
	}
	names := map[string]bool{}
	for _, f := range findings {
		if finding.SeverityTagged(f.Status) && f.Severity != "" {
			names[strings.ToUpper(f.Severity[:1])+f.Severity[1:]+" CVE"] = true
		}
		switch f.Strategy {
		case finding.StrategyAutoBump:
			names["CVE Auto-Remediated"] = true
		case finding.StrategyAgentic:
			names["CVE Agent Remediation"] = true
		}
	}
	var list []string
	for n := range names {
		list = append(list, n)
	}
	err = ReplaceTags(client, appID, finding.KindRemediation, "Vulnerability", "#c9190b", list)
	return
}
