package main

import (
	"flag"
	"fmt"

	"github.com/dymurray/mta-rhtpa-bridge/internal/finding"
	"github.com/konveyor/tackle2-hub/shared/binding"
)

// resetFinding re-arms a finding for the next nightly refresh, whatever its
// status.
func resetFinding(f *finding.Finding) {
	f.Status = finding.StatusFailed
	f.Attempts = 0
	f.Message = "Reset by an operator; will retry after the next nightly refresh."
}

func reset(hub *binding.RichClient, args []string) (err error) {
	fs := flag.NewFlagSet("reset", flag.ContinueOnError)
	appName := fs.String("app", "", "application name")
	cve := fs.String("cve", "", "CVE id")
	err = fs.Parse(args)
	if err != nil {
		return
	}
	if *appName == "" || *cve == "" {
		err = fmt.Errorf("usage: nightly-refresh reset --app <name> --cve <CVE-ID>")
		return
	}
	apps, err := hub.Application.List()
	if err != nil {
		return
	}
	for i := range apps {
		if apps[i].Name != *appName {
			continue
		}
		facts := hub.Application.Select(apps[i].ID).Fact.Source(finding.SourceCVE)
		f := &finding.Finding{}
		err = facts.Get(*cve, f)
		if err != nil {
			err = fmt.Errorf("app %s: finding %s: %w", *appName, *cve, err)
			return
		}
		resetFinding(f)
		err = facts.Set(*cve, f)
		if err == nil {
			fmt.Printf("app %s: %s reset\n", *appName, *cve)
		}
		return
	}
	err = fmt.Errorf("application %q not found", *appName)
	return
}
