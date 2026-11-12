// sbom-discovery is an MTA discovery addon: it generates a CycloneDX SBOM for
// the application's repository and imports it into Red Hat Trusted Profile
// Analyzer, recording the RHTPA SBOM id as the application fact rhtpa:sbom.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/dymurray/mta-rhtpa-bridge/internal/addonutil"
	"github.com/dymurray/mta-rhtpa-bridge/internal/finding"
	"github.com/dymurray/mta-rhtpa-bridge/internal/hubutil"
	"github.com/dymurray/mta-rhtpa-bridge/internal/rhtpa"
	"github.com/dymurray/mta-rhtpa-bridge/internal/scope"
	hub "github.com/konveyor/tackle2-hub/shared/addon"
	"github.com/konveyor/tackle2-hub/shared/addon/command"
	"github.com/konveyor/tackle2-hub/shared/api"
)

var addon = hub.Addon

// CycloneDX maven plugin used for Maven projects.
const cyclonedxPlugin = "org.cyclonedx:cyclonedx-maven-plugin:2.9.1:makeAggregateBom"

func main() {
	addon.Run(func() (err error) {
		addon.Activity("Fetching application.")
		app, err := addon.Task.Application()
		if err != nil {
			return
		}
		if !scope.Member(app, scope.Archetype()) {
			addon.Activity("Application is not in the %s archetype; skipping.", scope.Archetype())
			return
		}
		d := &Data{}
		err = addon.DataWith(d)
		if err != nil {
			return
		}
		if app.Repository == nil || app.Repository.URL == "" {
			addon.Activity("Application has no repository; nothing to do.")
			return
		}
		client, err := rhtpa.FromEnv()
		if err != nil {
			return
		}
		addon.Total(4)
		srcDir, _, err := addonutil.FetchRepository(app)
		if err != nil {
			return
		}
		addon.Increment()
		commit, cErr := headCommit(srcDir)
		if cErr != nil {
			addon.Activity("Could not determine source commit: %s", cErr)
		}
		sbomPath, generator, err := generate(srcDir, app.Name)
		if err != nil {
			return
		}
		addon.Increment()
		doc, err := os.ReadFile(sbomPath)
		if err != nil {
			return
		}
		if generator == "syft" {
			doc, err = cleanSyft(doc, app.Name)
			if err != nil {
				return
			}
			err = os.WriteFile(sbomPath, doc, 0644)
			if err != nil {
				return
			}
		}
		packages := countComponents(doc)
		f, err := addon.File.Put(sbomPath)
		if err == nil {
			addon.Attach(f)
		}
		addon.Activity("Importing SBOM (%d components) into RHTPA.", packages)
		facts := addon.Application.Select(app.ID).Fact.Source(finding.SourceRHTPA)
		previous := &finding.SBOM{}
		_ = facts.Get(finding.KeySBOM, previous)
		result, err := client.UploadSBOM(doc, map[string]string{
			"source":     "mta",
			"mta-app":    app.Name,
			"mta-app-id": fmt.Sprint(app.ID),
		})
		if err != nil {
			return
		}
		addon.Activity("RHTPA SBOM id: %s", result.ID)
		addon.Increment()
		sbom := finding.SBOM{
			ID:         result.ID,
			DocumentID: result.DocumentID,
			Name:       app.Name,
			Packages:   packages,
			Purls:      sbomPurls(doc),
			Generator:  generator,
			Uploaded:   time.Now().UTC(),
			ConsoleURL: client.SbomURL(result.ID),
			TaskID:     addonutil.TaskID(),
			Commit:     commit,
		}
		if d.Nightly {
			sbom.NightlyAt = time.Now().UTC()
		}
		err = facts.Set(finding.KeySBOM, sbom)
		if err != nil {
			return
		}
		if previous.ID != "" && previous.ID != result.ID {
			addon.Activity("Replacing previous SBOM %s.", previous.ID)
			if dErr := client.DeleteSBOM(previous.ID); dErr != nil {
				addon.Activity("Could not delete previous SBOM: %s", dErr)
			}
		}
		err = hubutil.ReplaceTags(addon.Client(), app.ID, "sbom-discovery", "RHTPA", "#ee0000", []string{"SBOM Imported"})
		if err != nil {
			return
		}
		addon.Increment()
		checkPullRequests(app)
		addon.Result(api.Map{"sbomId": result.ID, "packages": packages, "consoleUrl": sbom.ConsoleURL})
		return
	})
}

// Data is the task data.
type Data struct {
	// Nightly marks a run started by the nightly refresh.
	Nightly bool `json:"nightly"`
}

// headCommit returns the checked-out revision of the source directory.
func headCommit(srcDir string) (commit string, err error) {
	cmd := command.New("/usr/bin/git")
	cmd.Dir = srcDir
	cmd.Options.Add("rev-parse", "HEAD")
	err = cmd.Run()
	if err != nil {
		return
	}
	commit = strings.TrimSpace(string(cmd.Output()))
	return
}

// generate builds a CycloneDX JSON SBOM for the repository.
func generate(srcDir, appName string) (sbomPath, generator string, err error) {
	if _, sErr := os.Stat(filepath.Join(srcDir, "pom.xml")); sErr == nil {
		addon.Activity("Maven project detected; generating SBOM with the CycloneDX Maven plugin.")
		cmd := command.New("/usr/bin/mvn")
		cmd.Dir = srcDir
		cmd.Options.Add("-B", "-ntp")
		for _, opt := range addonutil.MavenRepoOption() {
			cmd.Options.Add(opt)
		}
		cmd.Options.Add(
			cyclonedxPlugin,
			"-DoutputFormat=json",
			"-DoutputName=bom",
			"-DincludeTestScope=false")
		err = cmd.Run()
		if err != nil {
			return
		}
		sbomPath = filepath.Join(srcDir, "target", "bom.json")
		generator = "cyclonedx-maven-plugin"
		return
	}
	_, gErr := os.Stat(filepath.Join(srcDir, "go.mod"))
	if lock, reqs, pyproject := pythonInputs(srcDir); gErr != nil && (lock != "" || len(reqs) > 0 || pyproject) {
		sbomPath, generator, err = pythonSBOM(srcDir, appName)
		if err == nil {
			return
		}
		addon.Activity("Python SBOM generation failed (%s); falling back to syft.", err)
		err = nil
	}
	if _, sErr := os.Stat("/usr/local/bin/syft"); sErr == nil {
		if gErr == nil {
			addon.Activity("Go module detected; generating SBOM with syft (go.mod / go.sum).")
		} else {
			addon.Activity("Generating SBOM with syft.")
		}
		sbomPath = filepath.Join(os.TempDir(), "bom.json")
		cmd := command.New("/usr/local/bin/syft")
		cmd.Dir = srcDir
		cmd.Options.Add("dir:.", "-o", "cyclonedx-json="+sbomPath)
		err = cmd.Run()
		generator = "syft"
		return
	}
	err = errors.New("unsupported project: no pom.xml and syft is unavailable")
	return
}

// cleanSyft normalizes a syft CycloneDX document for RHTPA: names the root
// component after the application, drops duplicate components (syft reports
// a Go module once per cataloger) and the Go stdlib entry (syft infers it
// from the scanning environment, not the application's toolchain), and
// prunes dependency references to removed components.
func cleanSyft(doc []byte, appName string) (out []byte, err error) {
	var bom map[string]any
	err = json.Unmarshal(doc, &bom)
	if err != nil {
		return
	}
	if md, ok := bom["metadata"].(map[string]any); ok {
		if c, ok := md["component"].(map[string]any); ok {
			if name, _ := c["name"].(string); name == "" || name == "." || strings.HasPrefix(name, "/") {
				c["name"] = appName
			}
		}
	}
	removed := map[string]bool{}
	seen := map[string]bool{}
	var kept []any
	components, _ := bom["components"].([]any)
	for _, c := range components {
		m, _ := c.(map[string]any)
		purl, _ := m["purl"].(string)
		if fixed := goVersionPurl(goMajorPurl(purl)); fixed != purl {
			m["purl"] = fixed
			purl = fixed
			if v, ok := m["version"].(string); ok {
				m["version"] = strings.TrimPrefix(v, "v")
			}
		}
		ref, _ := m["bom-ref"].(string)
		if (purl != "" && seen[purl]) || strings.HasPrefix(purl, "pkg:golang/stdlib@") {
			removed[ref] = true
			continue
		}
		seen[purl] = true
		kept = append(kept, c)
	}
	bom["components"] = kept
	if deps, ok := bom["dependencies"].([]any); ok {
		var keptDeps []any
		for _, d := range deps {
			m, _ := d.(map[string]any)
			if ref, _ := m["ref"].(string); removed[ref] {
				continue
			}
			if on, ok := m["dependsOn"].([]any); ok {
				var filtered []any
				for _, r := range on {
					if s, _ := r.(string); !removed[s] {
						filtered = append(filtered, r)
					}
				}
				m["dependsOn"] = filtered
			}
			keptDeps = append(keptDeps, d)
		}
		bom["dependencies"] = keptDeps
	}
	out, err = json.MarshalIndent(bom, "", "  ")
	return
}

var goMajorSubpathRe = regexp.MustCompile(`^(pkg:golang/[^@?#]+)@([^?#]+)(\?[^#]*)?#(v\d+)$`)

// goMajorPurl moves a Go major-version suffix from the purl subpath into the
// module name: syft writes github.com/x/y/v4 as pkg:golang/github.com/x/y@v4.5.0#v4,
// but advisories (and RHTPA matching) use pkg:golang/github.com/x/y/v4@v4.5.0.
func goMajorPurl(purl string) string {
	m := goMajorSubpathRe.FindStringSubmatch(purl)
	if m == nil {
		return purl
	}
	return m[1] + "/" + m[4] + "@" + m[2] + m[3]
}

var goVersionRe = regexp.MustCompile(`^(pkg:golang/[^@?#]+)@v(\d[^?#]*)(.*)$`)

// goVersionPurl drops the "v" from Go module purl versions. RHTPA compares
// OSV SEMVER ranges (used by the Go vulnerability database) with strict
// semver, which rejects "v0.57.0"; without the prefix both SEMVER and
// ECOSYSTEM (GitHub) ranges match. The addon restores the prefix for go get.
func goVersionPurl(purl string) string {
	return goVersionRe.ReplaceAllString(purl, "${1}@${2}${3}")
}

// sbomPurls collects the deduplicated, Go-normalized purls of a CycloneDX
// (components) or SPDX-style (packages) document, in document order.
func sbomPurls(doc []byte) []string {
	var bom struct {
		Components []struct {
			Purl string `json:"purl"`
		} `json:"components"`
		Packages []struct {
			Purl string `json:"purl"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(doc, &bom); err != nil {
		log.Printf("sbom purls: unmarshal SBOM document: %v", err)
		return nil
	}
	var purls []string
	seen := map[string]bool{}
	add := func(purl string) {
		purl = goVersionPurl(goMajorPurl(purl))
		if purl == "" || seen[purl] {
			return
		}
		seen[purl] = true
		purls = append(purls, purl)
	}
	for _, c := range bom.Components {
		add(c.Purl)
	}
	for _, p := range bom.Packages {
		add(p.Purl)
	}
	return purls
}

func countComponents(doc []byte) int {
	var bom struct {
		Components []json.RawMessage `json:"components"`
		Packages   []json.RawMessage `json:"packages"`
	}
	if err := json.Unmarshal(doc, &bom); err != nil {
		return 0
	}
	return len(bom.Components) + len(bom.Packages)
}

func init() {
	// mvn resolves ~ from HOME; keep it inside the writable addon home.
	if home := os.Getenv("HOME"); home == "" || strings.HasPrefix(home, "/root") {
		_ = os.Setenv("HOME", "/addon")
	}
}
