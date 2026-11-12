package rhtpa

import (
	"sort"
	"strings"
)

// CVE is the merged view of one vulnerability across all advisories that
// report it as affecting an SBOM.
type CVE struct {
	ID          string
	Title       string
	Description string
	Best        Score
	Packages    map[string]SbomPackage
	Advisories  []SbomAdvisory
	// Fixed lists fixed versions by advisory identifier.
	Fixed map[string][]string
}

// AffectedCVEs merges SBOM advisories into per-CVE records. Only statuses
// reported as "affected" are considered.
func AffectedCVEs(advisories []SbomAdvisory) (cves map[string]*CVE) {
	cves = make(map[string]*CVE)
	for _, adv := range advisories {
		for _, st := range adv.Status {
			if st.Status != "affected" {
				continue
			}
			id := st.Identifier
			c, found := cves[id]
			if !found {
				c = &CVE{
					ID:       id,
					Packages: make(map[string]SbomPackage),
					Fixed:    make(map[string][]string),
				}
				cves[id] = c
			}
			if c.Title == "" {
				c.Title = st.Title
			}
			if len(st.Description) > len(c.Description) {
				c.Description = st.Description
			}
			for _, s := range st.Scores {
				if s.Value > c.Best.Value {
					c.Best = s
				}
			}
			for _, p := range st.Packages {
				c.Packages[p.PurlString()] = p
			}
			c.Fixed[adv.Identifier] = append(c.Fixed[adv.Identifier], st.FixedVersions...)
			c.Advisories = append(c.Advisories, adv)
		}
	}
	return
}

// IDs returns the sorted CVE ids.
func IDs(cves map[string]*CVE) (ids []string) {
	for id := range cves {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return
}

// IsRedHatBuild reports whether a version is a Red Hat rebuild (only
// resolvable from the Red Hat Maven repository).
func IsRedHatBuild(version string) bool {
	return strings.Contains(strings.ToLower(version), "redhat")
}

// FixedVersions returns the sorted, deduplicated union of the fixed
// versions across advisories.
func (c *CVE) FixedVersions() (versions []string) {
	seen := map[string]bool{}
	for _, list := range c.Fixed {
		for _, v := range list {
			if !seen[v] {
				seen[v] = true
				versions = append(versions, v)
			}
		}
	}
	sort.Strings(versions)
	return
}
