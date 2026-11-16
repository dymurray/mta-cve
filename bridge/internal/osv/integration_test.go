package osv

import (
	"os"

	"github.com/dymurray/mta-rhtpa-bridge/internal/finding"
	"path/filepath"
	"testing"
)

// TestAnalyzeRepo runs rgctl against a real repo when RGCTL_BIN, RGCTL_REPO
// and OSV_DIR (holding <advisory>.json) are set.
func TestAnalyzeRepo(t *testing.T) {
	bin, repo, dir := os.Getenv("RGCTL_BIN"), os.Getenv("RGCTL_REPO"), os.Getenv("OSV_DIR")
	if bin == "" || repo == "" || dir == "" {
		t.Skip("RGCTL_BIN/RGCTL_REPO/OSV_DIR not set")
	}
	r := &Rgctl{Bin: bin, Repo: repo}
	if out, err := r.Discover(); err != nil {
		t.Fatalf("discover: %v %s", err, out)
	}
	cases := []struct{ file, cve, pkg, want string }{
		{"GHSA-599f-7c49-w659.json", "CVE-2022-42889", "org.apache.commons:commons-text", "exploitable"},
		{"GHSA-mjmj-j48q-9wg2.json", "CVE-2022-1471", "org.yaml:snakeyaml", "reachable"},
		{"GHSA-j288-q9x7-2f5v.json", "CVE-2025-48924", "org.apache.commons:commons-lang3", "unknown"},
	}
	for _, c := range cases {
		doc, err := os.ReadFile(filepath.Join(dir, c.file))
		if err != nil {
			t.Fatal(err)
		}
		enriched, src, entry, err := Enrich(doc, c.cve, c.pkg)
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(t.TempDir(), "osv.json")
		_ = os.WriteFile(p, enriched, 0644)
		re, _, err := r.Analyze(p, src, entry, true, finding.EcosystemMaven)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: verdict=%s exploit=%s deps=%s vex=%s/%s adjusted=%v sites=%v paths=%v reason=%q",
			c.cve, re.Verdict, re.Exploitability, re.DepsVerdict, re.Vex.Status, re.Vex.Justification,
			re.VexAdjusted, re.CallSites, re.Paths, re.VerdictReason)
		if re.Verdict != c.want {
			t.Errorf("%s: verdict %s, want %s", c.cve, re.Verdict, c.want)
		}
	}
}
