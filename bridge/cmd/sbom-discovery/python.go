package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/konveyor/tackle2-hub/shared/addon/command"
)

// pythonInputs returns the Python dependency inputs in dir: the lock file
// (uv.lock, poetry.lock) when present, else the requirements files and
// whether pyproject.toml has a [project] table.
func pythonInputs(dir string) (lock string, reqs []string, pyproject bool) {
	for _, l := range []string{"uv.lock", "poetry.lock"} {
		if _, err := os.Stat(filepath.Join(dir, l)); err == nil {
			lock = l
			return
		}
	}
	for _, pattern := range []string{"requirements*.txt", "requirements/*.txt"} {
		matches, _ := filepath.Glob(filepath.Join(dir, pattern))
		for _, m := range matches {
			rel, _ := filepath.Rel(dir, m)
			reqs = append(reqs, rel)
		}
	}
	sort.Strings(reqs)
	if b, err := os.ReadFile(filepath.Join(dir, "pyproject.toml")); err == nil {
		pyproject = regexp.MustCompile(`(?m)^\s*\[project\]\s*$`).Match(b)
	}
	return
}

// pyPackage is a resolved Python distribution.
type pyPackage struct{ name, version string }

// pythonSBOM writes a CycloneDX SBOM of the project's resolved Python
// packages: every package of the lock file, or pip's resolution of the
// requirements files (and the project) without installing. syft only sees
// exact requirement pins and no transitive packages without a lock file.
func pythonSBOM(dir, appName string) (sbomPath, generator string, err error) {
	lock, reqs, pyproject := pythonInputs(dir)
	var pkgs []pyPackage
	switch {
	case lock != "":
		addon.Activity("Python project with %s detected; generating SBOM from the lock file.", lock)
		var b []byte
		b, err = os.ReadFile(filepath.Join(dir, lock))
		if err != nil {
			return
		}
		pkgs = lockPackages(string(b))
		generator = lock
	case len(reqs) > 0 || pyproject:
		addon.Activity("Python project detected; generating SBOM from pip's dependency resolution (%s).",
			strings.Join(append(reqs, map[bool]string{true: "pyproject.toml"}[pyproject]), " "))
		pkgs, err = pipResolve(dir, reqs, pyproject)
		if err != nil {
			return
		}
		generator = "pip-resolve"
	default:
		err = errors.New("no Python dependency inputs")
		return
	}
	if len(pkgs) == 0 {
		err = errors.New("no Python packages resolved")
		return
	}
	doc, err := cycloneDX(appName, pkgs)
	if err != nil {
		return
	}
	sbomPath = filepath.Join(os.TempDir(), "bom.json")
	err = os.WriteFile(sbomPath, doc, 0644)
	return
}

var lockBlockRe = regexp.MustCompile(`(?m)^\[\[package\]\]\s*\n((?:[^\[\n].*\n?)*)`)

var (
	lockNameRe    = regexp.MustCompile(`(?m)^name\s*=\s*"([^"]+)"`)
	lockVersionRe = regexp.MustCompile(`(?m)^version\s*=\s*"([^"]+)"`)
	lockLocalRe   = regexp.MustCompile(`(?m)^source\s*=\s*\{[^}]*\b(editable|virtual|directory|path)\s*=`)
)

// lockPackages returns the packages of a uv.lock or poetry.lock, without
// the project itself and local (editable, virtual, path) packages.
func lockPackages(lock string) (pkgs []pyPackage) {
	for _, m := range lockBlockRe.FindAllStringSubmatch(lock, -1) {
		block := m[1]
		name, version := lockNameRe.FindStringSubmatch(block), lockVersionRe.FindStringSubmatch(block)
		if name == nil || version == nil || lockLocalRe.MatchString(block) {
			continue
		}
		pkgs = append(pkgs, pyPackage{name: name[1], version: version[1]})
	}
	return
}

// pipResolve resolves the requirements files (and the project) with
// `pip install --dry-run --report` and returns the packages pip would
// install, without the project itself.
func pipResolve(dir string, reqs []string, pyproject bool) (pkgs []pyPackage, err error) {
	report := filepath.Join(os.TempDir(), "pip-report.json")
	cmd := command.New("python3")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "PIP_DISABLE_PIP_VERSION_CHECK=1", "PIP_NO_INPUT=1", "PYTHONDONTWRITEBYTECODE=1")
	cmd.Options.Add("-m", "pip", "install", "--dry-run", "--ignore-installed", "--quiet", "--report", report)
	for _, r := range reqs {
		cmd.Options.Add("-r", r)
	}
	if pyproject {
		cmd.Options.Add(".")
	}
	err = cmd.Run()
	if err != nil {
		return
	}
	b, err := os.ReadFile(report)
	if err != nil {
		return
	}
	return reportPackages(b)
}

// reportPackages parses a pip installation report.
func reportPackages(report []byte) (pkgs []pyPackage, err error) {
	var r struct {
		Install []struct {
			DownloadInfo struct {
				DirInfo json.RawMessage `json:"dir_info"`
			} `json:"download_info"`
			Metadata struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"metadata"`
		} `json:"install"`
	}
	err = json.Unmarshal(report, &r)
	if err != nil {
		return
	}
	for _, i := range r.Install {
		if len(i.DownloadInfo.DirInfo) > 0 { // the local project
			continue
		}
		pkgs = append(pkgs, pyPackage{name: i.Metadata.Name, version: i.Metadata.Version})
	}
	return
}

// cycloneDX returns a CycloneDX 1.5 JSON document listing pkgs as
// pkg:pypi components of the application.
func cycloneDX(appName string, pkgs []pyPackage) ([]byte, error) {
	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].name < pkgs[j].name })
	var components []map[string]any
	seen := map[string]bool{}
	for _, p := range pkgs {
		purl := fmt.Sprintf("pkg:pypi/%s@%s", pypiName(p.name), p.version)
		if seen[purl] {
			continue
		}
		seen[purl] = true
		components = append(components, map[string]any{
			"type": "library", "bom-ref": purl, "name": p.name, "version": p.version, "purl": purl,
		})
	}
	return json.MarshalIndent(map[string]any{
		"bomFormat":    "CycloneDX",
		"specVersion":  "1.5",
		"serialNumber": "urn:uuid:" + uuid4(),
		"version":      1,
		"metadata": map[string]any{
			"tools":     map[string]any{"components": []map[string]any{{"type": "application", "name": "mta-sbom-discovery"}}},
			"component": map[string]any{"type": "application", "bom-ref": "app", "name": appName},
		},
		"components": components,
	}, "", "  ")
}

// pypiName is the purl name of a Python project: PEP 503 normalized.
func pypiName(name string) string {
	return strings.ToLower(regexp.MustCompile(`[-_.]+`).ReplaceAllString(name, "-"))
}

func uuid4() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
