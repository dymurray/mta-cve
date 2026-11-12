package jira

import (
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestDeployedComponentMapParses guards the shipped ConfigMap: its
// image-map.yaml value must parse as the per-product config.
func TestDeployedComponentMapParses(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/mta/51-component-map.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var cm struct {
		Data map[string]string `yaml:"data"`
	}
	if err := yaml.Unmarshal(raw, &cm); err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseConfig([]byte(cm.Data["image-map.yaml"]))
	if err != nil {
		t.Fatal(err)
	}
	p, ok := cfg.Products["mta"]
	if !ok {
		t.Fatalf("mta product missing: %+v", cfg.Products)
	}
	if p.JiraProject != "MTA" {
		t.Errorf("jiraProject = %q, want MTA", p.JiraProject)
	}
	if _, ok := p.Streams["mta-8.2"]; !ok {
		t.Errorf("stream mta-8.2 missing: %+v", p.Streams)
	}
	if len(p.Images) < 1 {
		t.Error("mta product has no images")
	}
	if c, ok := cfg.Products["cnv"]; !ok || c.JiraProject != "CNV" {
		t.Errorf("cnv product = %+v, want jiraProject CNV", c)
	}
}
