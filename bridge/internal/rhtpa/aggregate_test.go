package rhtpa

import (
	"strings"
	"testing"
)

func TestFixedVersions(t *testing.T) {
	c := &CVE{Fixed: map[string][]string{"GHSA-a": {"1.10.0", "1.9.1"}, "CVE-x": {"1.10.0"}}}
	got := c.FixedVersions()
	if strings.Join(got, ",") != "1.10.0,1.9.1" {
		t.Errorf("%v", got)
	}
}
