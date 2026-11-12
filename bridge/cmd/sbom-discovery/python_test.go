package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestLockPackages(t *testing.T) {
	uv := "version = 1\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\nsource = { editable = \".\" }\n\n[[package]]\nname = \"PyJWT\"\nversion = \"1.7.1\"\nsource = { registry = \"https://pypi.org/simple\" }\n"
	pkgs := lockPackages(uv)
	if len(pkgs) != 1 || pkgs[0] != (pyPackage{"PyJWT", "1.7.1"}) {
		t.Errorf("%v", pkgs)
	}
}

func TestReportPackages(t *testing.T) {
	report := `{"install":[{"download_info":{"url":"file:///src","dir_info":{}},"metadata":{"name":"app","version":"0.1"}},
		{"download_info":{"url":"https://files"},"metadata":{"name":"requests","version":"2.25.1"}}]}`
	pkgs, err := reportPackages([]byte(report))
	if err != nil || len(pkgs) != 1 || pkgs[0].name != "requests" {
		t.Errorf("%v %v", pkgs, err)
	}
}

func TestCycloneDX(t *testing.T) {
	doc, err := cycloneDX("demo", []pyPackage{{"PyJWT", "1.7.1"}, {"python_dateutil", "2.8.2"}, {"PyJWT", "1.7.1"}})
	if err != nil {
		t.Fatal(err)
	}
	var bom struct {
		SerialNumber string `json:"serialNumber"`
		Components   []struct {
			Purl string `json:"purl"`
		} `json:"components"`
	}
	_ = json.Unmarshal(doc, &bom)
	if len(bom.Components) != 2 || bom.Components[0].Purl != "pkg:pypi/pyjwt@1.7.1" || bom.Components[1].Purl != "pkg:pypi/python-dateutil@2.8.2" ||
		!strings.HasPrefix(bom.SerialNumber, "urn:uuid:") {
		t.Errorf("%s", doc)
	}
}
