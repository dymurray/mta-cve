package maven

import (
	"reflect"
	"strings"
	"testing"
)

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.9", "1.10.0", -1},
		{"1.33", "2.0", -1},
		{"2.0", "2.0.0", 0},
		{"1.10.0", "1.10.0-rc1", 1},
		{"1.33.0.SP1-redhat-00001", "1.33", 0 + 1},
		{"v0.3.7", "0.3.8", -1},
		{"v3.2.2+incompatible", "3.2.2", 0},
		{"v5.2.2", "v5.0.0-rc.1", 1},
	}
	for _, c := range cases {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
	if got := LowestFixed("1.33", []string{"2.2", "2.0", "1.32"}); got != "2.0" {
		t.Errorf("LowestFixed=%q", got)
	}
	if Major("1.33") != 1 || Major("2.0") != 2 {
		t.Error("Major")
	}
}

const pom = `<project>
  <properties>
    <commons-text.version>1.9</commons-text.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-text</artifactId>
      <version>${commons-text.version}</version>
    </dependency>
    <dependency>
      <groupId>org.yaml</groupId>
      <artifactId>snakeyaml</artifactId>
      <version>1.33</version>
    </dependency>
  </dependencies>
</project>
`

func TestSetVersion(t *testing.T) {
	p := &Pom{Text: pom}
	if _, err := p.SetVersion("org.apache.commons", "commons-text", "1.10.0"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p.Text, "<commons-text.version>1.10.0</commons-text.version>") {
		t.Errorf("property not updated:\n%s", p.Text)
	}
	if _, err := p.SetVersion("org.yaml", "snakeyaml", "2.0"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p.Text, "<version>2.0</version>") {
		t.Errorf("inline version not updated:\n%s", p.Text)
	}
	if _, err := p.SetVersion("org.apache.commons", "commons-lang3", "3.18.0"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p.Text, "<dependencyManagement>") || !strings.Contains(p.Text, "<artifactId>commons-lang3</artifactId>") {
		t.Errorf("managed override missing:\n%s", p.Text)
	}
	d, found := p.Find("org.apache.commons", "commons-lang3")
	if !found || !d.Managed || d.Version != "3.18.0" {
		t.Errorf("Find managed: %+v %v", d, found)
	}
}

func TestCoveringFix(t *testing.T) {
	tests := []struct {
		name    string
		current string
		fixed   [][]string
		want    string
		covered []bool
	}{
		{"single", "1.9", [][]string{{"1.10.0"}}, "1.10.0", []bool{true}},
		{"newest of the needed fixes", "1.9", [][]string{{"1.10.0"}, {"1.11.0"}, {"1.10.0"}}, "1.11.0", []bool{true, true, true}},
		{"release lines", "1.9", [][]string{{"1.10.1", "2.0.3"}, {"2.0.1"}}, "2.0.3", []bool{true, true}},
		{"stays on line", "1.9", [][]string{{"1.10.1", "2.0.3"}, {"1.10.2", "2.0.4"}}, "1.10.2", []bool{true, true}},
		{"no fix for one", "1.9", [][]string{{"1.10.0"}, nil}, "1.10.0", []bool{true, false}},
		{"none", "1.9", [][]string{nil, nil}, "", []bool{false, false}},
		{"already above", "2.0", [][]string{{"1.10.0"}}, "", []bool{false}},
		{"go", "v0.3.7", [][]string{{"v0.3.8"}, {"v0.3.9", "v0.4.1"}}, "v0.3.9", []bool{true, true}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, covered := CoveringFix(tc.current, tc.fixed)
			if got != tc.want || !reflect.DeepEqual(covered, tc.covered) {
				t.Errorf("CoveringFix() = %q %v, want %q %v", got, covered, tc.want, tc.covered)
			}
		})
	}
}

func TestFixes(t *testing.T) {
	fixed := []string{"1.10.1", "2.0.3"}
	for v, want := range map[string]bool{"1.9": false, "1.10.1": true, "1.10.4": true, "2.0.1": false, "2.0.3": true, "2.1.0": true} {
		if got := Fixes(v, fixed); got != want {
			t.Errorf("Fixes(%s) = %v, want %v", v, got, want)
		}
	}
}

func TestComparePEP440(t *testing.T) {
	for _, c := range [][2]string{{"2.0.dev1", "2.0a1"}, {"2.0a1", "2.0b1"}, {"2.0b1", "2.0rc1"}, {"2.0rc1", "2.0"}, {"2.0", "2.0.post1"}} {
		if Compare(c[0], c[1]) >= 0 {
			t.Errorf("%s should sort before %s", c[0], c[1])
		}
	}
}
