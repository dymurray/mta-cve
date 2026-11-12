package maven

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Pom is a pom.xml held as text so edits preserve formatting.
type Pom struct {
	Path string
	Text string
}

// LoadPom reads a pom.xml.
func LoadPom(path string) (p *Pom, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	p = &Pom{Path: path, Text: string(b)}
	return
}

// Save writes the pom.xml.
func (p *Pom) Save() error {
	return os.WriteFile(p.Path, []byte(p.Text), 0644)
}

var (
	depRe     = regexp.MustCompile(`(?s)<dependency>.*?</dependency>`)
	groupRe   = regexp.MustCompile(`<groupId>\s*([^<\s]+)\s*</groupId>`)
	artRe     = regexp.MustCompile(`<artifactId>\s*([^<\s]+)\s*</artifactId>`)
	versionRe = regexp.MustCompile(`<version>\s*([^<\s]+)\s*</version>`)
	propRe    = regexp.MustCompile(`^\$\{([^}]+)\}$`)
)

// Dependency is a declared dependency.
type Dependency struct {
	Group    string
	Artifact string
	// Version as written (may be a ${property} reference).
	Version string
	// Property is the referenced property name, if any.
	Property string
	// Managed is true when declared under dependencyManagement.
	Managed bool
	start   int
	end     int
}

// Find returns the declaration of group:artifact (a direct dependency is
// preferred over a dependencyManagement entry).
func (p *Pom) Find(group, artifact string) (d *Dependency, found bool) {
	mgmtStart, mgmtEnd := p.section("dependencyManagement")
	for _, loc := range depRe.FindAllStringIndex(p.Text, -1) {
		block := p.Text[loc[0]:loc[1]]
		g := groupRe.FindStringSubmatch(block)
		a := artRe.FindStringSubmatch(block)
		if g == nil || a == nil || g[1] != group || a[1] != artifact {
			continue
		}
		cand := &Dependency{Group: group, Artifact: artifact, start: loc[0], end: loc[1]}
		cand.Managed = loc[0] > mgmtStart && loc[1] < mgmtEnd
		if v := versionRe.FindStringSubmatch(block); v != nil {
			cand.Version = v[1]
			if m := propRe.FindStringSubmatch(v[1]); m != nil {
				cand.Property = m[1]
			}
		}
		if !cand.Managed {
			return cand, true
		}
		if d == nil {
			d, found = cand, true
		}
	}
	return
}

// SetVersion pins group:artifact to version. A property reference is
// updated in <properties>; an inline version is replaced; an undeclared
// (transitive) dependency gets a dependencyManagement override.
func (p *Pom) SetVersion(group, artifact, version string) (how string, err error) {
	d, found := p.Find(group, artifact)
	switch {
	case found && d.Property != "":
		re := regexp.MustCompile(`(<` + regexp.QuoteMeta(d.Property) + `>)\s*[^<]*\s*(</` + regexp.QuoteMeta(d.Property) + `>)`)
		if !re.MatchString(p.Text) {
			err = fmt.Errorf("property %s not defined in pom.xml", d.Property)
			return
		}
		p.Text = re.ReplaceAllString(p.Text, "${1}"+version+"${2}")
		how = fmt.Sprintf("updated property <%s> to %s", d.Property, version)
	case found && d.Version != "":
		block := p.Text[d.start:d.end]
		block = versionRe.ReplaceAllString(block, "<version>"+version+"</version>")
		p.Text = p.Text[:d.start] + block + p.Text[d.end:]
		how = fmt.Sprintf("updated %s:%s version to %s", group, artifact, version)
	default:
		err = p.addManaged(group, artifact, version)
		how = fmt.Sprintf("added dependencyManagement override %s:%s:%s", group, artifact, version)
	}
	return
}

func (p *Pom) addManaged(group, artifact, version string) (err error) {
	entry := fmt.Sprintf(
		"      <dependency>\n        <groupId>%s</groupId>\n        <artifactId>%s</artifactId>\n        <version>%s</version>\n      </dependency>\n",
		group, artifact, version)
	if start, end := p.section("dependencyManagement"); start >= 0 {
		section := p.Text[start:end]
		i := strings.Index(section, "<dependencies>")
		if i < 0 {
			err = fmt.Errorf("malformed dependencyManagement section")
			return
		}
		at := start + i + len("<dependencies>\n")
		p.Text = p.Text[:at] + entry + p.Text[at:]
		return
	}
	i := strings.Index(p.Text, "<dependencies>")
	if i < 0 {
		err = fmt.Errorf("pom.xml has no <dependencies> section")
		return
	}
	block := "<dependencyManagement>\n    <dependencies>\n" + entry + "    </dependencies>\n  </dependencyManagement>\n\n  "
	p.Text = p.Text[:i] + block + p.Text[i:]
	return
}

// section returns the [start,end) offsets of the named element, or -1.
func (p *Pom) section(name string) (start, end int) {
	start = strings.Index(p.Text, "<"+name+">")
	if start < 0 {
		return -1, -1
	}
	e := strings.Index(p.Text[start:], "</"+name+">")
	if e < 0 {
		return -1, -1
	}
	end = start + e + len("</"+name+">")
	return
}
