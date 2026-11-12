// Package maven contains the small amount of Maven knowledge the remediator
// needs: version ordering (also used for Go module and PEP 440 Python
// versions) and pom.xml dependency edits.
package maven

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var numRe = regexp.MustCompile(`\d+`)

// Major returns the leading numeric segment of a version ("1.33" -> 1).
func Major(v string) int {
	m := numRe.FindString(v)
	n, _ := strconv.Atoi(m)
	return n
}

// Compare orders Maven versions by their numeric segments, then by
// qualifier (a release sorts after any qualifier such as -rc1/-SNAPSHOT).
// Returns -1, 0 or 1.
func Compare(a, b string) int {
	na, qa := split(a)
	nb, qb := split(b)
	for i := 0; i < len(na) || i < len(nb); i++ {
		var x, y int
		if i < len(na) {
			x = na[i]
		}
		if i < len(nb) {
			y = nb[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	ra, rb := rank(qa), rank(qb)
	switch {
	case ra != rb && ra < rb:
		return -1
	case ra != rb:
		return 1
	case qa == qb:
		return 0
	case qa < qb:
		return -1
	default:
		return 1
	}
}

// rank orders qualifiers: development (-2) < pre-release (-1) < release
// (0) < post-release (1). PEP 440 pre-releases (a1 < b1 < rc1) order by
// their text.
func rank(q string) int {
	switch {
	case q == "" || q == "final" || q == "ga" || q == "release":
		return 0
	case strings.HasPrefix(q, "sp") || strings.Contains(q, "redhat") || strings.HasPrefix(q, "post"):
		return 1
	case strings.HasPrefix(q, "dev"):
		return -2
	default:
		return -1
	}
}

func split(v string) (nums []int, qualifier string) {
	v = strings.TrimSpace(v)
	// Go module versions: "v1.2.3", "v3.2.2+incompatible" (build metadata
	// does not affect ordering).
	v = strings.TrimPrefix(v, "v")
	if i := strings.Index(v, "+"); i >= 0 {
		v = v[:i]
	}
	cut := len(v)
	for i, r := range v {
		if r != '.' && (r < '0' || r > '9') {
			cut = i
			break
		}
	}
	for _, p := range strings.Split(strings.Trim(v[:cut], "."), ".") {
		if p == "" {
			continue
		}
		n, _ := strconv.Atoi(p)
		nums = append(nums, n)
	}
	qualifier = strings.ToLower(strings.TrimLeft(v[cut:], ".-_"))
	return
}

// LowestFixed returns the lowest candidate greater than current, or "".
func LowestFixed(current string, candidates []string) (best string) {
	for _, c := range candidates {
		if Compare(c, current) <= 0 {
			continue
		}
		if best == "" || Compare(c, best) < 0 {
			best = c
		}
	}
	return
}

// CoveringFix returns the lowest candidate above current that fixes every
// vulnerability, where fixed[i] lists the fixed versions of vulnerability i
// (one per maintained release line, e.g. 1.10.1 and 2.0.3). When no
// candidate fixes them all it returns the one fixing the most (the lowest on
// a tie). covered[i] reports whether version fixes vulnerability i;
// vulnerabilities without fixed versions are never covered.
func CoveringFix(current string, fixed [][]string) (version string, covered []bool) {
	var candidates []string
	seen := map[string]bool{}
	for _, list := range fixed {
		for _, v := range list {
			if !seen[v] && Compare(v, current) > 0 {
				seen[v] = true
				candidates = append(candidates, v)
			}
		}
	}
	sort.Slice(candidates, func(i, j int) bool { return Compare(candidates[i], candidates[j]) < 0 })
	best := -1
	for _, v := range candidates {
		n := 0
		for _, list := range fixed {
			if Fixes(v, list) {
				n++
			}
		}
		if n > best {
			best, version = n, v
		}
		if n == len(fixed) {
			break
		}
	}
	covered = make([]bool, len(fixed))
	for i, list := range fixed {
		covered[i] = version != "" && Fixes(version, list)
	}
	return
}

// Fixes reports whether version is outside the affected range described by
// the fixed versions: some fixed version is at or below it, and no fixed
// version above it is on its release line (same major.minor). For fixed
// versions 1.10.1 and 2.0.3, 1.10.4 and 2.1.0 are fixed; 2.0.1 is not.
func Fixes(version string, fixed []string) bool {
	below := false
	for _, f := range fixed {
		if Compare(f, version) <= 0 {
			below = true
		} else if line(f) == line(version) {
			return false
		}
	}
	return below
}

// line returns the major.minor release line of a version.
func line(v string) [2]int {
	nums, _ := split(v)
	var l [2]int
	copy(l[:], nums)
	return l
}
