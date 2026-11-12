// Package scope decides which applications the CVE features act on: those
// in the CVE archetype. It must not import the addon SDK (its init
// requires a task pod).
package scope

import (
	"errors"
	"fmt"
	"os"

	"github.com/konveyor/tackle2-hub/shared/api"
	"github.com/konveyor/tackle2-hub/shared/binding"
)

const (
	// EnvArchetype overrides the archetype name.
	EnvArchetype = "CVE_ARCHETYPE"
	// DefaultArchetype is the archetype used when EnvArchetype is unset.
	DefaultArchetype = "konveyor-cves"
)

// ErrNoArchetype is returned when no archetype has the requested name.
var ErrNoArchetype = errors.New("archetype not found")

// Archetype returns the configured archetype name.
func Archetype() string {
	if name := os.Getenv(EnvArchetype); name != "" {
		return name
	}
	return DefaultArchetype
}

// Member reports whether the application is in the named archetype.
func Member(app *api.Application, archetype string) bool {
	for _, r := range app.Archetypes {
		if r.Name == archetype {
			return true
		}
	}
	return false
}

// Members returns the ids of the applications in the named archetype.
func Members(client *binding.RichClient, archetype string) (ids map[uint]bool, err error) {
	list, err := client.Archetype.List()
	if err != nil {
		return
	}
	for _, a := range list {
		if a.Name != archetype {
			continue
		}
		ids = make(map[uint]bool)
		for _, r := range a.Applications {
			ids[r.ID] = true
		}
		return
	}
	err = fmt.Errorf("%w: %s", ErrNoArchetype, archetype)
	return
}
