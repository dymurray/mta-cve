package scope

import (
	"testing"

	"github.com/konveyor/tackle2-hub/shared/api"
)

func TestArchetypeDefault(t *testing.T) {
	t.Setenv(EnvArchetype, "")
	if Archetype() != "konveyor-cves" {
		t.Error(Archetype())
	}
	t.Setenv(EnvArchetype, "other")
	if Archetype() != "other" {
		t.Error(Archetype())
	}
}

func TestMember(t *testing.T) {
	app := &api.Application{Archetypes: []api.Ref{{ID: 2, Name: "konveyor-cves"}}}
	if !Member(app, "konveyor-cves") {
		t.Error("member")
	}
	if Member(&api.Application{}, "konveyor-cves") {
		t.Error("non-member")
	}
}
