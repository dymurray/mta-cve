module github.com/dymurray/mta-rhtpa-bridge

go 1.25.0

// Hub SDK vendored from migtools/mta-tackle2-hub@release-0.11 (MTA 8.3.x) so
// the addons speak exactly the API of the deployed hub.
replace github.com/konveyor/tackle2-hub/shared => ./third_party/hub-shared

require (
	github.com/konveyor/tackle2-hub/shared v0.0.0-00010101000000-000000000000
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/jortel/go-utils v0.1.5 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/sirupsen/logrus v1.9.4 // indirect
	golang.org/x/sys v0.47.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)
