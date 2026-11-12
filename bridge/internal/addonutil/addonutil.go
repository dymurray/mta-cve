// Package addonutil holds helpers for code running inside an addon pod.
package addonutil

import (
	"errors"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	hub "github.com/konveyor/tackle2-hub/shared/addon"
	"github.com/konveyor/tackle2-hub/shared/addon/scm"
	"github.com/konveyor/tackle2-hub/shared/api"
)

var addon = hub.Addon

// TaskID returns the running task id.
func TaskID() uint {
	n, _ := strconv.ParseUint(os.Getenv(hub.EnvTask), 10, 64)
	return uint(n)
}

// FetchRepository clones the application repository using its source
// identity and returns the project directory (honoring repository.path).
func FetchRepository(app *api.Application) (srcDir string, r scm.SCM, err error) {
	srcDir, r, _, err = FetchRepositoryWithIdentity(app)
	return
}

// SourceIdentity returns the application's decrypted source identity.
func SourceIdentity(app *api.Application) (identity *api.Identity, err error) {
	identity, _, err = addon.Application.Select(app.ID).Identity.
		Decrypted().
		Search().
		Direct("source").
		Indirect("source").
		Find()
	return
}

// FetchRepositoryWithIdentity is FetchRepository that also returns the
// source identity used (nil when the repository is public).
func FetchRepositoryWithIdentity(app *api.Application) (srcDir string, r scm.SCM, identity *api.Identity, err error) {
	if app.Repository == nil || app.Repository.URL == "" {
		err = errors.New("application repository not defined")
		return
	}
	identity, err = SourceIdentity(app)
	if err != nil {
		return
	}
	wd, _ := os.Getwd()
	dir := filepath.Join(wd, "source", strings.TrimSuffix(path.Base(app.Repository.URL), ".git"))
	addon.Activity("Fetching %s", app.Repository.URL)
	r, err = scm.New(dir, *app.Repository, identity)
	if err != nil {
		return
	}
	err = r.Fetch()
	if err != nil {
		return
	}
	srcDir = filepath.Join(dir, app.Repository.Path)
	return
}

// MavenRepoOption places the Maven local repository on the shared addon
// cache volume when available so dependencies are downloaded once.
func MavenRepoOption() []string {
	cache := os.Getenv(hub.EnvCacheDir)
	if cache == "" {
		return nil
	}
	if fi, err := os.Stat(cache); err != nil || !fi.IsDir() {
		return nil
	}
	return []string{"-Dmaven.repo.local=" + filepath.Join(cache, "m2")}
}

// MavenRepoDir returns the effective Maven local repository directory.
func MavenRepoDir() string {
	for _, opt := range MavenRepoOption() {
		return strings.TrimPrefix(opt, "-Dmaven.repo.local=")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".m2", "repository")
}
