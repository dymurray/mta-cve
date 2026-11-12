// nightly-refresh runs as a Kubernetes CronJob (not an addon). For each
// application in the CVE archetype it asks the remote repository for its
// head commit. When the commit is unchanged since the application's SBOM was
// generated, the SBOM is kept and only marked as seen by this nightly run;
// otherwise it submits an sbom-discovery task with {"nightly": true}.
//
// "nightly-refresh reset --app <name> --cve <CVE-ID>" re-arms a finding.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/dymurray/mta-rhtpa-bridge/internal/finding"
	"github.com/dymurray/mta-rhtpa-bridge/internal/scope"
	"github.com/konveyor/tackle2-hub/shared/api"
	"github.com/konveyor/tackle2-hub/shared/binding"
	"github.com/konveyor/tackle2-hub/shared/binding/auth"
)

func main() {
	hubURL := os.Getenv("HUB_BASE_URL")
	token := os.Getenv("HUB_BRIDGE_TOKEN")
	if hubURL == "" || token == "" {
		log.Fatal("HUB_BASE_URL and HUB_BRIDGE_TOKEN are required")
	}
	hub := binding.New(hubURL)
	hub.Client.Use(auth.NewBearer(token))
	if len(os.Args) > 1 && os.Args[1] == "reset" {
		if err := reset(hub, os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		return
	}
	created, skipped, err := refresh(hub, scope.Archetype(), gitLsRemote)
	log.Printf("created %d task(s), skipped %d", created, skipped)
	if err != nil {
		log.Fatal(err)
	}
}

// parseLsRemote returns the SHA on the first line of git ls-remote output.
func parseLsRemote(out string) string {
	fields := strings.Fields(strings.SplitN(out, "\n", 2)[0])
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

// skip reports whether the repository head matches the commit the SBOM was
// generated from.
func skip(sbom finding.SBOM, head string) bool {
	return head != "" && head == sbom.Commit
}

// lsRemoteRef returns the fully qualified ref for a branch (HEAD when
// empty), so ls-remote cannot match a same-named tag or a ref under
// another namespace (refs/heads/x/main) first.
func lsRemoteRef(branch string) string {
	if branch == "" {
		return "HEAD"
	}
	return "refs/heads/" + branch
}

// gitLsRemote returns the head commit of the branch (HEAD when empty)
// without credentials.
func gitLsRemote(url, branch string) (sha string, err error) {
	ref := lsRemoteRef(branch)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "ls-remote", url, ref)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.Output()
	if err != nil {
		return
	}
	sha = parseLsRemote(string(out))
	return
}

func refresh(hub *binding.RichClient, archetype string, lsRemote func(url, ref string) (string, error)) (created, skipped int, err error) {
	members, err := scope.Members(hub, archetype)
	if err != nil {
		return
	}
	if len(members) == 0 {
		return
	}
	apps, err := hub.Application.List()
	if err != nil {
		return
	}
	for i := range apps {
		app := &apps[i]
		if !members[app.ID] {
			continue
		}
		if app.Repository == nil || app.Repository.URL == "" {
			log.Printf("app %s: no repository; skipped", app.Name)
			continue
		}
		facts := hub.Application.Select(app.ID).Fact.Source(finding.SourceRHTPA)
		sbom := finding.SBOM{}
		hasSBOM := false
		if gerr := facts.Get(finding.KeySBOM, &sbom); gerr == nil {
			hasSBOM = sbom.ID != ""
		} else {
			var nf *binding.NotFound
			if !errors.As(gerr, &nf) {
				log.Printf("app %s: read sbom: %v", app.Name, gerr)
			}
		}
		head, lerr := lsRemote(app.Repository.URL, app.Repository.Branch)
		if lerr != nil {
			log.Printf("app %s: ls-remote: %v", app.Name, lerr)
			head = ""
		}
		if hasSBOM && skip(sbom, head) {
			sbom.NightlyAt = time.Now().UTC()
			if serr := facts.Set(finding.KeySBOM, &sbom); serr != nil {
				err = errors.Join(err, fmt.Errorf("app %s: mark nightly: %w", app.Name, serr))
				continue
			}
			log.Printf("app %s: skipped (commit %s unchanged)", app.Name, head)
			skipped++
			continue
		}
		task := &api.Task{
			Name:        app.Name + "-nightly-sbom",
			Kind:        finding.KindSBOM,
			Application: &api.Ref{ID: app.ID},
			State:       "Ready",
			Data:        api.Map{"nightly": true},
		}
		if terr := hub.Task.Create(task); terr != nil {
			err = errors.Join(err, fmt.Errorf("app %s: create task: %w", app.Name, terr))
			continue
		}
		log.Printf("app %s: created task %d", app.Name, task.ID)
		created++
	}
	return
}
