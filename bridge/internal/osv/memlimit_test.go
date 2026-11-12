package osv

import (
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestRunKillsOverMemLimit(t *testing.T) {
	if _, err := os.Stat("/proc/self/statm"); err != nil {
		t.Skip("needs /proc")
	}
	memPoll = 10 * time.Millisecond
	r := &Rgctl{MemLimit: 1}
	start := time.Now()
	_, err := r.run(exec.Command("sleep", "5"), true)
	if !errors.Is(err, ErrMemory) {
		t.Fatalf("err = %v, want ErrMemory", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Error("process not killed promptly")
	}
	r.MemLimit = 1 << 40
	if out, err := r.run(exec.Command("echo", "ok"), true); err != nil || string(out) != "ok\n" {
		t.Errorf("under the limit: %q %v", out, err)
	}
}

func TestParseSize(t *testing.T) {
	for in, want := range map[string]int64{"5Gi": 5 << 30, "512Mi": 512 << 20, "1024": 1024} {
		if got, ok := parseSize(in); !ok || got != want {
			t.Errorf("parseSize(%q) = %d %v", in, got, ok)
		}
	}
	if _, ok := parseSize("lots"); ok {
		t.Error("parseSize accepted garbage")
	}
}
