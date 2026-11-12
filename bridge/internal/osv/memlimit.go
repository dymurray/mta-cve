package osv

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ErrMemory means rgctl was stopped for exceeding Rgctl.MemLimit.
var ErrMemory = errors.New("rgctl exceeded its memory limit")

// memPoll is how often the resident memory of rgctl is sampled.
var memPoll = 250 * time.Millisecond

// run runs cmd and returns its stdout (and stderr, when combined). With a
// memory limit, the resident memory of cmd and its descendants is sampled
// and the process group is killed beyond the limit: on a very large
// repository rgctl then fails on its own (reachability is reported as
// unknown) instead of the kernel OOM-killing the whole task pod.
func (r *Rgctl) run(cmd *exec.Cmd, combined bool) (out []byte, err error) {
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if combined {
		cmd.Stderr = &stdout
	}
	err = cmd.Start()
	if err != nil {
		return
	}
	done := make(chan struct{})
	exceeded := make(chan int64, 1)
	if r.MemLimit > 0 {
		go func() {
			tick := time.NewTicker(memPoll)
			defer tick.Stop()
			for {
				select {
				case <-done:
					return
				case <-tick.C:
					if rss := treeRSS(cmd.Process.Pid); rss > r.MemLimit {
						exceeded <- rss
						_ = cmd.Process.Kill()
						return
					}
				}
			}
		}()
	}
	err = cmd.Wait()
	close(done)
	out = stdout.Bytes()
	select {
	case rss := <-exceeded:
		err = fmt.Errorf("%w (%s resident, limit %s)", ErrMemory, size(rss), size(r.MemLimit))
	default:
		if ee, ok := err.(*exec.ExitError); ok && !combined {
			ee.Stderr = stderr.Bytes()
		}
	}
	return
}

// treeRSS returns the resident memory in bytes of pid and its descendants
// (0 when /proc is unavailable).
func treeRSS(pid int) (total int64) {
	children := map[int][]int{}
	stats, _ := filepath.Glob("/proc/[0-9]*/stat")
	for _, path := range stats {
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		// pid (comm) state ppid ...; comm may contain spaces.
		s := string(b)
		i := strings.LastIndexByte(s, ')')
		if i < 0 {
			continue
		}
		fields := strings.Fields(s[i+1:])
		if len(fields) < 2 {
			continue
		}
		child, _ := strconv.Atoi(strings.Fields(s)[0])
		parent, _ := strconv.Atoi(fields[1])
		children[parent] = append(children[parent], child)
	}
	page := int64(os.Getpagesize())
	queue := []int{pid}
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		queue = append(queue, children[p]...)
		b, err := os.ReadFile(fmt.Sprintf("/proc/%d/statm", p))
		if err != nil {
			continue
		}
		f := strings.Fields(string(b))
		if len(f) > 1 {
			n, _ := strconv.ParseInt(f[1], 10, 64)
			total += n * page
		}
	}
	return
}

// DefaultMemLimit returns the rgctl memory limit: RGCTL_MEMORY_LIMIT (bytes,
// or with a Ki/Mi/Gi suffix) when set, else 70% of the container's cgroup
// memory limit, leaving room for the addon and git; 0 (no limit) when
// neither is known.
func DefaultMemLimit() int64 {
	if v := os.Getenv("RGCTL_MEMORY_LIMIT"); v != "" {
		if n, ok := parseSize(v); ok {
			return n
		}
	}
	b, err := os.ReadFile("/sys/fs/cgroup/memory.max") // cgroup v2
	if err != nil {
		b, err = os.ReadFile("/sys/fs/cgroup/memory/memory.limit_in_bytes") // v1
	}
	if err != nil {
		return 0
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil || n <= 0 || n > 1<<50 { // "max" or unlimited
		return 0
	}
	return n * 7 / 10
}

func parseSize(s string) (n int64, ok bool) {
	mult := int64(1)
	for suffix, m := range map[string]int64{"Ki": 1 << 10, "Mi": 1 << 20, "Gi": 1 << 30} {
		if strings.HasSuffix(s, suffix) {
			s, mult = strings.TrimSuffix(s, suffix), m
			break
		}
	}
	v, err := strconv.ParseInt(s, 10, 64)
	return v * mult, err == nil && v > 0
}

func size(n int64) string {
	return fmt.Sprintf("%.1fGi", float64(n)/(1<<30))
}
