// Package procinfo reads process details from /proc and keeps a small pid
// table filled from fork, exec and exit events, so that an event for a process
// that has already exited can still carry its parent and mount namespace.
package procinfo

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// Info is what the agent knows about one process.
type Info struct {
	PID     int
	PPID    int
	UID     int
	MntNS   uint64
	Comm    string
	Exe     string
	Cmdline []string
	// Truncated is set when Cmdline was cut to the size limit.
	Truncated bool
	Partial   bool
}

// Table is the pid table. It is safe for concurrent use.
type Table struct {
	proc       string
	maxCmdline int
	mu         sync.Mutex
	m          map[int]*Info
}

// NewTable returns an empty table reading from procRoot (normally /proc).
// Command lines longer than maxCmdline bytes are truncated.
func NewTable(procRoot string, maxCmdline int) *Table {
	return &Table{proc: procRoot, maxCmdline: maxCmdline, m: map[int]*Info{}}
}

func (t *Table) read(pid int) (Info, error) { return Read(t.proc, pid, t.maxCmdline) }

// OnFork records a child. Until it execs, a child runs its parent's program,
// so it inherits the parent's identity. A parent the table has not seen (it
// started before the agent) is read from /proc once.
func (t *Table) OnFork(parent, child int) {
	t.mu.Lock()
	p, ok := t.m[parent]
	t.mu.Unlock()
	if !ok || p.MntNS == 0 {
		if fresh, err := t.read(parent); err == nil {
			p = &fresh
			t.mu.Lock()
			t.m[parent] = p
			t.mu.Unlock()
		}
	}
	ci := &Info{PID: child, PPID: parent}
	if p != nil {
		ci.MntNS, ci.UID, ci.Comm, ci.Exe, ci.Cmdline, ci.Truncated = p.MntNS, p.UID, p.Comm, p.Exe, p.Cmdline, p.Truncated
	}
	t.mu.Lock()
	t.m[child] = ci
	t.mu.Unlock()
}

// OnExec reads the process from /proc and stores it. If /proc is already
// gone, it returns what the table remembers about the process and its parent,
// marked Partial; the program fields are then the parent's and are dropped.
func (t *Table) OnExec(pid int) Info {
	fresh, err := t.read(pid)
	t.mu.Lock()
	defer t.mu.Unlock()
	old := t.m[pid]
	if err != nil {
		info := Info{PID: pid, Partial: true}
		if old != nil {
			info.PPID, info.MntNS, info.UID = old.PPID, old.MntNS, old.UID
		}
		return info
	}
	if fresh.PPID == 0 && old != nil {
		fresh.PPID = old.PPID
	}
	t.m[pid] = &fresh
	return fresh
}

// OnExit forgets the process.
func (t *Table) OnExit(pid int) {
	t.mu.Lock()
	delete(t.m, pid)
	t.mu.Unlock()
}

// Lookup returns the stored info for pid, reading /proc if the pid is unknown.
// A forked child that never exec'd returns its parent's program fields.
func (t *Table) Lookup(pid int) (Info, bool) {
	t.mu.Lock()
	if i, ok := t.m[pid]; ok && i.MntNS != 0 {
		v := *i
		t.mu.Unlock()
		return v, true
	}
	t.mu.Unlock()
	fresh, err := t.read(pid)
	if err != nil {
		return Info{}, false
	}
	t.mu.Lock()
	t.m[pid] = &fresh
	t.mu.Unlock()
	return fresh, true
}

// Len is the number of tracked processes.
func (t *Table) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.m)
}

// Read reads one process from procRoot, truncating the command line to
// maxCmdline bytes.
func Read(procRoot string, pid, maxCmdline int) (Info, error) {
	dir := filepath.Join(procRoot, strconv.Itoa(pid))
	info := Info{PID: pid}
	ns, err := NSInode(filepath.Join(dir, "ns", "mnt"))
	if err != nil {
		return info, err
	}
	info.MntNS = ns
	status, err := os.ReadFile(filepath.Join(dir, "status"))
	if err != nil {
		return info, err
	}
	info.PPID, info.UID, info.Comm = parseStatus(status)
	if raw, err := os.ReadFile(filepath.Join(dir, "cmdline")); err == nil {
		if maxCmdline > 0 && len(raw) > maxCmdline {
			raw, info.Truncated = raw[:maxCmdline], true
		}
		info.Cmdline = SplitCmdline(raw)
	}
	if exe, err := os.Readlink(filepath.Join(dir, "exe")); err == nil {
		info.Exe = exe
	}
	return info, nil
}

// NSInode parses the inode out of a namespace link like "mnt:[4026531841]".
func NSInode(link string) (uint64, error) {
	s, err := os.Readlink(link)
	if err != nil {
		return 0, err
	}
	return ParseNSLink(s)
}

// ParseNSLink parses "mnt:[4026531841]".
func ParseNSLink(s string) (uint64, error) {
	i, j := strings.IndexByte(s, '['), strings.IndexByte(s, ']')
	if i < 0 || j <= i+1 {
		return 0, fmt.Errorf("unexpected namespace link %q", s)
	}
	return strconv.ParseUint(s[i+1:j], 10, 64)
}

// SplitCmdline splits a NUL-separated /proc/<pid>/cmdline.
func SplitCmdline(raw []byte) []string {
	raw = bytes.TrimRight(raw, "\x00")
	if len(raw) == 0 {
		return nil
	}
	parts := bytes.Split(raw, []byte{0})
	out := make([]string, len(parts))
	for i, p := range parts {
		out[i] = string(p)
	}
	return out
}

func parseStatus(b []byte) (ppid, uid int, name string) {
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "Name":
			name = v
		case "PPid":
			ppid, _ = strconv.Atoi(v)
		case "Uid":
			if f := strings.Fields(v); len(f) > 0 {
				uid, _ = strconv.Atoi(f[0])
			}
		}
	}
	return
}
