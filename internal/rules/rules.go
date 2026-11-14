// Package rules tags events. Rules never drop or change an event.
package rules

import (
	"net/netip"
	"strings"

	"github.com/littlemex/sandbox-guestwatch/internal/event"
)

// Rule names.
const (
	ExecFromTempDir         = "exec_from_temp_dir"
	ExecDeletedBinary       = "exec_deleted_binary"
	WriteToBinaryDir        = "write_to_binary_dir"
	ConnectOutsideAllowlist = "connect_outside_allowlist"
)

// Options configures the rules. BinaryDirs and TempDirs should be the same
// lists the file watcher uses.
type Options struct {
	BinaryDirs []string
	TempDirs   []string
	AllowCIDRs []string
}

// Rules is the parsed rule set.
type Rules struct {
	bin, tmp []string
	allow    []netip.Prefix
}

// New parses the options.
func New(o Options) (*Rules, error) {
	r := &Rules{bin: o.BinaryDirs, tmp: o.TempDirs}
	for _, c := range o.AllowCIDRs {
		p, err := netip.ParsePrefix(strings.TrimSpace(c))
		if err != nil {
			return nil, err
		}
		r.allow = append(r.allow, p.Masked())
	}
	return r, nil
}

// Tag returns the names of the rules e matches.
func (r *Rules) Tag(e *event.Event) []string {
	var out []string
	switch e.Type {
	case event.TypeExec:
		if e.Process == nil {
			break
		}
		exe := e.Process.Exe
		if underAny(strings.TrimSuffix(exe, " (deleted)"), r.tmp) || strings.HasPrefix(exe, "/memfd:") {
			out = append(out, ExecFromTempDir)
		}
		if strings.HasSuffix(exe, " (deleted)") {
			out = append(out, ExecDeletedBinary)
		}
	case event.TypeFile:
		if e.File == nil {
			break
		}
		switch e.File.Op {
		case event.OpCreate, event.OpWrite, event.OpMovedTo, event.OpAttrib:
			if underAny(e.File.Path, r.bin) {
				out = append(out, WriteToBinaryDir)
			}
		}
	case event.TypeConnect, event.TypeSend:
		if e.Net == nil || len(r.allow) == 0 {
			break
		}
		a, err := netip.ParseAddr(e.Net.Dst)
		if err != nil {
			break
		}
		for _, p := range r.allow {
			if p.Contains(a) {
				return out
			}
		}
		out = append(out, ConnectOutsideAllowlist)
	}
	return out
}

func underAny(p string, dirs []string) bool {
	for _, d := range dirs {
		if p == d || strings.HasPrefix(p, d+"/") {
			return true
		}
	}
	return false
}
