package rules

import (
	"reflect"
	"testing"

	"github.com/littlemex/sandbox-guestwatch/internal/config"
	"github.com/littlemex/sandbox-guestwatch/internal/event"
)

func TestTag(t *testing.T) {
	cfg := config.Default()
	r, err := New(Options{BinaryDirs: cfg.BinaryDirs, TempDirs: cfg.TempDirs, AllowCIDRs: []string{"10.0.0.0/8", "172.20.0.10/32"}})
	if err != nil {
		t.Fatal(err)
	}
	exec := func(exe string) *event.Event {
		return &event.Event{Type: event.TypeExec, Process: &event.Process{Exe: exe}}
	}
	file := func(p, op string) *event.Event {
		return &event.Event{Type: event.TypeFile, File: &event.File{Path: p, Op: op}}
	}
	conn := func(dst string) *event.Event { return &event.Event{Type: event.TypeConnect, Net: &event.Net{Dst: dst}} }
	cases := []struct {
		e    *event.Event
		want []string
	}{
		{exec("/tmp/x"), []string{ExecFromTempDir}},
		{exec("/tmpfoo/x"), nil},
		{exec("/dev/shm/x (deleted)"), []string{ExecFromTempDir, ExecDeletedBinary}},
		{exec("/memfd:payload (deleted)"), []string{ExecFromTempDir, ExecDeletedBinary}},
		{exec("/usr/bin/curl"), nil},
		{file("/usr/bin/ls", "write"), []string{WriteToBinaryDir}},
		{file("/bin/sh", "attrib"), []string{WriteToBinaryDir}},
		{file("/usr/bin/ls", "delete"), nil},
		{file("/etc/passwd", "write"), nil},
		{conn("10.1.2.3"), nil},
		{conn("172.20.0.10"), nil},
		{conn("93.184.216.34"), []string{ConnectOutsideAllowlist}},
	}
	for _, c := range cases {
		if got := r.Tag(c.e); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%+v %+v %+v: got %v, want %v", c.e.Process, c.e.File, c.e.Net, got, c.want)
		}
	}
}

func TestNoAllowlistNoTag(t *testing.T) {
	r, _ := New(Options{})
	if got := r.Tag(&event.Event{Type: event.TypeConnect, Net: &event.Net{Dst: "1.1.1.1"}}); got != nil {
		t.Fatalf("got %v", got)
	}
}

func TestBadCIDR(t *testing.T) {
	if _, err := New(Options{AllowCIDRs: []string{"10.0.0.0/33"}}); err == nil {
		t.Fatal("bad CIDR accepted")
	}
}
