package procinfo

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestParseNSLink(t *testing.T) {
	if v, err := ParseNSLink("mnt:[4026531841]"); err != nil || v != 4026531841 {
		t.Fatalf("got %d %v", v, err)
	}
	if _, err := ParseNSLink("mnt:"); err == nil {
		t.Fatal("bad link accepted")
	}
}

func TestSplitCmdline(t *testing.T) {
	if got := SplitCmdline([]byte("curl\x00-s\x00http://x\x00")); !reflect.DeepEqual(got, []string{"curl", "-s", "http://x"}) {
		t.Fatalf("got %q", got)
	}
	if got := SplitCmdline(nil); got != nil {
		t.Fatalf("got %q", got)
	}
}

func TestParseStatus(t *testing.T) {
	ppid, uid, name := parseStatus([]byte("Name:\tcurl\nPPid:\t7\nUid:\t1000\t1000\t1000\t1000\n"))
	if ppid != 7 || uid != 1000 || name != "curl" {
		t.Fatalf("got %d %d %q", ppid, uid, name)
	}
}

// A process that is gone by the time of exec keeps what fork recorded.
func TestExecOfExitedProcessIsPartial(t *testing.T) {
	proc := t.TempDir()
	parent := filepath.Join(proc, "10")
	os.MkdirAll(filepath.Join(parent, "ns"), 0o755)
	os.Symlink("mnt:[555]", filepath.Join(parent, "ns", "mnt"))
	os.WriteFile(filepath.Join(parent, "status"), []byte("Name:\tsh\nPPid:\t1\nUid:\t1000\n"), 0o644)

	tb := NewTable(proc, 4096)
	if _, ok := tb.Lookup(10); !ok {
		t.Fatal("parent not read")
	}
	tb.OnFork(10, 11)
	info := tb.OnExec(11)
	if !info.Partial || info.PPID != 10 || info.MntNS != 555 || info.UID != 1000 {
		t.Fatalf("got %+v", info)
	}
	tb.OnExit(11)
	if tb.Len() != 1 {
		t.Fatalf("table has %d entries", tb.Len())
	}
}

func TestReadTruncatesCmdline(t *testing.T) {
	proc := t.TempDir()
	d := filepath.Join(proc, "5")
	os.MkdirAll(filepath.Join(d, "ns"), 0o755)
	os.Symlink("mnt:[1]", filepath.Join(d, "ns", "mnt"))
	os.WriteFile(filepath.Join(d, "status"), []byte("Name:\tx\n"), 0o644)
	os.WriteFile(filepath.Join(d, "cmdline"), append([]byte("aaaaaaaaaa\x00"), make([]byte, 100)...), 0o644)
	info, err := Read(proc, 5, 8)
	if err != nil || !info.Truncated || len(info.Cmdline) != 1 || info.Cmdline[0] != "aaaaaaaa" {
		t.Fatalf("got %+v %v", info, err)
	}
}
