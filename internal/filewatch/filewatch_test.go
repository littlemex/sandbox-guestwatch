package filewatch

import (
	"encoding/binary"
	"testing"

	"golang.org/x/sys/unix"
)

func rec(wd int32, mask uint32, name string) []byte {
	n := (len(name) + 1 + 15) &^ 15
	b := make([]byte, unix.SizeofInotifyEvent+n)
	binary.LittleEndian.PutUint32(b[0:], uint32(wd))
	binary.LittleEndian.PutUint32(b[4:], mask)
	binary.LittleEndian.PutUint32(b[12:], uint32(n))
	copy(b[unix.SizeofInotifyEvent:], name)
	return b
}

func TestParseEvents(t *testing.T) {
	b := append(rec(3, unix.IN_CREATE, "a.sh"), rec(4, unix.IN_CLOSE_WRITE, "longer-file-name.bin")...)
	evs := ParseEvents(b)
	if len(evs) != 2 || evs[0].Name != "a.sh" || evs[0].WD != 3 || evs[1].Name != "longer-file-name.bin" {
		t.Fatalf("got %+v", evs)
	}
}

func TestOpName(t *testing.T) {
	cases := map[uint32]string{
		unix.IN_CREATE | unix.IN_ISDIR: "create",
		unix.IN_CLOSE_WRITE:            "write",
		unix.IN_MOVED_TO:               "moved_to",
		unix.IN_MOVED_FROM:             "moved_from",
		unix.IN_ATTRIB:                 "attrib",
		unix.IN_DELETE:                 "delete",
		unix.IN_OPEN:                   "",
	}
	for m, want := range cases {
		if got := OpName(m); got != want {
			t.Errorf("OpName(%#x) = %q, want %q", m, got, want)
		}
	}
}
