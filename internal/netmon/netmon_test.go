package netmon

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func raw(h Hook, addr []byte, port uint16, proto uint32) []byte {
	b := make([]byte, recordBytes)
	le := binary.LittleEndian
	le.PutUint64(b[offCgroup:], 77)
	le.PutUint32(b[offPID:], 4242)
	le.PutUint32(b[offUID:], 1000)
	b[offHook] = byte(h)
	le.PutUint32(b[offProto:], proto)
	binary.BigEndian.PutUint16(b[offPort:], port)
	copy(b[offAddr:], addr)
	copy(b[offComm:], "curl")
	return b
}

func TestDecodeV4(t *testing.T) {
	r, err := Decode(raw(HookConnect4, []byte{93, 184, 216, 34}, 443, 6))
	if err != nil {
		t.Fatal(err)
	}
	if r.Dst != netip.MustParseAddr("93.184.216.34") || r.Port != 443 || r.PID != 4242 || r.UID != 1000 || r.Comm != "curl" || r.CgroupID != 77 || r.ProtoName() != "tcp" {
		t.Fatalf("decoded %+v", r)
	}
}

func TestDecodeV4MappedIsUnmapped(t *testing.T) {
	a := netip.MustParseAddr("::ffff:10.0.0.5").As16()
	r, err := Decode(raw(HookConnect6, a[:], 80, 6))
	if err != nil {
		t.Fatal(err)
	}
	if !r.Dst.Is4() || r.Dst.String() != "10.0.0.5" {
		t.Fatalf("got %v, want 10.0.0.5", r.Dst)
	}
}

func TestDecodeShort(t *testing.T) {
	if _, err := Decode(make([]byte, 10)); err == nil {
		t.Fatal("short record accepted")
	}
}

func TestProgramsAssemble(t *testing.T) {
	for h := HookConnect4; h <= HookSendmsg6; h++ {
		ins := program(h, 3, 4)
		if err := ins.Marshal(nopWriter{}, binary.LittleEndian); err != nil {
			t.Fatalf("hook %d: %v", h, err)
		}
	}
}

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }
