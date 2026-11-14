package discover

import "testing"

func TestParseCgroupV2(t *testing.T) {
	in := "1:name=systemd:/x\n0::/kubepods/besteffort/pod1/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n"
	got := ParseCgroupV2(in)
	if got != "/kubepods/besteffort/pod1/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" {
		t.Fatalf("got %q", got)
	}
	if runtimeID.FindString(got) == "" {
		t.Fatal("runtime id not found")
	}
	if ParseCgroupV2("1:cpu:/x\n") != "" {
		t.Fatal("v1-only file returned a path")
	}
}
