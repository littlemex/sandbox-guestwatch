package procconn

import (
	"encoding/binary"
	"testing"
)

func msg(what uint32, fields ...uint32) []byte {
	payload := make([]byte, cnMsgLen+evHdrLen+4*len(fields))
	le := binary.LittleEndian
	le.PutUint32(payload[0:], cnIdxProc)
	le.PutUint32(payload[4:], cnValProc)
	le.PutUint32(payload[cnMsgLen:], what)
	for i, f := range fields {
		le.PutUint32(payload[cnMsgLen+evHdrLen+4*i:], f)
	}
	b := make([]byte, nlmsgHdrLen+len(payload))
	le.PutUint32(b[0:], uint32(len(b)))
	copy(b[nlmsgHdrLen:], payload)
	return b
}

func TestParse(t *testing.T) {
	b := append(msg(WhatFork, 10, 10, 11, 11), msg(WhatExec, 11, 11)...)
	b = append(b, msg(WhatExit, 11, 11, 0, 17, 10, 10)...)
	b = append(b, msg(0x40, 1, 2)...) // unknown event type
	evs := Parse(b)
	if len(evs) != 3 {
		t.Fatalf("got %d events, want 3: %+v", len(evs), evs)
	}
	if f := evs[0]; f.What != WhatFork || f.ParentTGID != 10 || f.TGID != 11 {
		t.Errorf("fork = %+v", f)
	}
	if e := evs[1]; e.What != WhatExec || e.PID != 11 {
		t.Errorf("exec = %+v", e)
	}
	if x := evs[2]; x.What != WhatExit || x.TGID != 11 {
		t.Errorf("exit = %+v", x)
	}
}

func TestParseTruncated(t *testing.T) {
	b := msg(WhatExec, 11, 11)
	if evs := Parse(b[:len(b)-6]); len(evs) != 0 {
		t.Fatalf("truncated message parsed: %+v", evs)
	}
}

func TestListenMsgLayout(t *testing.T) {
	b := listenMsg()
	le := binary.LittleEndian
	if int(le.Uint32(b[0:])) != len(b) || le.Uint32(b[16:]) != cnIdxProc || le.Uint16(b[32:]) != 4 || le.Uint32(b[36:]) != procCnMcastListen {
		t.Fatalf("bad listen message % x", b)
	}
}
