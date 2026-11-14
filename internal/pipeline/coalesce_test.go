package pipeline

import (
	"net/netip"
	"testing"
	"time"

	"github.com/littlemex/sandbox-guestwatch/internal/event"
	"github.com/littlemex/sandbox-guestwatch/internal/netmon"
)

func netEvent() *event.Event {
	e := event.New(event.TypeSend)
	e.Net = &event.Net{Proto: "udp", Family: 4, Dst: "10.0.0.10", Port: 53, Count: 1}
	return e
}

func TestCoalescerBurstAndRollover(t *testing.T) {
	c := newCoalescer(10*time.Second, 100)
	r := netmon.Record{PID: 1, Hook: netmon.HookSendmsg4, Dst: netip.MustParseAddr("10.0.0.10"), Port: 53, Proto: 17}
	k := keyOf(r)
	t0 := time.Unix(1000, 0)
	builds := 0
	build := func() *event.Event { builds++; return netEvent() }

	if e, _ := c.add(k, t0, build); e == nil {
		t.Fatal("first record not emitted")
	}
	for i := 0; i < 999; i++ {
		if e, rolled := c.add(k, t0.Add(time.Millisecond), build); e != nil || rolled != nil {
			t.Fatal("repeat emitted")
		}
	}
	if builds != 1 {
		t.Fatalf("attributed %d times, want once per window", builds)
	}
	// A record after the window but before any flush must not lose the count.
	e, rolled := c.add(k, t0.Add(10*time.Second), build)
	if e == nil || rolled == nil || rolled.Net.Count != 999 || !rolled.Net.Repeat || rolled.Net.WindowStart == nil {
		t.Fatalf("rollover: emit=%v rolled=%+v", e, rolled)
	}
	if got := c.flush(t0.Add(30*time.Second), false); len(got) != 0 {
		t.Fatalf("window without repeats flushed: %+v", got)
	}
}

func TestCoalescerFlushAndCap(t *testing.T) {
	c := newCoalescer(10*time.Second, 1)
	t0 := time.Unix(1000, 0)
	a := netKey{pid: 1, port: 1}
	b := netKey{pid: 1, port: 2}
	c.add(a, t0, netEvent)
	c.add(a, t0, netEvent)
	// The map is full: b passes through every time, uncoalesced.
	for i := 0; i < 3; i++ {
		if e, _ := c.add(b, t0, netEvent); e == nil {
			t.Fatal("record dropped when the coalescer is full")
		}
	}
	if got := c.flush(t0.Add(5*time.Second), false); len(got) != 0 {
		t.Fatalf("flushed early: %+v", got)
	}
	if got := c.flush(t0.Add(5*time.Second), true); len(got) != 1 || got[0].Net.Count != 1 {
		t.Fatalf("final flush: %+v", got)
	}
}
