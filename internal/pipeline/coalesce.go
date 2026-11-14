package pipeline

import (
	"net/netip"
	"time"

	"github.com/littlemex/sandbox-guestwatch/internal/event"
	"github.com/littlemex/sandbox-guestwatch/internal/netmon"
)

type netKey struct {
	pid   int
	hook  netmon.Hook
	dst   netip.Addr
	port  int
	proto int
}

func keyOf(r netmon.Record) netKey { return netKey{r.PID, r.Hook, r.Dst, r.Port, r.Proto} }

type window struct {
	start time.Time
	first *event.Event
	extra int
}

// coalescer collapses identical connect and send records (same process, hook,
// destination, port and protocol) inside a time window. The first record of a
// window is emitted at once, fully attributed at that moment; the number of
// repeats is emitted once when the window closes, as a copy of the first
// event with Repeat set. A UDP burst becomes two lines instead of thousands.
type coalescer struct {
	win time.Duration
	max int
	m   map[netKey]*window
}

func newCoalescer(win time.Duration, maxEntries int) *coalescer {
	return &coalescer{win: win, max: maxEntries, m: map[netKey]*window{}}
}

// add returns the event to emit now (nil if r is a repeat) and, if r closed an
// expired window that saw repeats, that window's repeat event.
func (c *coalescer) add(k netKey, now time.Time, build func() *event.Event) (emit, rolled *event.Event) {
	w, ok := c.m[k]
	if ok && now.Sub(w.start) < c.win {
		w.extra++
		return nil, nil
	}
	if ok {
		rolled = repeatOf(w, now)
		delete(c.m, k)
	}
	emit = build()
	if emit != nil && len(c.m) < c.max {
		c.m[k] = &window{start: now, first: emit}
	}
	return emit, rolled
}

// flush closes windows older than the window length and returns the repeat
// events of those that saw repeats.
func (c *coalescer) flush(now time.Time, all bool) []*event.Event {
	var out []*event.Event
	for k, w := range c.m {
		if all || now.Sub(w.start) >= c.win {
			if r := repeatOf(w, now); r != nil {
				out = append(out, r)
			}
			delete(c.m, k)
		}
	}
	return out
}

func repeatOf(w *window, now time.Time) *event.Event {
	if w.extra == 0 {
		return nil
	}
	e := *w.first
	n := *w.first.Net
	start := w.start.UTC()
	n.Count, n.Repeat, n.WindowStart = w.extra, true, &start
	e.Net, e.Time, e.Rules = &n, now.UTC(), nil
	return &e
}
