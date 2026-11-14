// Package sink owns everything about output volume: bounded queues that never
// block a source, a rate limit, drop accounting, and the JSON writer.
//
// Events go to one of two lanes. The priority lane carries agent and
// container lifecycle events, heartbeats, and every event a rule tagged; it is
// never rate limited and is drained first. Everything else uses the normal
// lane, which is rate limited. A full lane drops and counts.
package sink

import (
	"encoding/json"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/littlemex/sandbox-guestwatch/internal/event"
)

// Sink accepts events from many goroutines and writes them from one.
type Sink struct {
	prio, norm chan *event.Event
	out        io.Writer
	rate       int

	mu      sync.Mutex
	emitted map[string]uint64
	dropped map[string]uint64

	queueFull   atomic.Uint64
	rateDropped atomic.Uint64
	writeErrors atomic.Uint64

	closeMu sync.RWMutex
	closed  bool
	done    chan struct{}
}

// New returns a sink writing to out. rate is the limit for the normal lane in
// events per second (0 = unlimited).
func New(out io.Writer, queueSize, rate int) *Sink {
	return &Sink{
		prio: make(chan *event.Event, queueSize), norm: make(chan *event.Event, queueSize),
		out: out, rate: rate,
		emitted: map[string]uint64{}, dropped: map[string]uint64{},
		done: make(chan struct{}),
	}
}

// Priority reports whether e goes to the priority lane.
func Priority(e *event.Event) bool {
	switch e.Type {
	case event.TypeHeartbeat, event.TypeAgentStart, event.TypeAgentError,
		event.TypeContainerAdd, event.TypeContainerRemove:
		return true
	}
	return len(e.Rules) > 0
}

// Emit enqueues e without blocking.
func (s *Sink) Emit(e *event.Event) {
	s.closeMu.RLock()
	defer s.closeMu.RUnlock()
	if s.closed {
		return
	}
	q := s.norm
	if Priority(e) {
		q = s.prio
	}
	select {
	case q <- e:
	default:
		s.queueFull.Add(1)
		s.count(s.dropped, e.Type)
	}
}

func (s *Sink) count(m map[string]uint64, typ string) {
	s.mu.Lock()
	m[typ]++
	s.mu.Unlock()
}

// Stats returns "emitted.<type>", "dropped.<type>" and the totals
// "dropped.queue_full", "dropped.rate" and "write_errors".
func (s *Sink) Stats() map[string]uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]uint64, len(s.emitted)+len(s.dropped)+3)
	for k, v := range s.emitted {
		out["emitted."+k] = v
	}
	for k, v := range s.dropped {
		out["dropped."+k] = v
	}
	out["dropped.queue_full"] = s.queueFull.Load()
	out["dropped.rate"] = s.rateDropped.Load()
	out["write_errors"] = s.writeErrors.Load()
	return out
}

// Run writes events until Close is called and both lanes are drained.
func (s *Sink) Run() {
	defer close(s.done)
	enc := json.NewEncoder(s.out)
	tokens, last := float64(s.rate), time.Now()
	prio, norm := s.prio, s.norm
	for prio != nil || norm != nil {
		var e *event.Event
		var ok bool
		// Drain the priority lane first.
		select {
		case e, ok = <-prio:
			if !ok {
				prio = nil
				continue
			}
		default:
			select {
			case e, ok = <-prio:
				if !ok {
					prio = nil
					continue
				}
			case e, ok = <-norm:
				if !ok {
					norm = nil
					continue
				}
				if s.rate > 0 {
					now := time.Now()
					tokens += now.Sub(last).Seconds() * float64(s.rate)
					last = now
					if tokens > float64(s.rate) {
						tokens = float64(s.rate)
					}
					if tokens < 1 {
						s.rateDropped.Add(1)
						s.count(s.dropped, e.Type)
						continue
					}
					tokens--
				}
			}
		}
		if err := enc.Encode(e); err != nil {
			s.writeErrors.Add(1)
			s.count(s.dropped, e.Type)
			continue
		}
		s.count(s.emitted, e.Type)
	}
}

// Close stops accepting events and waits for the writer to drain.
func (s *Sink) Close() {
	s.closeMu.Lock()
	if !s.closed {
		s.closed = true
		close(s.prio)
		close(s.norm)
	}
	s.closeMu.Unlock()
	<-s.done
}
