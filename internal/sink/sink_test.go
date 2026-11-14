package sink

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/littlemex/sandbox-guestwatch/internal/event"
)

func decode(t *testing.T, s string) []event.Event {
	t.Helper()
	var out []event.Event
	for _, l := range strings.Split(strings.TrimSpace(s), "\n") {
		var e event.Event
		if err := json.Unmarshal([]byte(l), &e); err != nil {
			t.Fatal(err)
		}
		if e.V != event.SchemaVersion {
			t.Fatalf("schema version %d", e.V)
		}
		out = append(out, e)
	}
	return out
}

// Noise is rate limited; heartbeats and tagged events are never rate limited.
func TestRateLimitSparesPriorityLane(t *testing.T) {
	var buf bytes.Buffer
	s := New(&buf, 200, 5)
	for i := 0; i < 50; i++ {
		s.Emit(event.New(event.TypeFile))
	}
	tagged := event.New(event.TypeExec)
	tagged.Rules = []string{"exec_from_temp_dir"}
	s.Emit(tagged)
	s.Emit(event.New(event.TypeHeartbeat))
	go s.Run()
	s.Close()
	got := map[string]int{}
	for _, e := range decode(t, buf.String()) {
		got[e.Type]++
	}
	st := s.Stats()
	if got[event.TypeHeartbeat] != 1 || got[event.TypeExec] != 1 {
		t.Fatalf("priority events lost: %v", got)
	}
	if got[event.TypeFile] > 6 || uint64(got[event.TypeFile])+st["dropped.file"] != 50 || st["dropped.rate"] != st["dropped.file"] {
		t.Fatalf("written %v, stats %v", got, st)
	}
}

func TestFullQueueDropsWithoutBlocking(t *testing.T) {
	s := New(&bytes.Buffer{}, 2, 0)
	for i := 0; i < 10; i++ {
		s.Emit(event.New(event.TypeExec))
	}
	if st := s.Stats(); st["dropped.queue_full"] != 8 {
		t.Fatalf("stats %v", st)
	}
	go s.Run()
	s.Close()
	s.Emit(event.New(event.TypeExec)) // after Close: must not panic
}
