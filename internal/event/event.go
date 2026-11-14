// Package event defines the record every source emits.
package event

import "time"

// SchemaVersion is bumped on any incompatible change to the JSON shape.
const SchemaVersion = 1

// Types of events.
const (
	TypeExec            = "exec"
	TypeConnect         = "connect"
	TypeSend            = "send"
	TypeFile            = "file"
	TypeContainerAdd    = "container_add"
	TypeContainerRemove = "container_remove"
	TypeHeartbeat       = "heartbeat"
	TypeAgentStart      = "agent_start"
	TypeAgentError      = "agent_error"
)

// File operations.
const (
	OpCreate    = "create"
	OpWrite     = "write"
	OpMovedTo   = "moved_to"
	OpMovedFrom = "moved_from"
	OpAttrib    = "attrib"
	OpDelete    = "delete"
)

// Signal states reported in agent_start and heartbeat.
const (
	StateOK     = "ok"
	StateOff    = "off"
	StateCapped = "capped"
)

// Container identifies the container an event belongs to.
type Container struct {
	MntNS      uint64 `json:"mntns"`
	ID         string `json:"id,omitempty"`
	CgroupPath string `json:"cgroup,omitempty"`
	Anchor     string `json:"anchor,omitempty"`
}

// Process describes the process an event belongs to.
type Process struct {
	PID     int      `json:"pid"`
	PPID    int      `json:"ppid,omitempty"`
	UID     int      `json:"uid"`
	Comm    string   `json:"comm,omitempty"`
	Exe     string   `json:"exe,omitempty"`
	Cmdline []string `json:"cmdline,omitempty"`
	// Truncated is set when the command line was cut to the size limit.
	Truncated bool `json:"truncated,omitempty"`
	Partial   bool `json:"partial,omitempty"`
}

// Net describes a connect attempt or a datagram send.
type Net struct {
	Proto  string `json:"proto"`
	Family int    `json:"family"`
	Dst    string `json:"dst"`
	Port   int    `json:"port"`
	// Count is the number of records this line stands for. A line with
	// Repeat set reports the repeats seen after the first line of a window,
	// which started at WindowStart.
	Count       int        `json:"count"`
	Repeat      bool       `json:"repeat,omitempty"`
	WindowStart *time.Time `json:"window_start,omitempty"`
}

// File describes a change seen by inotify.
type File struct {
	Path   string `json:"path"`
	Op     string `json:"op"`
	Rescan bool   `json:"rescan,omitempty"`
}

// Event is one JSON line on stdout.
type Event struct {
	V         int               `json:"v"`
	Time      time.Time         `json:"ts"`
	Type      string            `json:"type"`
	Container *Container        `json:"container,omitempty"`
	Process   *Process          `json:"process,omitempty"`
	Net       *Net              `json:"net,omitempty"`
	File      *File             `json:"file,omitempty"`
	Rules     []string          `json:"rules,omitempty"`
	Msg       string            `json:"msg,omitempty"`
	Signals   map[string]string `json:"signals,omitempty"`
	Stats     map[string]uint64 `json:"stats,omitempty"`
}

// New returns an event of the given type stamped with the current time.
func New(typ string) *Event {
	return &Event{V: SchemaVersion, Time: time.Now().UTC(), Type: typ}
}
