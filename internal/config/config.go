// Package config holds the default directory lists and every tunable limit.
// Lists used by more than one package are defined here once, so that the file
// watcher and the rules can never disagree about which directories matter.
package config

import (
	"fmt"
	"path"
	"strings"
	"time"
)

// DefaultBinaryDirs are directories whose contents are normally only changed
// by an image build. Writes here are tagged by the rules.
func DefaultBinaryDirs() []string {
	return []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"}
}

// DefaultTempDirs are world-writable directories where dropped payloads usually land.
func DefaultTempDirs() []string { return []string{"/tmp", "/var/tmp", "/dev/shm"} }

// DefaultOtherWatchDirs are watched after the binary and temp directories, if
// the watch cap allows.
func DefaultOtherWatchDirs() []string { return []string{"/etc", "/root", "/home"} }

// Config is the runtime configuration, filled from flags.
type Config struct {
	ProcRoot     string
	CgroupRoot   string
	CgroupPrefix string

	// WatchDirs is the watch list in priority order: when the watch cap is
	// reached, directories earlier in the list keep their watches.
	WatchDirs  []string
	BinaryDirs []string
	TempDirs   []string
	MaxWatches int
	MaxDepth   int

	DiscoveryInterval time.Duration
	MinRescanInterval time.Duration
	HeartbeatInterval time.Duration

	EventsPerSecond int
	QueueSize       int
	MaxCmdlineBytes int

	NetCoalesce        time.Duration
	NetCoalesceEntries int
	FileCoalesce       time.Duration

	ProcRcvBufBytes int
	RingBufBytes    uint32

	AllowCIDRs []string
	Require    []string
}

// Default returns the configuration used when no flags are given.
func Default() Config {
	bin, tmp := DefaultBinaryDirs(), DefaultTempDirs()
	watch := append(append(append([]string{}, bin...), tmp...), DefaultOtherWatchDirs()...)
	return Config{
		ProcRoot:           "/proc",
		CgroupRoot:         "/sys/fs/cgroup",
		CgroupPrefix:       "/kubepods",
		WatchDirs:          watch,
		BinaryDirs:         bin,
		TempDirs:           tmp,
		MaxWatches:         8192,
		MaxDepth:           32,
		DiscoveryInterval:  2 * time.Second,
		MinRescanInterval:  250 * time.Millisecond,
		HeartbeatInterval:  30 * time.Second,
		EventsPerSecond:    300,
		QueueSize:          4096,
		MaxCmdlineBytes:    4096,
		NetCoalesce:        10 * time.Second,
		NetCoalesceEntries: 4096,
		FileCoalesce:       time.Second,
		ProcRcvBufBytes:    4 << 20,
		RingBufBytes:       1 << 20,
	}
}

// Validate rejects values that would make the agent panic or misbehave.
func (c *Config) Validate() error {
	positive := map[string]time.Duration{
		"discovery-interval": c.DiscoveryInterval,
		"heartbeat":          c.HeartbeatInterval,
		"net-coalesce":       c.NetCoalesce,
		"file-coalesce":      c.FileCoalesce,
	}
	for name, d := range positive {
		if d <= 0 {
			return fmt.Errorf("--%s must be positive", name)
		}
	}
	if c.QueueSize <= 0 || c.MaxWatches <= 0 || c.EventsPerSecond < 0 || c.MaxCmdlineBytes <= 0 {
		return fmt.Errorf("--queue, --max-watches and --max-cmdline must be positive, --rate not negative")
	}
	if c.RingBufBytes == 0 || c.RingBufBytes&(c.RingBufBytes-1) != 0 {
		return fmt.Errorf("ring buffer size must be a power of two")
	}
	for _, b := range c.BinaryDirs {
		if !covered(b, c.WatchDirs) {
			return fmt.Errorf("binary directory %q is not covered by --watch, so write_to_binary_dir could never fire for it", b)
		}
	}
	for _, list := range [][]string{c.WatchDirs, c.BinaryDirs, c.TempDirs} {
		for _, d := range list {
			if !strings.HasPrefix(d, "/") || path.Clean(d) != d {
				return fmt.Errorf("directory %q must be absolute and clean", d)
			}
		}
	}
	return nil
}

func covered(dir string, watched []string) bool {
	for _, w := range watched {
		if dir == w || strings.HasPrefix(dir, w+"/") || w == "/" {
			return true
		}
	}
	return false
}
