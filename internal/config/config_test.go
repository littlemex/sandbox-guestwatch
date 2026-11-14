package config

import "testing"

func TestDefaultIsValid(t *testing.T) {
	c := Default()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := map[string]func(*Config){
		"zero heartbeat":          func(c *Config) { c.HeartbeatInterval = 0 },
		"relative watch dir":      func(c *Config) { c.WatchDirs = append(c.WatchDirs, "tmp") },
		"unclean watch dir":       func(c *Config) { c.WatchDirs = append(c.WatchDirs, "/tmp/../etc") },
		"binary dir not watched":  func(c *Config) { c.BinaryDirs = append(c.BinaryDirs, "/opt/bin") },
		"ring not a power of two": func(c *Config) { c.RingBufBytes = 3 << 20 },
		"zero queue":              func(c *Config) { c.QueueSize = 0 },
	}
	for name, mutate := range cases {
		c := Default()
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
