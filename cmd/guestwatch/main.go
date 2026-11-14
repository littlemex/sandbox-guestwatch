// Command guestwatch records process, network and file activity inside an
// Amazon EKS Nitro Sandbox Pod and writes it as JSON lines to stdout. Run it as
// a privileged sidecar in a Pod with hostPID: true.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/littlemex/sandbox-guestwatch/internal/config"
	"github.com/littlemex/sandbox-guestwatch/internal/pipeline"
	"github.com/littlemex/sandbox-guestwatch/internal/sink"
)

var version = "dev"

func main() {
	cfg := config.Default()
	var watch, bin, tmp, allow, require string
	var ring uint
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.StringVar(&cfg.ProcRoot, "proc", cfg.ProcRoot, "proc file system of the guest")
	flag.StringVar(&cfg.CgroupRoot, "cgroup-root", cfg.CgroupRoot, "cgroup v2 root of the guest")
	flag.StringVar(&cfg.CgroupPrefix, "cgroup-prefix", cfg.CgroupPrefix, "only mount namespaces whose cgroup path starts with this are containers")
	flag.StringVar(&watch, "watch", strings.Join(cfg.WatchDirs, ","), "directories to watch in every container, in priority order")
	flag.StringVar(&bin, "binary-dirs", strings.Join(cfg.BinaryDirs, ","), "directories for the write_to_binary_dir rule")
	flag.StringVar(&tmp, "temp-dirs", strings.Join(cfg.TempDirs, ","), "directories for the exec_from_temp_dir rule")
	flag.IntVar(&cfg.MaxWatches, "max-watches", cfg.MaxWatches, "maximum inotify watches")
	flag.IntVar(&cfg.MaxDepth, "max-depth", cfg.MaxDepth, "maximum directory depth below a watched directory")
	flag.DurationVar(&cfg.DiscoveryInterval, "discovery-interval", cfg.DiscoveryInterval, "how often to rescan for containers")
	flag.DurationVar(&cfg.HeartbeatInterval, "heartbeat", cfg.HeartbeatInterval, "heartbeat interval")
	flag.IntVar(&cfg.EventsPerSecond, "rate", cfg.EventsPerSecond, "maximum untagged events per second written (0 = unlimited)")
	flag.IntVar(&cfg.QueueSize, "queue", cfg.QueueSize, "length of each event queue")
	flag.IntVar(&cfg.MaxCmdlineBytes, "max-cmdline", cfg.MaxCmdlineBytes, "command lines longer than this many bytes are truncated")
	flag.DurationVar(&cfg.NetCoalesce, "net-coalesce", cfg.NetCoalesce, "window for collapsing identical connect and send records")
	flag.DurationVar(&cfg.FileCoalesce, "file-coalesce", cfg.FileCoalesce, "window for collapsing identical file events")
	flag.UintVar(&ring, "ring-bytes", uint(cfg.RingBufBytes), "size of the eBPF ring buffer (power of two)")
	flag.StringVar(&allow, "allow-cidr", "", "comma-separated CIDRs; connections elsewhere are tagged connect_outside_allowlist")
	flag.StringVar(&require, "require", "", "comma-separated signals (exec,net,file) that must work, or the agent exits")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	cfg.WatchDirs, cfg.BinaryDirs, cfg.TempDirs = splitList(watch), splitList(bin), splitList(tmp)
	cfg.AllowCIDRs, cfg.Require = splitList(allow), splitList(require)
	cfg.RingBufBytes = uint32(ring)
	if err := cfg.Validate(); err != nil {
		fatal(err)
	}

	out := sink.New(os.Stdout, cfg.QueueSize, cfg.EventsPerSecond)
	go out.Run()
	agent, err := pipeline.New(cfg, version, out)
	if err != nil {
		out.Close()
		fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	err = agent.Run(ctx)
	out.Close()
	if err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "guestwatch:", err)
	os.Exit(1)
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
