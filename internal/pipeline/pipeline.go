// Package pipeline wires the sources to the sink. It owns attribution (which
// container and process an event belongs to), network coalescing, rule
// tagging, the startup probe, heartbeats and shutdown order.
package pipeline

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/littlemex/sandbox-guestwatch/internal/config"
	"github.com/littlemex/sandbox-guestwatch/internal/discover"
	"github.com/littlemex/sandbox-guestwatch/internal/event"
	"github.com/littlemex/sandbox-guestwatch/internal/filewatch"
	"github.com/littlemex/sandbox-guestwatch/internal/netmon"
	"github.com/littlemex/sandbox-guestwatch/internal/procconn"
	"github.com/littlemex/sandbox-guestwatch/internal/procinfo"
	"github.com/littlemex/sandbox-guestwatch/internal/rules"
	"github.com/littlemex/sandbox-guestwatch/internal/sink"
)

// Signal names used in agent_start, heartbeat and Config.Require.
const (
	SignalExec = "exec"
	SignalNet  = "net"
	SignalFile = "file"
)

// States beyond event.StateOK and event.StateOff.
const (
	stateNoEvents = "set up, but the startup probe saw no event"
)

// The agent connects a UDP socket to this address at startup and expects to
// see its own record (port 9 is the discard service; nothing is sent).
var (
	probeDst  = netip.MustParseAddr("127.0.0.1")
	probePort = 9
)

// Agent is one running pipeline.
type Agent struct {
	cfg     config.Config
	version string
	out     *sink.Sink
	procs   *procinfo.Table
	reg     *discover.Registry
	rules   *rules.Rules

	conn *procconn.Conn
	mon  *netmon.Monitor
	fw   *filewatch.Watcher

	mu      sync.Mutex
	signals map[string]string

	unattributed    atomic.Uint64
	netUnattributed atomic.Uint64
	probeExecPID atomic.Int64
	probeExec    chan struct{}
	probeNet     chan struct{}
	probeNetOnce sync.Once
	netDone      chan struct{}
}

// New prepares an agent writing to out.
func New(cfg config.Config, version string, out *sink.Sink) (*Agent, error) {
	r, err := rules.New(rules.Options{BinaryDirs: cfg.BinaryDirs, TempDirs: cfg.TempDirs, AllowCIDRs: cfg.AllowCIDRs})
	if err != nil {
		return nil, fmt.Errorf("--allow-cidr: %w", err)
	}
	reg, err := discover.New(cfg.ProcRoot, cfg.CgroupRoot, cfg.CgroupPrefix)
	if err != nil {
		return nil, fmt.Errorf("reading mount namespaces (is the Pod hostPID?): %w", err)
	}
	return &Agent{
		cfg: cfg, version: version, out: out, rules: r, reg: reg,
		procs:     procinfo.NewTable(cfg.ProcRoot, cfg.MaxCmdlineBytes),
		signals:   map[string]string{SignalExec: event.StateOff, SignalNet: event.StateOff, SignalFile: event.StateOff},
		probeExec: make(chan struct{}), probeNet: make(chan struct{}), netDone: make(chan struct{}),
	}, nil
}

// Run starts every source, reports agent_start, and runs until ctx is done.
// It returns an error only for a failed Config.Require check.
func (a *Agent) Run(ctx context.Context) error {
	a.reg.Subscribe(lifecycle{a})
	a.startFiles()
	a.startExec(ctx)
	a.startNet(ctx)
	a.reg.Scan()
	go a.reg.Run(ctx, a.cfg.DiscoveryInterval, a.cfg.MinRescanInterval)

	a.probe()
	start := event.New(event.TypeAgentStart)
	start.Msg = "guestwatch " + a.version
	start.Signals = a.signalsCopy()
	a.out.Emit(start)
	for _, s := range a.cfg.Require {
		if st := a.signalsCopy()[s]; st != event.StateOK {
			a.shutdown()
			return fmt.Errorf("required signal %q is %q", s, st)
		}
	}

	t := time.NewTicker(a.cfg.HeartbeatInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			a.shutdown()
			return nil
		case <-t.C:
			a.heartbeat()
		}
	}
}

// shutdown stops the sources, flushes pending network repeats, releases the
// containers and leaves the sink to the caller.
func (a *Agent) shutdown() {
	if a.mon != nil {
		a.mon.Close()
		<-a.netDone
	}
	if a.conn != nil {
		a.conn.Close()
	}
	a.reg.Close()
}

func (a *Agent) setSignal(name, state string) {
	a.mu.Lock()
	a.signals[name] = state
	a.mu.Unlock()
}

func (a *Agent) signalsCopy() map[string]string {
	a.mu.Lock()
	defer a.mu.Unlock()
	m := make(map[string]string, len(a.signals))
	for k, v := range a.signals {
		m[k] = v
	}
	return m
}

// publish tags e with the rules and hands it to the sink.
func (a *Agent) publish(e *event.Event) {
	e.Rules = a.rules.Tag(e)
	a.out.Emit(e)
}

func (a *Agent) fail(signal string, err error) {
	a.setSignal(signal, "failed: "+err.Error())
	e := event.New(event.TypeAgentError)
	e.Msg = fmt.Sprintf("%s: %v", signal, err)
	a.out.Emit(e)
}

// probe makes one exec and one UDP connect of its own and waits for each to
// come back through its source, so "ok" means events are delivered, not only
// that setup returned without error.
func (a *Agent) probe() {
	wait := func(ch chan struct{}, signal string) {
		if a.signalsCopy()[signal] != event.StateOK {
			return
		}
		select {
		case <-ch:
		case <-time.After(2 * time.Second):
			a.setSignal(signal, stateNoEvents)
		}
	}
	if a.conn != nil {
		cmd := exec.Command("/proc/self/exe", "--version")
		if err := cmd.Start(); err == nil {
			a.probeExecPID.Store(int64(cmd.Process.Pid))
			wait(a.probeExec, SignalExec)
			cmd.Wait()
		}
	}
	if a.mon != nil {
		if c, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(probeDst, uint16(probePort)))); err == nil {
			c.Close()
		}
		wait(a.probeNet, SignalNet)
	}
}

// containerFor finds the container of a process. ok is false for the agent's
// own processes and the guest's infrastructure, which are not reported. For
// network events the kernel-captured cgroup id is tried first, because the pid
// may have been reused by the time the record is read.
func (a *Agent) containerFor(info procinfo.Info, cgroupID uint64) (*event.Container, bool) {
	if cgroupID != 0 {
		if c := a.reg.ByCgroup(cgroupID); c != nil {
			return c.Identity(), true
		}
	}
	if info.MntNS != 0 && a.reg.Ignored(info.MntNS) {
		return nil, false
	}
	if c := a.reg.ByNS(info.MntNS); c != nil {
		return c.Identity(), true
	}
	if info.MntNS != 0 {
		return &event.Container{MntNS: info.MntNS}, true
	}
	return nil, true
}

type lifecycle struct{ a *Agent }

func (l lifecycle) ContainerAdded(c *discover.Container) {
	e := event.New(event.TypeContainerAdd)
	e.Container = c.Identity()
	l.a.out.Emit(e)
}

func (l lifecycle) ContainerRemoved(c *discover.Container) {
	e := event.New(event.TypeContainerRemove)
	e.Container = c.Identity()
	l.a.out.Emit(e)
}

func (a *Agent) startExec(ctx context.Context) {
	conn, err := procconn.Open(filepath.Join(a.cfg.ProcRoot, "1", "ns", "net"), a.cfg.ProcRcvBufBytes)
	if err != nil {
		a.fail(SignalExec, err)
		return
	}
	a.conn = conn
	a.setSignal(SignalExec, event.StateOK)
	go func() {
		buf := make([]byte, 64*1024)
		for {
			evs, err := conn.Read(buf)
			if err != nil {
				if ctx.Err() == nil {
					a.fail(SignalExec, err)
				}
				return
			}
			for _, ev := range evs {
				a.onProcEvent(ev)
			}
		}
	}()
}

func (a *Agent) onProcEvent(ev procconn.Event) {
	if ev.PID != ev.TGID {
		return // a thread, not a process
	}
	switch ev.What {
	case procconn.WhatFork:
		a.procs.OnFork(ev.ParentTGID, ev.TGID)
	case procconn.WhatExit:
		a.procs.OnExit(ev.TGID)
	case procconn.WhatExec:
		if int64(ev.TGID) == a.probeExecPID.Load() {
			a.probeExecPID.Store(0)
			close(a.probeExec)
			return
		}
		info := a.procs.OnExec(ev.TGID)
		if info.MntNS == 0 {
			// Neither the process nor its parent could be read. In the
			// guest this is the sandbox runtime's own lineage, whose /proc
			// entries are not readable; it is counted, not reported.
			a.unattributed.Add(1)
			return
		}
		c, ok := a.containerFor(info, 0)
		if !ok {
			return
		}
		e := event.New(event.TypeExec)
		e.Container = c
		e.Process = &event.Process{
			PID: info.PID, PPID: info.PPID, UID: info.UID, Comm: info.Comm, Exe: info.Exe,
			Cmdline: info.Cmdline, Truncated: info.Truncated, Partial: info.Partial,
		}
		a.publish(e)
	}
}

func (a *Agent) startNet(ctx context.Context) {
	mon, err := netmon.Open(a.cfg.CgroupRoot, a.cfg.RingBufBytes)
	if err != nil {
		a.fail(SignalNet, err)
		close(a.netDone)
		return
	}
	a.mon = mon
	a.setSignal(SignalNet, event.StateOK)
	recs := make(chan netmon.Record, 1024)
	go func() {
		defer close(recs)
		for {
			r, err := mon.Read()
			if netmon.IsClosed(err) {
				return
			}
			if err != nil {
				if ctx.Err() == nil {
					a.fail(SignalNet, err)
				}
				return
			}
			recs <- r
		}
	}()
	go func() {
		defer close(a.netDone)
		co := newCoalescer(a.cfg.NetCoalesce, a.cfg.NetCoalesceEntries)
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		self := os.Getpid()
		for {
			select {
			case r, ok := <-recs:
				if !ok {
					for _, e := range co.flush(time.Now(), true) {
						a.publish(e)
					}
					return
				}
				if r.PID == self {
					if r.Dst == probeDst && r.Port == probePort {
						a.probeNetOnce.Do(func() { close(a.probeNet) })
					}
					continue
				}
				emit, rolled := co.add(keyOf(r), time.Now(), func() *event.Event { return a.netEvent(r) })
				for _, e := range []*event.Event{rolled, emit} {
					if e != nil {
						a.publish(e)
					}
				}
			case now := <-tick.C:
				for _, e := range co.flush(now, false) {
					a.publish(e)
				}
			}
		}
	}()
}

// netEvent attributes r at the moment it is read. It returns nil for the
// agent's own traffic and the guest's infrastructure.
func (a *Agent) netEvent(r netmon.Record) *event.Event {
	info, _ := a.procs.Lookup(r.PID)
	c, ok := a.containerFor(info, r.CgroupID)
	if !ok {
		return nil
	}
	if c == nil {
		// Neither the cgroup nor the process could be matched: the sandbox
		// runtime's own processes, or a process gone before it was read.
		a.netUnattributed.Add(1)
		return nil
	}
	typ := event.TypeSend
	if r.Hook.Connect() {
		typ = event.TypeConnect
	}
	family := 4
	if r.Dst.Is6() {
		family = 6
	}
	e := event.New(typ)
	e.Container = c
	e.Process = &event.Process{PID: r.PID, PPID: info.PPID, UID: r.UID, Comm: r.Comm, Exe: info.Exe}
	e.Net = &event.Net{Proto: r.ProtoName(), Family: family, Dst: r.Dst.String(), Port: r.Port, Count: 1}
	return e
}

func (a *Agent) startFiles() {
	fw, err := filewatch.New(a.cfg.WatchDirs, a.cfg.MaxWatches, a.cfg.MaxDepth, a.cfg.FileCoalesce,
		func(c *discover.Container, f event.File) {
			e := event.New(event.TypeFile)
			e.Container = c.Identity()
			e.File = &f
			a.publish(e)
		})
	if err != nil {
		a.fail(SignalFile, err)
		return
	}
	a.fw = fw
	a.reg.Subscribe(fw)
	a.setSignal(SignalFile, event.StateOK)
	go func() {
		if err := fw.Run(); err != nil && !errors.Is(err, os.ErrClosed) {
			a.fail(SignalFile, err)
		}
	}()
}

func (a *Agent) heartbeat() {
	e := event.New(event.TypeHeartbeat)
	e.Signals = a.signalsCopy()
	st := a.out.Stats()
	st["containers"] = uint64(a.reg.Len())
	st["pids_tracked"] = uint64(a.procs.Len())
	st["exec.unattributed"] = a.unattributed.Load()
	st["net.unattributed"] = a.netUnattributed.Load()
	if a.conn != nil {
		st["exec.overrun"] = a.conn.Overrun.Load()
	}
	if a.mon != nil {
		st["net.ring_drops"] = a.mon.Drops()
	}
	if a.fw != nil {
		st["file.watches"] = uint64(a.fw.Watches())
		st["file.queue_overflow"] = a.fw.Overflows.Load()
		st["file.watch_cap_hits"] = a.fw.CapHits.Load()
		st["file.add_failures"] = a.fw.AddFailures.Load()
		if a.fw.CapHits.Load() > 0 && e.Signals[SignalFile] == event.StateOK {
			e.Signals[SignalFile] = event.StateCapped
		}
	}
	e.Stats = st
	a.out.Emit(e)
}
