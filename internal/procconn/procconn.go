// Package procconn is a client for the Linux proc connector, which reports
// fork, exec and exit of every process. The kernel only delivers these events
// to sockets created in the initial network namespace, so Open creates the
// socket there and then returns the thread to the agent's own namespace.
package procconn

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// Kernel constants from include/uapi/linux/connector.h and cn_proc.h.
const (
	cnIdxProc         = 1
	cnValProc         = 1
	procCnMcastListen = 1

	WhatFork = 0x00000001
	WhatExec = 0x00000002
	WhatExit = 0x80000000

	nlmsgHdrLen = 16
	cnMsgLen    = 20
	evHdrLen    = 16
)

// Event is one decoded proc connector event.
type Event struct {
	What uint32
	// For fork: the child. For exec and exit: the process.
	PID, TGID int
	// For fork: the parent.
	ParentPID, ParentTGID int
}

// Conn is an open proc connector socket.
type Conn struct {
	fd int
	// Overrun counts ENOBUFS: the kernel dropped events because the socket
	// buffer was full.
	Overrun atomic.Uint64
}

// Open creates the socket in the network namespace at netnsPath (normally
// /proc/1/ns/net) and subscribes to events.
func Open(netnsPath string, rcvbuf int) (*Conn, error) {
	fd, err := socketIn(netnsPath)
	if err != nil {
		return nil, err
	}
	if rcvbuf > 0 {
		// Needs CAP_NET_ADMIN; fall back to the unprivileged option.
		if unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, rcvbuf) != nil {
			_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, rcvbuf)
		}
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: cnIdxProc, Pid: 0}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("bind: %w", err)
	}
	if err := unix.Sendto(fd, listenMsg(), 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("subscribe: %w", err)
	}
	return &Conn{fd: fd}, nil
}

func socketIn(netnsPath string) (int, error) {
	type result struct {
		fd  int
		err error
	}
	ch := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		orig, err := os.Open("/proc/thread-self/ns/net")
		if err != nil {
			runtime.UnlockOSThread()
			ch <- result{-1, err}
			return
		}
		defer orig.Close()
		target, err := os.Open(netnsPath)
		if err != nil {
			runtime.UnlockOSThread()
			ch <- result{-1, err}
			return
		}
		defer target.Close()
		if err := unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
			runtime.UnlockOSThread()
			ch <- result{-1, fmt.Errorf("setns %s: %w", netnsPath, err)}
			return
		}
		fd, serr := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_CONNECTOR)
		if err := unix.Setns(int(orig.Fd()), unix.CLONE_NEWNET); err != nil {
			// The thread is in the wrong namespace. Leave it locked so the
			// runtime discards it when this goroutine returns.
			if serr == nil {
				ch <- result{fd, nil}
			} else {
				ch <- result{-1, serr}
			}
			return
		}
		runtime.UnlockOSThread()
		ch <- result{fd, serr}
	}()
	r := <-ch
	return r.fd, r.err
}

func listenMsg() []byte {
	b := make([]byte, nlmsgHdrLen+cnMsgLen+4)
	le := binary.LittleEndian
	le.PutUint32(b[0:], uint32(len(b)))
	le.PutUint16(b[4:], unix.NLMSG_DONE)
	le.PutUint32(b[12:], uint32(os.Getpid()))
	le.PutUint32(b[16:], cnIdxProc)
	le.PutUint32(b[20:], cnValProc)
	le.PutUint16(b[32:], 4)
	le.PutUint32(b[36:], procCnMcastListen)
	return b
}

// Read blocks for the next datagram and returns the events in it. ENOBUFS
// (the kernel dropped events) is counted in Overrun and, like EINTR, is not
// an error.
func (c *Conn) Read(buf []byte) ([]Event, error) {
	n, _, err := unix.Recvfrom(c.fd, buf, 0)
	if errors.Is(err, unix.EINTR) {
		return nil, nil
	}
	if errors.Is(err, unix.ENOBUFS) {
		c.Overrun.Add(1)
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return Parse(buf[:n]), nil
}

// Close closes the socket.
func (c *Conn) Close() error { return unix.Close(c.fd) }

// Parse decodes every netlink message in b. Unknown events are skipped.
func Parse(b []byte) []Event {
	var out []Event
	le := binary.LittleEndian
	for len(b) >= nlmsgHdrLen {
		l := int(le.Uint32(b[0:]))
		if l < nlmsgHdrLen || l > len(b) {
			break
		}
		msg := b[nlmsgHdrLen:l]
		if len(msg) >= cnMsgLen+evHdrLen && le.Uint32(msg[0:]) == cnIdxProc && le.Uint32(msg[4:]) == cnValProc {
			if ev, ok := parseEvent(msg[cnMsgLen:]); ok {
				out = append(out, ev)
			}
		}
		adv := (l + 3) &^ 3
		if adv >= len(b) {
			break
		}
		b = b[adv:]
	}
	return out
}

func parseEvent(p []byte) (Event, bool) {
	le := binary.LittleEndian
	what := le.Uint32(p[0:])
	d := p[evHdrLen:]
	u := func(i int) int { return int(le.Uint32(d[i*4:])) }
	switch what {
	case WhatFork:
		if len(d) < 16 {
			return Event{}, false
		}
		return Event{What: what, ParentPID: u(0), ParentTGID: u(1), PID: u(2), TGID: u(3)}, true
	case WhatExec:
		if len(d) < 8 {
			return Event{}, false
		}
		return Event{What: what, PID: u(0), TGID: u(1)}, true
	case WhatExit:
		if len(d) < 8 {
			return Event{}, false
		}
		return Event{What: what, PID: u(0), TGID: u(1)}, true
	}
	return Event{}, false
}
