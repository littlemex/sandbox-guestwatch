// Package filewatch watches directories inside each container with inotify.
//
// A configured directory is resolved with openat2(RESOLVE_IN_ROOT) against the
// container's root directory fd, so a symlink inside the image (for example
// /bin -> usr/bin) resolves inside the container and never in the agent's own
// file system. Below a configured directory, every child is opened relative to
// its parent's fd with RESOLVE_BENEATH and RESOLVE_NO_SYMLINKS, so the
// workload cannot steer the walk elsewhere by swapping a directory for a
// symlink.
//
// Limits: watches are global to the inotify instance, so a directory shared by
// two containers (the same volume) is reported for the container that was
// watched first, and the watch cap is shared by all containers.
package filewatch

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"github.com/littlemex/sandbox-guestwatch/internal/discover"
	"github.com/littlemex/sandbox-guestwatch/internal/event"
)

const mask = unix.IN_CREATE | unix.IN_CLOSE_WRITE | unix.IN_MOVED_TO | unix.IN_MOVED_FROM |
	unix.IN_ATTRIB | unix.IN_DELETE | unix.IN_ONLYDIR

// Handler receives one file event for a container.
type Handler func(*discover.Container, event.File)

type watch struct {
	c    *discover.Container
	path string
}

// Watcher is one inotify instance shared by all containers.
type Watcher struct {
	fd       int
	dirs     []string
	max      int
	maxDepth int
	coalesce time.Duration
	handle   Handler

	mu         sync.Mutex
	wds        map[int32]watch
	containers map[uint64]*discover.Container
	recent     map[string]time.Time
	lastPrune  time.Time

	Overflows   atomic.Uint64
	CapHits     atomic.Uint64
	AddFailures atomic.Uint64
}

// New creates the inotify instance. dirs is in priority order.
func New(dirs []string, maxWatches, maxDepth int, coalesce time.Duration, h Handler) (*Watcher, error) {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC)
	if err != nil {
		return nil, err
	}
	return &Watcher{
		fd: fd, dirs: dirs, max: maxWatches, maxDepth: maxDepth, coalesce: coalesce, handle: h,
		wds: map[int32]watch{}, containers: map[uint64]*discover.Container{}, recent: map[string]time.Time{},
	}, nil
}

// Watches is the number of active watches.
func (w *Watcher) Watches() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.wds)
}

// ContainerAdded adds watches for every configured directory of c.
func (w *Watcher) ContainerAdded(c *discover.Container) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.containers[c.MntNS] = c
	w.watchConfigured(c, false)
}

// ContainerRemoved drops c's watches.
func (w *Watcher) ContainerRemoved(c *discover.Container) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.dropWhere(func(ww watch) bool { return ww.c == c })
	if w.containers[c.MntNS] == c {
		delete(w.containers, c.MntNS)
	}
}

// watchConfigured walks every configured directory of c. Caller holds w.mu.
func (w *Watcher) watchConfigured(c *discover.Container, rescan bool) {
	for _, d := range w.dirs {
		fd, err := unix.Openat2(c.RootFD, d, &unix.OpenHow{
			Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
			Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
		})
		if err != nil {
			w.countOpenErr(err)
			continue
		}
		w.walk(c, fd, d, 0, rescan)
	}
}

// dropWhere removes every watch matching f. Caller holds w.mu.
func (w *Watcher) dropWhere(f func(watch) bool) {
	for wd, ww := range w.wds {
		if f(ww) {
			unix.InotifyRmWatch(w.fd, uint32(wd))
			delete(w.wds, wd)
		}
	}
}

func (w *Watcher) countOpenErr(err error) {
	if !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ENOTDIR) {
		w.AddFailures.Add(1)
	}
}

// walk watches the directory open at fd (named dir in the container's view)
// and, recursively, its subdirectories. It takes ownership of fd. With
// rescan set, entries found are reported as creates: they appeared before the
// watch existed. Caller holds w.mu.
func (w *Watcher) walk(c *discover.Container, fd int, dir string, depth int, rescan bool) {
	f := os.NewFile(uintptr(fd), dir)
	defer f.Close()
	if len(w.wds) >= w.max {
		w.CapHits.Add(1)
		return
	}
	wd, err := unix.InotifyAddWatch(w.fd, "/proc/self/fd/"+strconv.Itoa(fd), mask)
	if err != nil {
		w.AddFailures.Add(1)
		return
	}
	if old, dup := w.wds[int32(wd)]; dup && (old.c != c || old.path != dir) {
		// The same directory reached again: by another configured path (/bin
		// and /usr/bin), or by another container sharing a volume. The first
		// owner, which is the higher-priority path, keeps the watch.
		return
	}
	w.wds[int32(wd)] = watch{c: c, path: dir}
	if depth >= w.maxDepth {
		return
	}
	ents, err := f.ReadDir(-1)
	if err != nil {
		return
	}
	for _, e := range ents {
		p := path.Join(dir, e.Name())
		if rescan {
			w.send(c, event.File{Path: p, Op: event.OpCreate, Rescan: true})
		}
		if !e.IsDir() {
			continue
		}
		child, err := openChild(fd, e.Name())
		if err != nil {
			w.countOpenErr(err)
			continue
		}
		w.walk(c, child, p, depth+1, rescan)
	}
}

func openChild(parent int, name string) (int, error) {
	return unix.Openat2(parent, name, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
}

// send applies coalescing and hands the event on. Caller holds w.mu.
func (w *Watcher) send(c *discover.Container, f event.File) {
	now := time.Now()
	key := strconv.FormatUint(c.MntNS, 10) + "|" + f.Op + "|" + f.Path
	if t, ok := w.recent[key]; ok && now.Sub(t) < w.coalesce {
		return
	}
	w.recent[key] = now
	if now.Sub(w.lastPrune) >= w.coalesce {
		for k, t := range w.recent {
			if now.Sub(t) >= w.coalesce {
				delete(w.recent, k)
			}
		}
		w.lastPrune = now
	}
	w.handle(c, f)
}

// OpName maps an inotify mask to the reported operation.
func OpName(m uint32) string {
	switch {
	case m&unix.IN_CREATE != 0:
		return event.OpCreate
	case m&unix.IN_CLOSE_WRITE != 0:
		return event.OpWrite
	case m&unix.IN_MOVED_TO != 0:
		return event.OpMovedTo
	case m&unix.IN_MOVED_FROM != 0:
		return event.OpMovedFrom
	case m&unix.IN_ATTRIB != 0:
		return event.OpAttrib
	case m&unix.IN_DELETE != 0:
		return event.OpDelete
	}
	return ""
}

// RawEvent is one inotify record.
type RawEvent struct {
	WD   int32
	Mask uint32
	Name string
}

// ParseEvents decodes a buffer filled by read(2) on an inotify fd.
func ParseEvents(b []byte) []RawEvent {
	var out []RawEvent
	for len(b) >= unix.SizeofInotifyEvent {
		wd := int32(binary.LittleEndian.Uint32(b[0:]))
		m := binary.LittleEndian.Uint32(b[4:])
		n := int(binary.LittleEndian.Uint32(b[12:]))
		if unix.SizeofInotifyEvent+n > len(b) {
			break
		}
		name := b[unix.SizeofInotifyEvent : unix.SizeofInotifyEvent+n]
		if i := bytes.IndexByte(name, 0); i >= 0 {
			name = name[:i]
		}
		out = append(out, RawEvent{WD: wd, Mask: m, Name: string(name)})
		b = b[unix.SizeofInotifyEvent+n:]
	}
	return out
}

// Run reads events until the fd is closed or fails.
func (w *Watcher) Run() error {
	buf := make([]byte, 64*1024)
	for {
		n, err := unix.Read(w.fd, buf)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		if n <= 0 {
			return nil
		}
		for _, ev := range ParseEvents(buf[:n]) {
			w.dispatch(ev)
		}
	}
}

func (w *Watcher) dispatch(ev RawEvent) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if ev.Mask&unix.IN_Q_OVERFLOW != 0 {
		// Events were lost, possibly including directory creations. Walk
		// every container again so new directories get watches.
		w.Overflows.Add(1)
		for _, c := range w.containers {
			w.watchConfigured(c, false)
		}
		return
	}
	ww, ok := w.wds[ev.WD]
	if !ok {
		return
	}
	if ev.Mask&unix.IN_IGNORED != 0 {
		delete(w.wds, ev.WD)
		return
	}
	op := OpName(ev.Mask)
	if op == "" || ev.Name == "" {
		return
	}
	p := path.Join(ww.path, ev.Name)
	w.send(ww.c, event.File{Path: p, Op: op})
	if ev.Mask&unix.IN_ISDIR == 0 {
		return
	}
	switch {
	case ev.Mask&unix.IN_MOVED_FROM != 0:
		// The subtree now lives elsewhere; its watches carry stale paths.
		w.dropWhere(func(x watch) bool { return x.c == ww.c && (x.path == p || strings.HasPrefix(x.path, p+"/")) })
	case ev.Mask&(unix.IN_CREATE|unix.IN_MOVED_TO) != 0:
		fd, err := unix.Openat2(ww.c.RootFD, ww.path, &unix.OpenHow{
			Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
			Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
		})
		if err != nil {
			w.countOpenErr(err)
			return
		}
		child, err := openChild(fd, ev.Name)
		unix.Close(fd)
		if err != nil {
			w.countOpenErr(err)
			return
		}
		depth := strings.Count(p, "/")
		w.walk(ww.c, child, p, depth, true)
	}
}
