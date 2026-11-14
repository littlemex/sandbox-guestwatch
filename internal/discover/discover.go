// Package discover finds the containers in the guest. A container is a mount
// namespace other than the agent's own and the guest init's, whose cgroup is
// under the configured prefix (Kubernetes puts every container under
// /kubepods). Other namespaces, such as the guest's own system services, are
// treated as infrastructure and ignored. For each container it
// holds a directory fd on the container's root, opened through an anchor
// process, so that later path resolution never depends on that PID again.
package discover

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/littlemex/sandbox-guestwatch/internal/event"
	"github.com/littlemex/sandbox-guestwatch/internal/procinfo"
)

// Container is one discovered container. RootFD is an O_PATH directory fd on
// the container's root; it stays valid until every Listener's
// ContainerRemoved for this container has returned.
type Container struct {
	MntNS      uint64
	AnchorPID  int
	Anchor     string
	CgroupPath string
	CgroupID   uint64
	ID         string
	RootFD     int
}

// Identity returns the container identity carried by every event.
func (c *Container) Identity() *event.Container {
	return &event.Container{MntNS: c.MntNS, ID: c.ID, CgroupPath: c.CgroupPath, Anchor: c.Anchor}
}

// Listener is told about containers appearing and disappearing.
type Listener interface {
	ContainerAdded(*Container)
	ContainerRemoved(*Container)
}

// Registry is the set of live containers.
type Registry struct {
	proc, cgroupRoot string
	cgroupPrefix     string
	selfNS, initNS   uint64
	mu               sync.Mutex
	infra            map[uint64]bool
	byNS             map[uint64]*Container
	byCgroup         map[uint64]*Container
	listeners        []Listener
	rescan           chan struct{}
}

// New prepares a registry. It fails if the agent cannot read its own or the
// guest init's mount namespace, which means it is not running with hostPID.
func New(procRoot, cgroupRoot, cgroupPrefix string) (*Registry, error) {
	self, err := procinfo.NSInode(filepath.Join(procRoot, "self", "ns", "mnt"))
	if err != nil {
		return nil, err
	}
	init, err := procinfo.NSInode(filepath.Join(procRoot, "1", "ns", "mnt"))
	if err != nil {
		return nil, err
	}
	return &Registry{
		proc: procRoot, cgroupRoot: cgroupRoot, cgroupPrefix: cgroupPrefix, selfNS: self, initNS: init,
		infra: map[uint64]bool{}, byNS: map[uint64]*Container{}, byCgroup: map[uint64]*Container{},
		rescan: make(chan struct{}, 1),
	}, nil
}

// Subscribe registers l. Call before Scan.
func (r *Registry) Subscribe(l Listener) { r.listeners = append(r.listeners, l) }

// Ignored reports whether ns is the agent's, the guest init's, or a guest
// infrastructure namespace seen by the last scan.
func (r *Registry) Ignored(ns uint64) bool {
	if ns == r.selfNS || ns == r.initNS {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.infra[ns]
}

// ByNS returns the container for a mount namespace. An unknown, non-ignored
// namespace triggers a rescan.
func (r *Registry) ByNS(ns uint64) *Container {
	r.mu.Lock()
	c := r.byNS[ns]
	r.mu.Unlock()
	if c == nil && ns != 0 && !r.Ignored(ns) {
		r.RequestScan()
	}
	return c
}

// ByCgroup returns the container for a cgroup id.
func (r *Registry) ByCgroup(id uint64) *Container {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.byCgroup[id]
}

// Len is the number of live containers.
func (r *Registry) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.byNS)
}

// RequestScan asks the scan loop to run soon. It never blocks.
func (r *Registry) RequestScan() {
	select {
	case r.rescan <- struct{}{}:
	default:
	}
}

// Scan walks /proc once, adds new containers and removes vanished ones.
func (r *Registry) Scan() {
	live := map[uint64][]int{}
	ents, err := os.ReadDir(r.proc)
	if err != nil {
		return
	}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		ns, err := procinfo.NSInode(filepath.Join(r.proc, e.Name(), "ns", "mnt"))
		if err != nil || ns == r.selfNS || ns == r.initNS {
			continue
		}
		live[ns] = append(live[ns], pid)
	}

	var added, removed []*Container
	infra := map[uint64]bool{}
	r.mu.Lock()
	for ns, c := range r.byNS {
		pids, ok := live[ns]
		if ok && r.sameContainer(c, pids) {
			continue
		}
		// Gone, or the namespace inode was reused by a new container.
		delete(r.byNS, ns)
		if r.byCgroup[c.CgroupID] == c {
			delete(r.byCgroup, c.CgroupID)
		}
		removed = append(removed, c)
	}
	for ns, pids := range live {
		if _, ok := r.byNS[ns]; ok {
			continue
		}
		if r.infra[ns] {
			infra[ns] = true
			continue
		}
		sort.Ints(pids)
		for _, pid := range pids {
			c, err := r.open(ns, pid)
			if err == errInfra {
				infra[ns] = true
				break
			}
			if err == nil {
				r.byNS[ns] = c
				// A nested mount namespace (unshare, bubblewrap) shares its
				// container's cgroup; the first one keeps the entry.
				if _, taken := r.byCgroup[c.CgroupID]; c.CgroupID != 0 && !taken {
					r.byCgroup[c.CgroupID] = c
				}
				added = append(added, c)
				break
			}
		}
	}
	r.infra = infra
	r.mu.Unlock()

	for _, c := range removed {
		for _, l := range r.listeners {
			l.ContainerRemoved(c)
		}
		unix.Close(c.RootFD)
	}
	for _, c := range added {
		for _, l := range r.listeners {
			l.ContainerAdded(c)
		}
	}
}

// sameContainer reports whether a live process in the namespace still has the
// container's cgroup, which tells a reused namespace inode from the original.
func (r *Registry) sameContainer(c *Container, pids []int) bool {
	for _, pid := range pids {
		raw, err := os.ReadFile(filepath.Join(r.proc, strconv.Itoa(pid), "cgroup"))
		if err == nil {
			return ParseCgroupV2(string(raw)) == c.CgroupPath
		}
	}
	return true
}

// Run scans every interval and whenever RequestScan is called, but not more
// often than minGap, until ctx is done.
func (r *Registry) Run(ctx context.Context, interval, minGap time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	last := time.Time{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-r.rescan:
			if d := minGap - time.Since(last); d > 0 {
				select {
				case <-ctx.Done():
					return
				case <-time.After(d):
				}
			}
		}
		r.Scan()
		last = time.Now()
	}
}

// Close releases every root fd.
func (r *Registry) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.byNS {
		unix.Close(c.RootFD)
	}
	r.byNS, r.byCgroup = map[uint64]*Container{}, map[uint64]*Container{}
}

var runtimeID = regexp.MustCompile(`[0-9a-f]{64}`)

var errInfra = errors.New("not a container: cgroup outside the prefix")

func (r *Registry) open(ns uint64, pid int) (*Container, error) {
	dir := filepath.Join(r.proc, strconv.Itoa(pid))
	fd, err := unix.Open(filepath.Join(dir, "root"), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	// The pid may have been reused between reading ns/mnt and opening root.
	if again, err := procinfo.NSInode(filepath.Join(dir, "ns", "mnt")); err != nil || again != ns {
		unix.Close(fd)
		return nil, syscall.ESRCH
	}
	raw, err := os.ReadFile(filepath.Join(dir, "cgroup"))
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	c := &Container{MntNS: ns, AnchorPID: pid, RootFD: fd, CgroupPath: ParseCgroupV2(string(raw))}
	if !strings.HasPrefix(c.CgroupPath, r.cgroupPrefix) {
		unix.Close(fd)
		return nil, errInfra
	}
	c.ID = runtimeID.FindString(filepath.Base(c.CgroupPath))
	var st unix.Stat_t
	if unix.Stat(filepath.Join(r.cgroupRoot, c.CgroupPath), &st) == nil {
		c.CgroupID = st.Ino
	}
	if raw, err := os.ReadFile(filepath.Join(dir, "cmdline")); err == nil {
		c.Anchor = strings.Join(procinfo.SplitCmdline(raw), " ")
	}
	return c, nil
}

// ParseCgroupV2 returns the path of the "0::" line of /proc/<pid>/cgroup.
func ParseCgroupV2(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if p, ok := strings.CutPrefix(line, "0::"); ok {
			return p
		}
	}
	return ""
}
