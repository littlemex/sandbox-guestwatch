// Package netmon attaches cgroup sock_addr programs at the cgroup v2 root and
// reads one record per connect() or UDP sendmsg() from a ring buffer. The
// programs are built with the Go assembler and need no BTF and no C toolchain.
// Every program returns 1, so nothing is ever blocked.
package netmon

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

// Hook identifies which program produced a record.
type Hook uint8

const (
	HookConnect4 Hook = iota
	HookConnect6
	HookSendmsg4
	HookSendmsg6
)

// Connect reports whether the hook is a connect (as opposed to a datagram send).
func (h Hook) Connect() bool { return h == HookConnect4 || h == HookConnect6 }

// Record layout written by the programs. Offsets are part of the contract
// between the assembler below and Decode. The time, thread id and socket
// family are written for debugging with bpftool but not decoded.
const (
	offTime     = 0
	offCgroup   = 8
	offPID      = 16
	offTID      = 20
	offUID      = 24
	offFamily   = 28
	offHook     = 30
	offProto    = 32
	offType     = 36
	offPort     = 40
	offAddr     = 44
	offComm     = 60
	commLen     = 16
	recordBytes = 80
)

// Offsets in struct bpf_sock_addr (include/uapi/linux/bpf.h).
const (
	ctxUserFamily = 0
	ctxUserIP4    = 4
	ctxUserIP6    = 8
	ctxUserPort   = 24
	ctxType       = 32
	ctxProtocol   = 36
)

// Record is one decoded ring buffer entry.
type Record struct {
	CgroupID uint64
	PID      int
	UID      int
	Hook     Hook
	Proto    int
	SockType int
	Dst      netip.Addr
	Port     int
	Comm     string
}

// Decode parses one raw record. IPv4-mapped IPv6 destinations are unmapped.
func Decode(b []byte) (Record, error) {
	if len(b) < offComm+commLen {
		return Record{}, fmt.Errorf("short record: %d bytes", len(b))
	}
	le := binary.LittleEndian
	r := Record{
		CgroupID: le.Uint64(b[offCgroup:]),
		PID:      int(le.Uint32(b[offPID:])),
		UID:      int(le.Uint32(b[offUID:])),
		Hook:     Hook(b[offHook]),
		Proto:    int(le.Uint32(b[offProto:])),
		SockType: int(le.Uint32(b[offType:])),
		Port:     int(binary.BigEndian.Uint16(b[offPort:])),
	}
	switch r.Hook {
	case HookConnect4, HookSendmsg4:
		r.Dst = netip.AddrFrom4([4]byte(b[offAddr : offAddr+4]))
	default:
		r.Dst = netip.AddrFrom16([16]byte(b[offAddr : offAddr+16])).Unmap()
	}
	comm := b[offComm : offComm+commLen]
	if i := bytes.IndexByte(comm, 0); i >= 0 {
		comm = comm[:i]
	}
	r.Comm = string(comm)
	return r, nil
}

// ProtoName returns "tcp", "udp" or the number.
func (r Record) ProtoName() string {
	switch {
	case r.Proto == unix.IPPROTO_TCP || (r.Proto == 0 && r.SockType == unix.SOCK_STREAM):
		return "tcp"
	case r.Proto == unix.IPPROTO_UDP || (r.Proto == 0 && r.SockType == unix.SOCK_DGRAM):
		return "udp"
	}
	return fmt.Sprint(r.Proto)
}

// Monitor owns the maps, programs, links and reader.
type Monitor struct {
	events, drops *ebpf.Map
	progs         []*ebpf.Program
	links         []link.Link
	rd            *ringbuf.Reader
}

// Open creates the maps and programs and attaches them at cgroupRoot, which
// must be the root of a cgroup v2 hierarchy. ringBytes must be a power of two
// and a multiple of the page size.
func Open(cgroupRoot string, ringBytes uint32) (*Monitor, error) {
	if err := checkCgroupRoot(cgroupRoot); err != nil {
		return nil, err
	}
	m := &Monitor{}
	var err error
	m.events, err = ebpf.NewMap(&ebpf.MapSpec{Name: "gw_events", Type: ebpf.RingBuf, MaxEntries: ringBytes})
	if err != nil {
		return nil, fmt.Errorf("ring buffer: %w", err)
	}
	m.drops, err = ebpf.NewMap(&ebpf.MapSpec{Name: "gw_drops", Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1})
	if err != nil {
		m.Close()
		return nil, fmt.Errorf("drop counter: %w", err)
	}
	hooks := []struct {
		hook   Hook
		attach ebpf.AttachType
	}{
		{HookConnect4, ebpf.AttachCGroupInet4Connect},
		{HookConnect6, ebpf.AttachCGroupInet6Connect},
		{HookSendmsg4, ebpf.AttachCGroupUDP4Sendmsg},
		{HookSendmsg6, ebpf.AttachCGroupUDP6Sendmsg},
	}
	for _, h := range hooks {
		p, err := ebpf.NewProgram(&ebpf.ProgramSpec{
			Name:         fmt.Sprintf("gw_hook%d", h.hook),
			Type:         ebpf.CGroupSockAddr,
			AttachType:   h.attach,
			Instructions: program(h.hook, m.events.FD(), m.drops.FD()),
			License:      "Apache-2.0",
		})
		if err != nil {
			m.Close()
			return nil, fmt.Errorf("load hook %d: %w", h.hook, err)
		}
		m.progs = append(m.progs, p)
		l, err := link.AttachCgroup(link.CgroupOptions{Path: cgroupRoot, Attach: h.attach, Program: p})
		if err != nil {
			m.Close()
			return nil, fmt.Errorf("attach hook %d: %w", h.hook, err)
		}
		m.links = append(m.links, l)
	}
	m.rd, err = ringbuf.NewReader(m.events)
	if err != nil {
		m.Close()
		return nil, err
	}
	return m, nil
}

func checkCgroupRoot(path string) error {
	var fs unix.Statfs_t
	if err := unix.Statfs(path, &fs); err != nil {
		return err
	}
	if fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return fmt.Errorf("%s is not cgroup2", path)
	}
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return err
	}
	if st.Ino != 1 {
		return fmt.Errorf("%s is not the cgroup root (inode %d)", path, st.Ino)
	}
	return nil
}

// Read blocks for the next record. It returns ringbuf.ErrClosed after Close.
func (m *Monitor) Read() (Record, error) {
	rec, err := m.rd.Read()
	if err != nil {
		return Record{}, err
	}
	return Decode(rec.RawSample)
}

// Drops is the number of records the programs could not reserve.
func (m *Monitor) Drops() uint64 {
	var v uint64
	if m.drops == nil || m.drops.Lookup(uint32(0), &v) != nil {
		return 0
	}
	return v
}

// IsClosed reports whether err means the monitor was closed.
func IsClosed(err error) bool { return errors.Is(err, ringbuf.ErrClosed) }

// Close detaches everything.
func (m *Monitor) Close() {
	if m.rd != nil {
		m.rd.Close()
	}
	for _, l := range m.links {
		l.Close()
	}
	for _, p := range m.progs {
		p.Close()
	}
	if m.events != nil {
		m.events.Close()
	}
	if m.drops != nil {
		m.drops.Close()
	}
}

// program returns the instructions for one hook. Register use:
// R6 = ctx, R7 = reserved record.
func program(h Hook, ringFD, dropsFD int) asm.Instructions {
	ins := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.LoadMapPtr(asm.R1, ringFD),
		asm.Mov.Imm(asm.R2, recordBytes),
		asm.Mov.Imm(asm.R3, 0),
		asm.FnRingbufReserve.Call(),
		asm.JEq.Imm(asm.R0, 0, "drop"),
		asm.Mov.Reg(asm.R7, asm.R0),

		asm.FnKtimeGetNs.Call(),
		asm.StoreMem(asm.R7, offTime, asm.R0, asm.DWord),
		asm.FnGetCurrentCgroupId.Call(),
		asm.StoreMem(asm.R7, offCgroup, asm.R0, asm.DWord),
		asm.FnGetCurrentPidTgid.Call(),
		asm.StoreMem(asm.R7, offTID, asm.R0, asm.Word),
		asm.RSh.Imm(asm.R0, 32),
		asm.StoreMem(asm.R7, offPID, asm.R0, asm.Word),
		asm.FnGetCurrentUidGid.Call(),
		asm.StoreMem(asm.R7, offUID, asm.R0, asm.Word),

		asm.LoadMem(asm.R1, asm.R6, ctxUserFamily, asm.Word),
		asm.StoreMem(asm.R7, offFamily, asm.R1, asm.Half),
		asm.StoreImm(asm.R7, offHook, int64(h), asm.Byte),
		asm.StoreImm(asm.R7, offHook+1, 0, asm.Byte),
		asm.LoadMem(asm.R1, asm.R6, ctxProtocol, asm.Word),
		asm.StoreMem(asm.R7, offProto, asm.R1, asm.Word),
		asm.LoadMem(asm.R1, asm.R6, ctxType, asm.Word),
		asm.StoreMem(asm.R7, offType, asm.R1, asm.Word),
		asm.LoadMem(asm.R1, asm.R6, ctxUserPort, asm.Word),
		asm.StoreMem(asm.R7, offPort, asm.R1, asm.Word),
	}
	if h == HookConnect4 || h == HookSendmsg4 {
		ins = append(ins,
			asm.LoadMem(asm.R1, asm.R6, ctxUserIP4, asm.Word),
			asm.StoreMem(asm.R7, offAddr, asm.R1, asm.Word),
			asm.StoreImm(asm.R7, offAddr+4, 0, asm.Word),
			asm.StoreImm(asm.R7, offAddr+8, 0, asm.Word),
			asm.StoreImm(asm.R7, offAddr+12, 0, asm.Word),
		)
	} else {
		for i := int16(0); i < 4; i++ {
			ins = append(ins,
				asm.LoadMem(asm.R1, asm.R6, ctxUserIP6+4*i, asm.Word),
				asm.StoreMem(asm.R7, offAddr+4*i, asm.R1, asm.Word),
			)
		}
	}
	ins = append(ins,
		asm.Mov.Reg(asm.R1, asm.R7),
		asm.Add.Imm(asm.R1, offComm),
		asm.Mov.Imm(asm.R2, commLen),
		asm.FnGetCurrentComm.Call(),
		asm.Mov.Reg(asm.R1, asm.R7),
		asm.Mov.Imm(asm.R2, 0),
		asm.FnRingbufSubmit.Call(),
		asm.Ja.Label("out"),

		asm.StoreImm(asm.R10, -4, 0, asm.Word).WithSymbol("drop"),
		asm.LoadMapPtr(asm.R1, dropsFD),
		asm.Mov.Reg(asm.R2, asm.R10),
		asm.Add.Imm(asm.R2, -4),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "out"),
		asm.Mov.Imm(asm.R1, 1),
		asm.StoreXAdd(asm.R0, asm.R1, asm.DWord),

		asm.Mov.Imm(asm.R0, 1).WithSymbol("out"),
		asm.Return(),
	)
	return ins
}
