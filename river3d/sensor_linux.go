//go:build linux && (386 || amd64)

package main

// The kernel sources: load the generated objects, attach either the six syscall
// tracepoints (-source ebpf) or the three BPF-LSM hooks (-source lsm), keep the
// `watched` and `blocked_inodes` maps in step with enrollment, and drain the ring
// buffer into the Decoder.

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// sourceMode names the attached program family.
type sourceMode string

const (
	modeTracepoint sourceMode = "ebpf"
	modeLSM        sourceMode = "lsm"
)

// tracepointObjs is the subset of the object file the tracepoint source needs.
// LoadAndAssign loads only what a struct references, which is what lets the LSM
// programs sit in the same object without being loaded on a kernel that cannot
// take them.
type tracepointObjs struct {
	EnterOpenat  *ebpf.Program `ebpf:"enter_openat"`
	ExitOpenat   *ebpf.Program `ebpf:"exit_openat"`
	EnterExecve  *ebpf.Program `ebpf:"enter_execve"`
	ExitExecve   *ebpf.Program `ebpf:"exit_execve"`
	EnterConnect *ebpf.Program `ebpf:"enter_connect"`
	ExitConnect  *ebpf.Program `ebpf:"exit_connect"`
	Events       *ebpf.Map     `ebpf:"events"`
	Watched      *ebpf.Map     `ebpf:"watched"`
	Inflight     *ebpf.Map     `ebpf:"inflight"`
	Scratch      *ebpf.Map     `ebpf:"scratch"`
}

// lsmObjs is the LSM subset. It leaves out `inflight` and `scratch` (LRU hash
// maps are preallocated, and the LSM hooks have no enter/exit pairing to keep).
type lsmObjs struct {
	FileOpen      *ebpf.Program `ebpf:"lsm_file_open"`
	BprmCheck     *ebpf.Program `ebpf:"lsm_bprm_check"`
	SocketConnect *ebpf.Program `ebpf:"lsm_socket_connect"`
	Events        *ebpf.Map     `ebpf:"events"`
	Watched       *ebpf.Map     `ebpf:"watched"`
	BlockedInodes *ebpf.Map     `ebpf:"blocked_inodes"`
}

type ebpfSource struct {
	mode    sourceMode
	events  *ebpf.Map
	watched *ebpf.Map
	blocked *ebpf.Map // nil in tracepoint mode
	closers []interface{ Close() error }
	links   []link.Link
	rd      *ringbuf.Reader
	lost    uint64
	bad     uint64
}

// bootClock computes wall time at monotonic zero so kernel timestamps map to wall time.
func bootClock() Clock {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return Clock{}
	}
	mono := time.Duration(ts.Sec)*time.Second + time.Duration(ts.Nsec)
	return Clock{wallAtBoot: time.Now().UTC().Add(-mono)}
}

// errNoBPFLSM says this kernel cannot run the LSM family; the caller falls back
// to tracepoints (contract §8) unless inline blocking was demanded. It covers
// three cases: "bpf" missing from the active LSM list, no BTF for the hooks
// (CONFIG_BPF_LSM off), and a kernel that refuses to load trampoline-based
// programs at all (EPERM before verification: seen on hardened VM kernels).
var errNoBPFLSM = errors.New("BPF-LSM programs cannot run on this kernel")

// lsmFile is where the kernel lists its active LSMs (securityfs).
var lsmFile = "/sys/kernel/security/lsm"

// bpfLSMActive reports whether "bpf" is among the active LSMs according to the
// given securityfs listing. The distinction matters because on a kernel built
// with CONFIG_BPF_LSM but booted without `lsm=...,bpf`, LSM programs LOAD and
// ATTACH without error and are simply never called: an enforcement sensor must
// not be fooled by that. unknown=true when the file cannot be read (securityfs not
// mounted); the caller then lets the load attempt decide.
func bpfLSMActive(listing []byte, err error) (active, unknown bool) {
	if err != nil {
		return false, true
	}
	for _, name := range strings.Split(strings.TrimSpace(string(listing)), ",") {
		if name == "bpf" {
			return true, false
		}
	}
	return false, false
}

func openEBPF(mode sourceMode) (*ebpfSource, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("memlock: %w", err)
	}
	spec, err := loadSensor()
	if err != nil {
		return nil, err
	}
	switch mode {
	case modeTracepoint:
		return openTracepoints(spec)
	case modeLSM:
		return openLSM(spec)
	}
	return nil, fmt.Errorf("unknown source mode %q", mode)
}

func verifierErr(err error, what string) error {
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		return fmt.Errorf("verifier rejected %s: %+v", what, ve)
	}
	return fmt.Errorf("load %s: %w", what, err)
}

func openTracepoints(spec *ebpf.CollectionSpec) (*ebpfSource, error) {
	var o tracepointObjs
	if err := spec.LoadAndAssign(&o, nil); err != nil {
		return nil, verifierErr(err, "the tracepoint sensor")
	}
	s := &ebpfSource{mode: modeTracepoint, events: o.Events, watched: o.Watched}
	s.closers = []interface{ Close() error }{o.EnterOpenat, o.ExitOpenat, o.EnterExecve, o.ExitExecve, o.EnterConnect, o.ExitConnect, o.Events, o.Watched, o.Inflight, o.Scratch}
	attach := []struct {
		name string
		prog *ebpf.Program
	}{
		{"sys_enter_openat", o.EnterOpenat}, {"sys_exit_openat", o.ExitOpenat},
		{"sys_enter_execve", o.EnterExecve}, {"sys_exit_execve", o.ExitExecve},
		{"sys_enter_connect", o.EnterConnect}, {"sys_exit_connect", o.ExitConnect},
	}
	for _, a := range attach {
		l, err := link.Tracepoint("syscalls", a.name, a.prog, nil)
		if err != nil {
			s.Close()
			return nil, fmt.Errorf("attach %s: %w", a.name, err)
		}
		s.links = append(s.links, l)
	}
	return s.openRing()
}

func openLSM(spec *ebpf.CollectionSpec) (*ebpfSource, error) {
	listing, err := os.ReadFile(lsmFile)
	if active, unknown := bpfLSMActive(listing, err); !active && !unknown {
		return nil, fmt.Errorf("%w: %s lists %q, no bpf", errNoBPFLSM, lsmFile, strings.TrimSpace(string(listing)))
	}
	var o lsmObjs
	if err := spec.LoadAndAssign(&o, nil); err != nil {
		// No BTF for bpf_lsm_file_open, or no CONFIG_BPF_LSM: ENOENT/EINVAL/ENOTSUPP
		// from the kernel. A verifier rejection is a bug in our program, not a
		// missing kernel feature, and must surface as such.
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, verifierErr(err, "the LSM sensor")
		}
		return nil, fmt.Errorf("%w: load: %v", errNoBPFLSM, err)
	}
	s := &ebpfSource{mode: modeLSM, events: o.Events, watched: o.Watched, blocked: o.BlockedInodes}
	s.closers = []interface{ Close() error }{o.FileOpen, o.BprmCheck, o.SocketConnect, o.Events, o.Watched, o.BlockedInodes}
	for _, p := range []struct {
		name string
		prog *ebpf.Program
	}{{"file_open", o.FileOpen}, {"bprm_check_security", o.BprmCheck}, {"socket_connect", o.SocketConnect}} {
		l, err := link.AttachLSM(link.LSMOptions{Program: p.prog})
		if err != nil {
			s.Close()
			return nil, fmt.Errorf("%w: attach lsm/%s: %v", errNoBPFLSM, p.name, err)
		}
		s.links = append(s.links, l)
	}
	return s.openRing()
}

func (s *ebpfSource) openRing() (*ebpfSource, error) {
	rd, err := ringbuf.NewReader(s.events)
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("ring buffer: %w", err)
	}
	s.rd = rd
	return s, nil
}

func (s *ebpfSource) Close() {
	if s.rd != nil {
		s.rd.Close()
	}
	for _, l := range s.links {
		l.Close()
	}
	for _, c := range s.closers {
		if c != nil {
			c.Close()
		}
	}
}

// Mode reports which program family is attached.
func (s *ebpfSource) Mode() sourceMode { return s.mode }

// setWatched makes the kernel map equal to `desired`: add what is missing, remove
// what is no longer enrolled (a restarted container's old namespace, for instance).
func (s *ebpfSource) setWatched(desired map[uint32]bool) error {
	present := map[uint32]bool{}
	var k uint32
	var v uint8
	it := s.watched.Iterate()
	for it.Next(&k, &v) {
		present[k] = true
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("iterate watched: %w", err)
	}
	for ns := range desired {
		if !present[ns] {
			if err := s.watched.Put(ns, uint8(1)); err != nil {
				return fmt.Errorf("watch %d: %w", ns, err)
			}
		}
	}
	for ns := range present {
		if !desired[ns] {
			if err := s.watched.Delete(ns); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				return fmt.Errorf("unwatch %d: %w", ns, err)
			}
		}
	}
	return nil
}

// setBlocked makes `blocked_inodes` equal to `desired` with the same add/remove
// discipline as setWatched. Only the LSM source has the map.
func (s *ebpfSource) setBlocked(desired map[inodeKey]bool) error {
	if s.blocked == nil {
		return errors.New("inline blocking needs -source lsm")
	}
	present := map[inodeKey]bool{}
	var k sensorInodeKey
	var v uint8
	it := s.blocked.Iterate()
	for it.Next(&k, &v) {
		present[inodeKey{Dev: k.Dev, Ino: k.Ino, Mntns: k.Mntns}] = true
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("iterate blocked_inodes: %w", err)
	}
	for key := range desired {
		if !present[key] {
			if err := s.blocked.Put(sensorInodeKey{Dev: key.Dev, Ino: key.Ino, Mntns: key.Mntns}, uint8(1)); err != nil {
				return fmt.Errorf("block %+v: %w", key, err)
			}
		}
	}
	for key := range present {
		if !desired[key] {
			if err := s.blocked.Delete(sensorInodeKey{Dev: key.Dev, Ino: key.Ino, Mntns: key.Mntns}); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				return fmt.Errorf("unblock %+v: %w", key, err)
			}
		}
	}
	return nil
}

// Run drains the ring buffer until ctx ends.
func (s *ebpfSource) Run(ctx context.Context, dec *Decoder, emit func(Event)) error {
	go func() {
		<-ctx.Done()
		s.rd.Close() // unblocks Read
	}()
	for {
		rec, err := s.rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("ring buffer read: %w", err)
		}
		var raw sensorEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &raw); err != nil {
			s.bad++
			continue
		}
		if ev, ok := dec.Decode(fromRaw(raw)); ok {
			emit(ev)
		}
	}
}

func fromRaw(r sensorEvent) kernelEvent {
	k := kernelEvent{
		EnterNs: r.EnterNs, ExitNs: r.ExitNs, Ret: r.Ret, Type: r.Type, Pid: r.Pid, Tgid: r.Tgid, Ppid: r.Ppid,
		Uid: r.Uid, Mntns: r.Mntns, Flags: r.Flags, Family: r.Family, Port: r.Port, Addr: r.Addr,
		Comm: cstr(r.Comm[:]), Path: cstr(r.Path[:]),
		Dev: r.Dev, Ino: r.Ino, Inline: r.Lsm != 0,
	}
	for i := range r.Args {
		a := cstr(r.Args[i][:])
		if a == "" {
			break
		}
		k.Args = append(k.Args, a)
	}
	return k
}

const ebpfSupported = true
