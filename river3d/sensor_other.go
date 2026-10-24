//go:build !(linux && (386 || amd64))

package main

// On anything but linux/amd64 (the Mac host, for one) there is no eBPF source; the
// Falco source is the way in. These stubs keep `go build` and `go test` working there.

import (
	"context"
	"errors"
	"time"
)

type sourceMode string

const (
	modeTracepoint sourceMode = "ebpf"
	modeLSM        sourceMode = "lsm"
)

type ebpfSource struct{}

var errNoBPFLSM = errors.New("the kernel has no active bpf LSM")

func bootClock() Clock { return Clock{wallAtBoot: time.Now().UTC()} }

func openEBPF(sourceMode) (*ebpfSource, error) {
	return nil, errors.New("the eBPF sensor only runs on linux/amd64; use -source falco here")
}

func (s *ebpfSource) Close()                                           {}
func (s *ebpfSource) Mode() sourceMode                                 { return modeTracepoint }
func (s *ebpfSource) setWatched(map[uint32]bool) error                 { return nil }
func (s *ebpfSource) setBlocked(map[inodeKey]bool) error               { return errNoBPFLSM }
func (s *ebpfSource) Run(context.Context, *Decoder, func(Event)) error { return nil }

const ebpfSupported = false
