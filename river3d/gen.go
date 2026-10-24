package main

// bpf2go compiles bpf/sensor.bpf.c for linux/amd64 with CO-RE relocations (the
// kernel struct layouts are resolved against the running kernel's BTF at load
// time). -type exports the two record types userspace reads: the ring-buffer
// `event` and the `blocked_inodes` key.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target amd64 -type event -type inode_key sensor bpf/sensor.bpf.c -- -O2 -g -Wall -Ibpf -D__TARGET_ARCH_x86
