package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target amd64 -type event sensor bpf/sensor.bpf.c -- -O2 -g -Wall -Ibpf
