//go:build unix

package main

import (
	"os"
	"syscall"
)

// fileInode returns the (device, inode) pair that identifies a file independently
// of its name. It is the cache key for hashes and is reported in the event so two
// execs of the same file can be correlated.
func fileInode(fi os.FileInfo) (dev, ino uint64, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return 0, 0, false
	}
	return uint64(st.Dev), uint64(st.Ino), true
}
