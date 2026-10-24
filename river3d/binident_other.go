//go:build !unix

package main

import "os"

// Without a Stat_t there is no stable inode identity; hashes are then not cached
// and exe_dev / exe_ino stay zero. The classification rule itself is unaffected.
func fileInode(os.FileInfo) (dev, ino uint64, ok bool) { return 0, 0, false }
