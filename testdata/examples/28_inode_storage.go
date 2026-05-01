//go:build ignore

// Per-inode storage. InodeStorage gives every `struct inode *` its own
// value slot — common in LSM hooks and file-related tracing. Kernel-
// sized, so no MaxEntries.

package main

import "github.com/boratanrikulu/gobee/bpf"

//bpf:license GPL

type FileStats struct {
	Opens uint64
}

var perInode = bpf.InodeStorage[FileStats]{}

//bpf:section lsm/file_open
func TrackOpen(ctx *bpf.LsmCtx) bpf.LsmReturn {
	return bpf.LsmAllow
}

func main() {}
