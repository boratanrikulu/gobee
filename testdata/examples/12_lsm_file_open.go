//go:build ignore

// An LSM program on the file_open hook that allows everything. To make a
// real allow/deny decision, you'd reach into the hook's args via the
// bpf.ProbeReadKernel helpers and conditionally return bpf.LsmDeny.

package main

import "github.com/boratanrikulu/gobee/bpf"

//bpf:license GPL

//bpf:section lsm/file_open
func AllowFileOpen(ctx *bpf.LsmCtx) bpf.LsmReturn {
	return bpf.LsmAllow
}

func main() {}
