//go:build ignore

// Subscribes to the WRITE_HDR_OPT TCP callback. Reads
// `ctx.BpfSockOpsCbFlags` to preserve any flag another program already
// set, OR-s in BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG, and installs the
// new mask via bpf_sock_ops_cb_flags_set.

package main

import (
	"unsafe"

	"github.com/boratanrikulu/gobee/bpf"
)

//bpf:license GPL

//bpf:section sockops
func InstallWriteHdrCb(ctx *bpf.SockOpsMd) bpf.SockOpsReturn {
	var flags uint32 = ctx.BpfSockOpsCbFlags | bpf.BpfSockOpsWriteHdrOptCbFlag
	bpf.SockOpsCbFlagsSet(unsafe.Pointer(ctx), int32(flags))
	return bpf.SockOpsOk
}

func main() {}
