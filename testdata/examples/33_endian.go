//go:build ignore

// Reads the remote port from a sock_ops context. The kernel exposes
// `bpf_sock_ops::remote_port` as a __be32, so converting to host byte
// order requires bpf_ntohl from <bpf/bpf_endian.h>.

package main

import "github.com/boratanrikulu/gobee/bpf"

//bpf:license GPL

//bpf:section sockops
func RecordRemotePort(ctx *bpf.SockOpsMd) bpf.SockOpsReturn {
	var port uint32 = bpf.Ntohl(ctx.RemotePort)
	if port == 0 {
		return bpf.SockOpsErr
	}
	return bpf.SockOpsOk
}

func main() {}
