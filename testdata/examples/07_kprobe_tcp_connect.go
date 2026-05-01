//go:build ignore

// Counts every kernel-side tcp_connect() call. Demonstrates the kprobe
// program type, no ctx-field access (pre-CO-RE friendly), and probe
// programs returning 0.

package main

import "github.com/boratanrikulu/gobee/bpf"

//bpf:license GPL

var Connects = bpf.ArrayMap[uint32, uint64]{MaxEntries: 1}

//bpf:section kprobe/tcp_connect
func TcpConnectEntry(ctx *bpf.PtRegs) bpf.KpReturn {
	var key uint32 = 0
	count, ok := Connects.Lookup(&key)
	if !ok {
		return bpf.KpOk
	}
	bpf.AtomicAdd64(count, 1)
	return bpf.KpOk
}

func main() {}
