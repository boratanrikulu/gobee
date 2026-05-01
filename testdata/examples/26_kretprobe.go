//go:build ignore

// Kretprobe on tcp_connect — fires when the function returns. Useful for
// surfacing return values that aren't visible at function entry.

package main

import "github.com/boratanrikulu/gobee/bpf"

//bpf:license GPL

var connectFailures = bpf.HashMap[uint32, uint64]{MaxEntries: 1024}

//bpf:section kretprobe/tcp_connect
func OnTcpConnectReturn(ctx *bpf.PtRegs) bpf.KpReturn {
	var pid uint32 = bpf.GetCurrentPid()
	count, ok := connectFailures.Lookup(&pid)
	if !ok {
		var one uint64 = 1
		connectFailures.Update(&pid, &one)
		return bpf.KpOk
	}
	bpf.AtomicAdd64(count, 1)
	return bpf.KpOk
}

func main() {}
