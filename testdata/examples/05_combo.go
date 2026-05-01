//go:build ignore

// Combines several helpers in one program: per-PID histogram of packet
// inter-arrival times. The map value is a 64-bit "last seen" timestamp;
// each new packet computes a delta and we throw away the previous slot
// rather than maintain a real histogram (kept simple for the example).
// Demonstrates: two helpers in the same program, two maps, multiple
// branches.

package main

import "github.com/boratanrikulu/gobee/bpf"

//bpf:license GPL

var LastSeen = bpf.HashMap[uint32, uint64]{MaxEntries: 1024}

var DeltaNs = bpf.HashMap[uint32, uint64]{MaxEntries: 1024}

//bpf:section xdp
func InterArrival(ctx *bpf.XdpMd) bpf.XdpAction {
	var pidTgid uint64 = bpf.GetCurrentPidTgid()
	var pid uint32 = uint32(pidTgid >> 32)
	var now uint64 = bpf.KtimeGetNs()

	prev, ok := LastSeen.Lookup(&pid)
	LastSeen.Update(&pid, &now)
	if !ok {
		return bpf.XdpPass
	}
	var delta uint64 = now - *prev
	DeltaNs.Update(&pid, &delta)
	return bpf.XdpPass
}

func main() {}
