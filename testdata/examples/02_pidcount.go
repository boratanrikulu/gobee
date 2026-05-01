//go:build ignore

// Counts packets per PID using a HashMap keyed by the upper 32 bits of
// bpf_get_current_pid_tgid (the PID, not the TID). Demonstrates: a 64-bit
// helper return value used in arithmetic, HashMap with comma-ok lookup,
// auto-translated atomic add on a map value pointer.

package main

import "github.com/boratanrikulu/gobee/bpf"

//bpf:license GPL

var PerPid = bpf.HashMap[uint32, uint64]{MaxEntries: 1024}

//bpf:section xdp
func CountByPid(ctx *bpf.XdpMd) bpf.XdpAction {
	var pidTgid uint64 = bpf.GetCurrentPidTgid()
	var pid uint32 = uint32(pidTgid >> 32)
	count, ok := PerPid.Lookup(&pid)
	if !ok {
		var one uint64 = 1
		PerPid.Update(&pid, &one)
		return bpf.XdpPass
	}
	bpf.AtomicAdd64(count, 1)
	return bpf.XdpPass
}

func main() {}
