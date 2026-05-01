//go:build ignore

// Emits an event on every execve syscall, carrying the PID and command
// name. Demonstrates `bpf.RingBuf[T]` with the typed Reserve / Submit
// pattern, plus a user-defined struct event payload.

package main

import "github.com/boratanrikulu/gobee/bpf"

//bpf:license GPL

type ExecEvent struct {
	Pid  uint32
	Comm [16]byte
}

var Events = bpf.RingBuf[ExecEvent]{MaxEntries: 4096}

//bpf:section tracepoint/syscalls/sys_enter_execve
func OnExec(ctx *bpf.TracepointCtx) bpf.TpReturn {
	e, ok := Events.Reserve()
	if !ok {
		return bpf.TpOk
	}
	e.Pid = uint32(bpf.GetCurrentPidTgid() >> 32)
	Events.Submit(e)
	return bpf.TpOk
}

func main() {}
