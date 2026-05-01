//go:build ignore

package main

import "github.com/boratanrikulu/gobee/bpf"

//bpf:license GPL

// Event is the tagged payload all event-driven programs publish to the
// ringbuf. Field layout uses only 4-byte-aligned types so Go's
// binary.Read on the userspace side and clang's struct layout in the
// kernel agree without padding surprises.
type Event struct {
	TimeNsHi uint32
	TimeNsLo uint32
	Pid      uint32
	Uid      uint32
	Kind     uint32 // 1=exec, 2=open, 3=tcp_connect, 4=exec_failed, 5=proc_exit
	Ret      int32  // exec_failed: -errno from execve. proc_exit: process exit status. zero otherwise.
	Comm     [16]byte
	Path     [128]byte
	Args     [256]byte // exec argv only; zero for other kinds
}

const (
	kindExec       = uint32(1)
	kindOpen       = uint32(2)
	kindTcpConnect = uint32(3)
	kindExecFailed = uint32(4)
	kindProcExit   = uint32(5)
)

// All event-driven programs share one ringbuf.
var events = bpf.RingBuf[Event]{MaxEntries: 65536}

// XDP program writes packet counts here, keyed by ingress ifindex. The
// userspace driver polls this map periodically.
var packetsByIface = bpf.HashMap[uint32, uint64]{MaxEntries: 64}

// fillHeader sets every field of e that's the same for every kind of
// event: timestamp, pid, uid, comm, kind. Inlined into each section
// program by the BPF verifier so there's no call overhead.
func fillHeader(e *Event, kind uint32) {
	var ts uint64 = bpf.KtimeGetNs()
	e.TimeNsHi = uint32(ts >> 32)
	e.TimeNsLo = uint32(ts)
	e.Pid = bpf.GetCurrentPid()
	e.Uid = bpf.GetCurrentUid()
	e.Kind = kind
	bpf.GetTaskComm(&e.Comm)
}

//bpf:section xdp
func OnPacket(ctx *bpf.XdpMd) bpf.XdpAction {
	var idx uint32 = ctx.IngressIfIndex
	count, ok := packetsByIface.Lookup(&idx)
	if !ok {
		var one uint64 = 1
		packetsByIface.Update(&idx, &one)
		return bpf.XdpPass
	}
	bpf.AtomicAdd64(count, 1)
	return bpf.XdpPass
}

//bpf:section tracepoint/syscalls/sys_enter_execve
func OnExec(ctx *bpf.ExecveEnterCtx) bpf.TpReturn {
	e, ok := events.Reserve()
	if !ok {
		return bpf.TpOk
	}
	fillHeader(e, kindExec)
	bpf.GetUserString(&e.Path, ctx.Filename)
	bpf.GetUserArgv(&e.Args, ctx.Argv)
	events.Submit(e)
	return bpf.TpOk
}

//bpf:section tracepoint/syscalls/sys_enter_openat
func OnOpen(ctx *bpf.OpenatEnterCtx) bpf.TpReturn {
	e, ok := events.Reserve()
	if !ok {
		return bpf.TpOk
	}
	fillHeader(e, kindOpen)
	bpf.GetUserString(&e.Path, ctx.Filename)
	events.Submit(e)
	return bpf.TpOk
}

//bpf:section kprobe/tcp_connect
func OnTcpConnect(ctx *bpf.PtRegs) bpf.KpReturn {
	e, ok := events.Reserve()
	if !ok {
		return bpf.KpOk
	}
	fillHeader(e, kindTcpConnect)
	events.Submit(e)
	return bpf.KpOk
}

// OnProcExit fires when a process calls exit_group(N). Args[0] is the
// exit status (curl=6 if it can't resolve a host, etc.). Doesn't catch
// signal-based deaths (SIGKILL, SIGSEGV) — those need sched_process_exit
// plus CO-RE access to task->exit_code.
//bpf:section tracepoint/syscalls/sys_enter_exit_group
func OnProcExit(ctx *bpf.SyscallEnterCtx) bpf.TpReturn {
	e, ok := events.Reserve()
	if !ok {
		return bpf.TpOk
	}
	fillHeader(e, kindProcExit)
	e.Ret = int32(ctx.Args[0])
	events.Submit(e)
	return bpf.TpOk
}

// OnExecExit fires when execve returns. Successful exec replaces the
// process so this only meaningfully fires when execve FAILED — the
// return value is the negative errno (e.g. -2 = ENOENT, -13 = EACCES).
//bpf:section tracepoint/syscalls/sys_exit_execve
func OnExecExit(ctx *bpf.SyscallExitCtx) bpf.TpReturn {
	if ctx.Ret >= 0 {
		return bpf.TpOk
	}
	e, ok := events.Reserve()
	if !ok {
		return bpf.TpOk
	}
	fillHeader(e, kindExecFailed)
	e.Ret = int32(ctx.Ret)
	events.Submit(e)
	return bpf.TpOk
}

func main() {}
