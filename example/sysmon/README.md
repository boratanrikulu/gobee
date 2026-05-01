# sysmon

A small system-activity monitor that exercises a representative slice of gobee in one binary. Six BPF programs attached at once, sharing a single ringbuf for events plus a hash map for packet counts.

## What it shows

| Program | Type | Source | Output |
|---|---|---|---|
| `OnPacket` | XDP | `*bpf.XdpMd` | per-iface counter (polled from userspace) |
| `OnExec` | tracepoint `sys_enter_execve` | `*bpf.ExecveEnterCtx` | `[exec]` line over ringbuf |
| `OnExecExit` | tracepoint `sys_exit_execve` | `*bpf.SyscallExitCtx` | `[fail]` for failed execves |
| `OnOpen` | tracepoint `sys_enter_openat` | `*bpf.OpenatEnterCtx` | `[open]` line |
| `OnProcExit` | tracepoint `sys_enter_exit_group` | `*bpf.SyscallEnterCtx` | `[exit]` with status code |
| `OnTcpConnect` | kprobe `tcp_connect` | `*bpf.PtRegs` | `[tcp]` line |

All six programs live in [`bpf/src/sysmon.go`](bpf/src/sysmon.go). About 100 lines of kernel-side Go.

The userspace driver runs two concurrent loops: one reading the shared ringbuf, the other polling the packet-count map every 5 seconds. Single `objs.AttachAll(ifindex)` call handles every program; main.go never names a section string.

## Run

Linux only, arm64 or amd64. Needs `clang` with the BPF target plus `llvm-strip`. The vendored `vmlinux.h` is for the lima ARM kernel; regenerate per the sibling `bpf/src/SOURCE.md` if you build elsewhere.

```bash
cd example/sysmon
make build
sudo ./sysmon                        # tracing only: no XDP, no interface needed
sudo ./sysmon lima0                  # also attach the XDP packet counter
```

The interface argument is optional. Without it, the five event-driven programs (execve enter/exit, openat, exit_group, tcp_connect) still run system-wide. Only the XDP packet counter needs an interface.

Default behavior:

- UID 0 events are hidden so the output is dominated by what *you* run, not by `systemd-journal` and friends.
- `[open]` events are hidden because openat fires once per shared-library load and floods the screen.
- `[exit]` events for PIDs we never saw exec for are hidden too. Those are usually shell-fork orphans (zsh subshells, command substitution) that never actually exec'd anything; showing them is noise.

Flags:

- `--all`: include UID 0 (root) events.
- `--show-open`: include `[open]` events.
- `--all-exits`: include orphan `[exit]` events.

```bash
sudo ./sysmon --all                       # everyone, no [open]
sudo ./sysmon --show-open                 # your activity + [open] firehose
sudo ./sysmon --all --show-open lima0     # everything plus XDP packet counter
```

Trigger some activity from another shell and you'll see something like:

```
sysmon: tracing execve, openat, tcp_connect; XDP attached to lima0. ctrl-c to stop.
[exec] pid=26160  uid=501  zsh              /usr/bin/curl bora.sh
[tcp ] pid=26160  uid=501  curl             tcp_connect
[exit] pid=26160  uid=501  curl             status=0
[stats] iface=lima0 packets=42
```

## Architecture

```
   ┌──────────────────────────┐                    ┌──────────────┐
   │  bpf/src/sysmon.go       │                    │  main.go     │
   │  (kernel-side)           │                    │  (userspace) │
   │                          │                    │              │
   │  OnPacket  ─► packets    │   poll every 5s   ►│   ticker     │
   │              ByIface     │   objs.PacketsByI- │              │
   │             (HashMap)    │   face.Lookup      │              │
   │                          │                    │              │
   │  OnExec    ─┐            │                    │              │
   │  OnOpen    ─┤            │                    │              │
   │  OnTcp     ─┼─► events   │   ringbuf read ───►│  dispatcher  │
   │  OnExit    ─┤  (RingBuf) │                    │   on Kind    │
   │  OnExecExit─┘            │                    │              │
   └──────────────────────────┘                    └──────────────┘
```

## How it uses the new generated bindings

`gobee translate --bindings-dir ./bpf ./bpf/src` produces `bpf/sysmon_bindings.go`. Userspace imports `example.com/sysmon/bpf` and gets:

```go
spec, _ := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpf.Program))
objs, _ := bpf.LoadSysmon(spec)        // typed constructor + kernel-version gate
defer objs.Close()

links, _ := objs.AttachAll(xdpIdx)     // attaches all 6 programs in one call
defer closeAll(links)

rd, _ := ringbuf.NewReader(objs.Events)
defer rd.Close()
```

No `coll.Programs["OnExec"]`. No `"syscalls", "sys_enter_execve"` strings. The kernel-side `//bpf:section tracepoint/syscalls/sys_enter_execve` directive is the single source of truth for what `OnExec` attaches to. Rename the kernel-side function and the bindings get a new method name.

The bindings also re-publish the kernel-side `Event` struct and the `kindExec`/`kindOpen`/etc. constants:

```go
// kernel side: bpf/src/sysmon.go
type Event struct { ... }
const kindExec = uint32(1)

// userspace, automatically:
var ev bpf.Event
switch ev.Kind {
case bpf.KindExec: ...
case bpf.KindOpen: ...
}
```

`binary.Read` decodes the ringbuf payload directly into `bpf.Event`, layout-compatible by construction.

## Code highlights

The six BPF programs share one ringbuf via a tagged event. A user-defined helper handles the boilerplate that's the same for every kind:

```go
func fillHeader(e *Event, kind uint32) {
    var ts uint64 = bpf.KtimeGetNs()
    e.TimeNsHi = uint32(ts >> 32)
    e.TimeNsLo = uint32(ts)
    e.Pid = bpf.GetCurrentPid()
    e.Uid = bpf.GetCurrentUid()
    e.Kind = kind
    bpf.GetTaskComm(&e.Comm)
}

//bpf:section tracepoint/syscalls/sys_enter_execve
func OnExec(ctx *bpf.ExecveEnterCtx) bpf.TpReturn {
    e, ok := events.Reserve()
    if !ok { return bpf.TpOk }
    fillHeader(e, kindExec)
    bpf.GetUserString(&e.Path, ctx.Filename)
    bpf.GetUserArgv(&e.Args, ctx.Argv)
    events.Submit(e)
    return bpf.TpOk
}
```

`fillHeader` is emitted as `static __always_inline` in C so the verifier inlines it at every call site. No call overhead, no separate stack frame.

Per-interface packet counts aren't pushed via the ringbuf (would flood). Userspace polls the map every 5 seconds.
