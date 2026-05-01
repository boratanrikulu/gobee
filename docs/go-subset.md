# The Go subset

> The full "what's supported / WIP / planned / won't support" tables live in [`status.md`](status.md). This file is the prose explanation. If the two disagree, `status.md` wins.

gobee accepts a small slice of Go inside `//bpf:section` functions and the user-defined helpers they call. The rest is rejected at validation time with a `file:line:col` diagnostic. The subset is small on purpose: it tracks what BPF programs already look like in C, just spelled with Go syntax.

## Supported

| Feature | Notes |
|---|---|
| `bool`, `int8/16/32/64`, `uint8/16/32/64` | Map to `__s*` / `__u*` C types |
| `unsafe.Pointer` | Renders as `void *`. Used for kernel-object pointers (task, sock, inode) and `bpf.GetCurrentTaskBtf()` |
| Fixed-size arrays `[N]T` | N must be a constant |
| Pointers `*T` | Just a raw `*` in C |
| Structs (no methods) | User-defined types are emitted in C with the same layout; methods on user types are not supported |
| `if` / `else` / `else if` | |
| Constant-bounded `for i := 0; i < N; i++` | Verifier-friendly loop. May need `#pragma unroll` on tight inner loops; coming in a later phase |
| Calls into `bpf` package helpers | All ~200 libbpf helpers via `bpf.<Name>(...)` |
| Map methods | `Lookup`, `Update`, `Delete` on the standard maps; type-specific methods on the others (`Add`/`Contains` on bloom, `Push`/`Pop`/`Peek` on queue/stack, `Reserve`/`Submit`/`Discard` on ringbuf, `TailCall` on prog array, `Output` on perf event array, `Get`/`GetOrCreate`/`Delete` on storage maps) |
| User-defined helpers | Top-level functions without `//bpf:section`. Emitted as `static __always_inline`. Single-value or no return |
| Single return values | Multi-return is not supported |
| Local `var x T = ...` and `x := ...` | |
| Comma-ok on map lookup and storage Get | `count, ok := PktCount.Lookup(&key)` and `v, ok := taskCtx.Get(task)` are the two multi-assignment shapes allowed |

## Rejected

The validator emits a diagnostic for each of these. Most messages tell you what to do instead.

| Construct | Why |
|---|---|
| Slices `[]T` | BPF programs can't grow buffers. Use `[N]T` |
| Builtin maps `map[K]V` | Use `bpf.ArrayMap` / `bpf.HashMap` / etc. as a struct-literal package var |
| Strings | Not addressable in BPF. Use a fixed array |
| Goroutines | No scheduler in kernel context |
| Channels | Same |
| Closures / function literals | No heap, no captured state |
| `defer`, `panic`, `recover` | No unwinding, no runtime |
| Interfaces | No dynamic dispatch |
| Methods on user types | Not supported |
| Generics in user code | Not supported (gobee itself uses generics in the `bpf` package; user kernel-side code does not) |
| `range` | Use a constant-bounded `for` |
| `switch` / type switch | Use `if / else if` |
| Multi-return (other than the comma-ok cases) | Not supported |
| `make` / `new` | No heap allocation in BPF |

## Map declaration

Maps are package-scope vars initialized with a struct literal:

```go
var PktCount = bpf.ArrayMap[uint32, uint64]{MaxEntries: 1}
var Sessions = bpf.HashMap[uint64, SessionState]{MaxEntries: 4096}
var Events   = bpf.RingBuf[Event]{MaxEntries: 4096}

// Storage maps are kernel-sized; no MaxEntries.
var PerTask  = bpf.TaskStorage[Counter]{}
```

The map name is the Go identifier. The kind comes from the Go type. K and V come from the generic type arguments. `MaxEntries` is required for everything except per-object storage maps.

Lookup, update, and delete are method calls on the map var:

```go
count, ok := PktCount.Lookup(&key)              // bpf_map_lookup_elem
err := Sessions.Update(&key, &val)              // bpf_map_update_elem(..., BPF_ANY)
err := Sessions.Delete(&key)                    // bpf_map_delete_elem
```

Storage maps add a `Get` / `GetOrCreate` pair:

```go
task := bpf.GetCurrentTaskBtf()
c, ok := PerTask.Get(task)
if !ok {
    var zero Counter
    c = PerTask.GetOrCreate(task, &zero)
}
```

The receiver gets rewritten to `&MapName` in C, which is what the kernel helpers expect.

## Program functions

A function becomes a BPF program when it's tagged with `//bpf:section`:

```go
//bpf:section xdp
func CountPackets(ctx *bpf.XdpMd) bpf.XdpAction { ... }

//bpf:section tracepoint/syscalls/sys_enter_execve
func OnExec(ctx *bpf.ExecveEnterCtx) bpf.TpReturn { ... }

//bpf:section kprobe/tcp_connect
func OnTcpConnect(ctx *bpf.PtRegs) bpf.KpReturn { ... }
```

The section value is forwarded verbatim to the emitted `SEC("...")`. Each program type has its own ctx and return type:

| Section prefix | Ctx | Return |
|---|---|---|
| `xdp` | `*bpf.XdpMd` | `bpf.XdpAction` |
| `tracepoint/syscalls/sys_enter_execve` | `*bpf.ExecveEnterCtx` | `bpf.TpReturn` |
| `tracepoint/syscalls/sys_enter_openat` | `*bpf.OpenatEnterCtx` | `bpf.TpReturn` |
| Other tracepoints | `*bpf.SyscallEnterCtx` / `*bpf.SyscallExitCtx` / `*bpf.TracepointCtx` | `bpf.TpReturn` |
| `kprobe/<sym>`, `kretprobe/<sym>`, `uprobe/...` | `*bpf.PtRegs` | `bpf.KpReturn` |
| `sockops` | `*bpf.SockOpsMd` | `bpf.SockOpsReturn` |
| `classifier/<name>`, `action/<name>` | `*bpf.SkBuff` | `bpf.TcAction` |
| `cgroup_skb/{ingress,egress}` | `*bpf.SkBuff` | `bpf.CgroupSkbReturn` |
| `lsm/<hook>` | `*bpf.LsmCtx` | `bpf.LsmReturn` |

The return type renders as `int` in C (libbpf's contract).

`func main() {}` is required because the file is `package main`. It's never called and never transpiled.

## User-defined helpers

Top-level functions without `//bpf:section` become inline helpers:

```go
func fillHeader(e *Event, kind uint32) {
    var ts uint64 = bpf.KtimeGetNs()
    e.TimeNsHi = uint32(ts >> 32)
    e.TimeNsLo = uint32(ts)
    e.Pid = bpf.GetCurrentPid()
    e.Kind = kind
}

//bpf:section tracepoint/syscalls/sys_enter_execve
func OnExec(ctx *bpf.ExecveEnterCtx) bpf.TpReturn {
    e, ok := events.Reserve()
    if !ok { return bpf.TpOk }
    fillHeader(e, kindExec)
    events.Submit(e)
    return bpf.TpOk
}
```

The emitted C is `static __always_inline void fillHeader(...)`. The verifier inlines it at every call site, so there's no indirect-call overhead and no separate stack frame.

## Type mapping

| Go | C |
|---|---|
| `bool` | `bool` |
| `int8` | `__s8` |
| `int16` | `__s16` |
| `int32`, untyped int literal | `__s32` |
| `int64` | `__s64` |
| `uint8` | `__u8` |
| `uint16` | `__u16` |
| `uint32` | `__u32` |
| `uint64` | `__u64` |
| `unsafe.Pointer` | `void *` |
| `*T` | `T *` (no space before the variable name) |
| `bpf.XdpMd` | `struct xdp_md` |
| `bpf.PtRegs` | `struct pt_regs` |
| `bpf.SkBuff` | `struct __sk_buff` |
| `bpf.SockOpsMd` | `struct bpf_sock_ops` |
| `bpf.XdpAction`, `bpf.TpReturn`, `bpf.KpReturn`, `bpf.TcAction`, `bpf.CgroupSkbReturn`, `bpf.LsmReturn`, `bpf.SockOpsReturn` | `int` |

User-defined struct types render with their Go name. Each field is emitted with the same C type as if you wrote it by hand.

## Constants

The `bpf` package's exported constants map to the libbpf macros:

| Go | C |
|---|---|
| `bpf.XdpAborted`, `XdpDrop`, `XdpPass`, `XdpTx`, `XdpRedirect` | `XDP_ABORTED`, `XDP_DROP`, `XDP_PASS`, `XDP_TX`, `XDP_REDIRECT` |
| `bpf.TpOk`, `bpf.KpOk`, `bpf.TcOk`, `bpf.LsmAllow` | `0` |
| `bpf.LsmDeny` | `-1` |

Plus the sock_ops op constants (`bpf.BpfSockOpsTcpConnectCb`, …) and the TC return values (`bpf.TcShot`, `bpf.TcRedirect`, …). See `bpf/` source for the full list.

User-defined constants are inlined as literals in emitted C:

```go
const kindExec = uint32(1)

// somewhere
e.Kind = kindExec
```

becomes:

```c
e->Kind = (__u32)(1);
```

## Helpers

The `bpf` package wraps roughly 200 libbpf helpers, auto-generated from `bpf_helper_defs.h`:

```go
ts := bpf.KtimeGetNs()
pid := bpf.GetCurrentPid()
bpf.AtomicAdd64(&counter, 1)
```

`bpf.AtomicAdd64` is a hand-written exception that emits `__sync_fetch_and_add` (a clang intrinsic, not a BPF helper). Everything else maps to its libbpf name: `bpf.MapLookupElem` ↔ `bpf_map_lookup_elem`, `bpf.RingbufReserve` ↔ `bpf_ringbuf_reserve`, etc.

Variadic helpers (`bpf_trace_printk`) and string-typed helpers don't have stubs yet. Use the typed ringbuf instead of `bpf_trace_printk` for now.

## Imports

Two imports are allowed in a kernel-side `.go` file:

```go
import "github.com/boratanrikulu/gobee/bpf"
import "unsafe"     // only for unsafe.Pointer values returned by some helpers
```

Anything else fails validation up front:

```
counter.go:6:2: import "net" is not allowed in BPF programs;
                only "github.com/boratanrikulu/gobee/bpf" can be imported
```

The Go stdlib (`net`, `fmt`, `strings`, …) runs in userspace. None of it is callable from a BPF program. If you want to parse an IP, build a struct from packet bytes, or do anything the stdlib would normally help with, do it in your userspace driver and pass the result through a BPF map.

## When the validator complains

Read the diagnostic. It usually tells you what to do instead. If it doesn't, the message is bad and worth a bug report. The validator is the most reader-facing part of gobee, so wording matters.
