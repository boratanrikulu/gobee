# Directives

gobee reads two magic comments. They start with `//bpf:` and live above the relevant declaration with no blank line in between (Go's standard doc-comment association). Maps don't use a directive at all; the Go type drives them.

## `//bpf:license <name>`

File-level. Sets the BPF program license. Required, since loading a non-GPL BPF program restricts which kernel helpers you can call.

```go
//bpf:license GPL
```

Emits:

```c
char _license[] SEC("license") = "GPL";
```

Place it near the top of the file, before any decls. gobee scans the whole file for it; position doesn't matter, but conventionally it goes right after `package main`.

## `//bpf:section <name>`

Function-level. Marks a function as a BPF program. The argument is the SEC name passed to libbpf, verbatim.

```go
//bpf:section xdp
func CountPackets(ctx *bpf.XdpMd) bpf.XdpAction { ... }

//bpf:section tracepoint/syscalls/sys_enter_execve
func OnExec(ctx *bpf.ExecveEnterCtx) bpf.TpReturn { ... }

//bpf:section kprobe/tcp_connect
func OnTcpConnect(ctx *bpf.PtRegs) bpf.KpReturn { ... }
```

Each program type expects a specific ctx and return type. See [`go-subset.md`](go-subset.md#program-functions) for the full table.

Functions without a `//bpf:section` are not BPF programs. They become C `static __always_inline` helpers if they're called from at least one program. `func main() {}` exists only so the file is valid Go; gobee skips it.

The bindings generator also reads `//bpf:section` to emit per-program `Attach<Name>(...)` helpers in `<stem>_bindings.go`. XDP programs get an `(ifindex int)` parameter. Tracepoints, kprobes, and kretprobes take none. The generated `AttachAll(xdpIfindex int)` runs them all.

## Map declarations (no directive)

Maps are package-level vars initialized with a struct literal of one of the bpf-package map types:

```go
var PktCount = bpf.ArrayMap[uint32, uint64]{MaxEntries: 1}
var Sessions = bpf.HashMap[uint64, SessionState]{MaxEntries: 4096}
var Events   = bpf.RingBuf[Event]{MaxEntries: 4096}
var Stages   = bpf.ProgArray{MaxEntries: 8}

// Storage maps are kernel-sized; no MaxEntries.
var PerTask  = bpf.TaskStorage[Counter]{}
```

The transpiler walks every package-level var. If its type is one of the recognized bpf-package map types, it's treated as a BPF map. K and V come from the generic instantiation. `MaxEntries` from the struct literal.

Recognized map types: `ArrayMap`, `HashMap`, `LruHashMap`, `PerCPUArray`, `PerCPUHash`, `LruPerCPUHash`, `BloomFilter`, `LpmTrie`, `RingBuf`, `Queue`, `Stack`, `ProgArray`, `PerfEventArray`, `TaskStorage`, `SkStorage`, `InodeStorage`.

A simple `bpf.HashMap` declaration emits:

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1024);
} PktCount SEC(".maps");
```

The map identifier is the Go variable name verbatim. It's also the symbol the generated bindings expose: `objs.PktCount` corresponds to `coll.Maps["PktCount"]` in stringly-typed code.

There used to be a `//bpf:map` directive. It got removed when the type-driven approach proved cleaner: the Go type already says what kind of map it is, and gopls hover/autocomplete works without a separate annotation.

## Comment association rules

gobee uses Go's standard doc-comment attachment: the comment is treated as a directive only if it sits immediately above the decl, with no blank line.

Works:

```go
//bpf:section xdp
func CountPackets(...) ... { ... }
```

Doesn't:

```go
//bpf:section xdp

func CountPackets(...) ... { ... }
```

The blank line breaks the association. The validator and emitter will silently ignore the directive in the second form. If a `//bpf:section` function never gets emitted, this is the first thing to check.

For `//bpf:license` the rule is looser: gobee scans every comment in the file. Blank lines around it don't matter.

## What's not a directive

Lines that look like `//bpf:` but don't match a known directive name are silently ignored. If you misspell `//bpf:secton` you'll get the function transpiled as a non-program (or skipped entirely), which is the wrong outcome but a useful debug hint that the directive didn't match.

A future version may warn on unknown directives. For now: if a function isn't getting emitted, double-check the spelling.
