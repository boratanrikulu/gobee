# Support status

Single source of truth for what gobee supports today, what's planned, and what we won't support. The goal is that nobody has to read source code to know whether their program will transpile.

Legend:
- ✅ **Supported**: works, has tests, used by at least one example
- 🚧 **WIP**: code exists but is incomplete or unproven; expect rough edges
- 📋 **Planned**: not started, but on the roadmap
- ❌ **Won't support**: fundamentally incompatible with BPF; the validator rejects these and will keep rejecting them

---

## Go subset

### Types

| Feature | Status | Notes |
|---|---|---|
| `bool` | ✅ | Maps to `bool` |
| `int8`, `int16`, `int32`, `int64` | ✅ | Map to `__s8`/`__s16`/`__s32`/`__s64` |
| `uint8`, `uint16`, `uint32`, `uint64` | ✅ | Map to `__u8`/`__u16`/`__u32`/`__u64` |
| `unsafe.Pointer` | ✅ | Renders as `void *`. Used for kernel-object pointers (task, sock, inode) |
| `uintptr` | 📋 | Useful for some helper signatures |
| `float32`, `float64` | ❌ | BPF has no FP unit |
| `complex64`, `complex128` | ❌ | Same |
| Fixed arrays `[N]T` | ✅ | N must be a constant integer |
| Pointers `*T` | ✅ | Raw `T *` in C |
| Structs (no methods) | ✅ | |
| Struct methods on user types | ❌ | Not supported |
| Generics in user code | ❌ | gobee uses generics in the `bpf` package; user BPF program code does not |
| Slices `[]T` | ❌ | No heap-grown buffers in BPF |
| Strings | ❌ | Not addressable in BPF |
| Builtin maps `map[K]V` | ❌ | Use `bpf.ArrayMap` / `bpf.HashMap` etc. |
| Channels | ❌ | No scheduler in kernel context |
| Interfaces | ❌ | No dynamic dispatch |

### Statements

| Feature | Status | Notes |
|---|---|---|
| `if` / `else` / `else if` | ✅ | |
| Constant-bounded `for i := 0; i < N; i++` | ✅ | Verifier-friendly loop |
| `range` | 📋 | Use a constant-bounded `for` |
| `switch`, type switch | 📋 | Use `if/else if` |
| Single-value `return` | ✅ | |
| Multi-value `return` | ❌ | |
| `var`, `:=` (single) | ✅ | |
| `:=` comma-ok on map lookup | ✅ | One of the two multi-assignment shapes allowed |
| `:=` comma-ok on storage Get | ✅ | The other one |
| Other multi-assignment | ❌ | |
| `goto`, labels | 📋 | |
| `defer` | ❌ | No unwinding in BPF |
| `panic` / `recover` | ❌ | No runtime |
| `go` (goroutines) | ❌ | No scheduler |
| `select` | ❌ | No channels |

### Expressions

| Feature | Status | Notes |
|---|---|---|
| Numeric literals | ✅ | |
| Unary ops `!`, `&`, `-`, `^` | ✅ | |
| Binary arithmetic `+ - * / %` | ✅ | |
| Binary bitwise `& \| ^ << >>` | ✅ | |
| Comparison `== != < <= > >=` | ✅ | |
| Logical `&& \|\|` | ✅ | |
| Function calls (helpers) | ✅ | All ~200 libbpf helpers |
| Method calls (map ops) | ✅ | Per-map-type method sets |
| User function calls | ✅ | Top-level helpers without `//bpf:section` are emitted as `static __always_inline` |
| Type conversions | ✅ | Numeric widening, named-type conversions emit explicit casts |
| Type assertions | ❌ | No interfaces |
| `make` / `new` | ❌ | No heap allocation |

### Heap and allocation

| Feature | Status | Notes |
|---|---|---|
| Stack-only locals | ✅ | All locals live on the BPF program stack (512-byte limit) |
| Heap allocation | ❌ | BPF doesn't have a heap |
| BPF maps as state | ✅ | |

### Imports

| Import path | Status | Notes |
|---|---|---|
| `github.com/boratanrikulu/gobee/bpf` | ✅ | The BPF API surface |
| `unsafe` | ✅ | For `unsafe.Pointer` returned by some helpers |
| Anything else | ❌ | Validator rejects with a clear diagnostic. The Go stdlib runs in userspace; nothing in it is callable from a BPF program |

---

## eBPF features

### Program types

| Type | Status | Notes |
|---|---|---|
| XDP | ✅ | `//bpf:section xdp`, ctx is `*bpf.XdpMd` |
| Tracepoint | ✅ | `//bpf:section tracepoint/<cat>/<name>`. Per-syscall typed contexts (`ExecveEnterCtx`, `OpenatEnterCtx`) for the common cases; `SyscallEnterCtx` / `SyscallExitCtx` / `TracepointCtx` for the rest |
| Kprobe / Kretprobe | ✅ | `//bpf:section kprobe/<sym>` or `kretprobe/<sym>`, ctx is `*bpf.PtRegs` |
| Uprobe / Uretprobe | ✅ | `//bpf:section uprobe/<binary>:<sym>`, reuses `*bpf.PtRegs` |
| Sock ops | ✅ | `//bpf:section sockops`, ctx is `*bpf.SockOpsMd`. Op constants: `bpf.BpfSockOps*` |
| TC (cls/act) | ✅ | `//bpf:section classifier/<name>` or `action/<name>`, ctx is `*bpf.SkBuff`, return is `bpf.TcAction` |
| Cgroup skb | ✅ | `//bpf:section cgroup_skb/{ingress,egress}`, ctx is `*bpf.SkBuff` |
| LSM | ✅ | `//bpf:section lsm/<hook>`, ctx is `*bpf.LsmCtx` |
| Perf event | 📋 | Depends on perf-event-array map type, which is supported; the program-type wiring isn't |

### Map types

| Type | Status | Go API | Notes |
|---|---|---|---|
| `BPF_MAP_TYPE_ARRAY` | ✅ | `bpf.ArrayMap[K, V]` | |
| `BPF_MAP_TYPE_HASH` | ✅ | `bpf.HashMap[K, V]` | |
| `BPF_MAP_TYPE_LRU_HASH` | ✅ | `bpf.LruHashMap[K, V]` | Evicts LRU entry when full |
| `BPF_MAP_TYPE_PERCPU_ARRAY` | ✅ | `bpf.PerCPUArray[K, V]` | |
| `BPF_MAP_TYPE_PERCPU_HASH` | ✅ | `bpf.PerCPUHash[K, V]` | |
| `BPF_MAP_TYPE_LRU_PERCPU_HASH` | ✅ | `bpf.LruPerCPUHash[K, V]` | |
| `BPF_MAP_TYPE_BLOOM_FILTER` | ✅ | `bpf.BloomFilter[T]` | `Add(*T)` / `Contains(*T) bool` |
| `BPF_MAP_TYPE_LPM_TRIE` | ✅ | `bpf.LpmTrie[K, V]` | Key must lead with `__u32 prefixlen` |
| `BPF_MAP_TYPE_RINGBUF` | ✅ | `bpf.RingBuf[T]` | Typed `Reserve()`/`Submit()`/`Discard()`/`Output()` |
| `BPF_MAP_TYPE_PERF_EVENT_ARRAY` | ✅ | `bpf.PerfEventArray[T]` | Legacy alternative to ringbuf |
| `BPF_MAP_TYPE_PROG_ARRAY` | ✅ | `bpf.ProgArray` | `TailCall(ctx, key)` for chained programs |
| `BPF_MAP_TYPE_QUEUE` | ✅ | `bpf.Queue[T]` | `Push`/`Pop`/`Peek` |
| `BPF_MAP_TYPE_STACK` | ✅ | `bpf.Stack[T]` | Same |
| `BPF_MAP_TYPE_TASK_STORAGE` | ✅ | `bpf.TaskStorage[V]` | `Get`/`GetOrCreate`/`Delete`. Kernel-sized |
| `BPF_MAP_TYPE_SK_STORAGE` | ✅ | `bpf.SkStorage[V]` | Same shape |
| `BPF_MAP_TYPE_INODE_STORAGE` | ✅ | `bpf.InodeStorage[V]` | Same |
| `BPF_MAP_TYPE_DEVMAP` | ✅ | `bpf.DevMap` | XDP redirect to interface ifindex via `Redirect(ctx, key, flags)` |
| `BPF_MAP_TYPE_CPUMAP` | ✅ | `bpf.CpuMap` | XDP redirect to a target CPU |
| `BPF_MAP_TYPE_XSKMAP` | ✅ | `bpf.XskMap` | XDP redirect to an AF_XDP socket |

### BPF helpers (BPF `bpf` package)

The full libbpf helper surface is auto-generated from `bpf_helper_defs.h` (libbpf v1.5.0). 196 helpers ship as typed Go stubs in `bpf/helpers_generated.go`; 15 are skipped as not BPF-safe in their current form (string-typed parameters and variadics like `bpf_trace_printk`).

| Surface | Status | Notes |
|---|---|---|
| `bpf.AtomicAdd64(*uint64, uint64)` | ✅ | Hand-written; emits `__sync_fetch_and_add` (clang intrinsic, not a BPF helper) |
| Map / storage method calls | ✅ | Type-specific methods on each map kind |
| Auto-generated helpers (196 total) | ✅ | Names map 1:1 to libbpf via `KtimeGetNs` ↔ `bpf_ktime_get_ns`, etc. |
| `bpf_trace_printk` (variadic) | 📋 | Needs a typed wrapper |
| String-typed helpers (`bpf_probe_read_str`, …) | 📋 | Need a buffer-backed Go wrapper |
| Bumping libbpf version | ✅ | `make gen-helpers` after bumping `tools/genhelpers/data/bpf_helper_defs.h` |

### CO-RE and kernel struct access

| Feature | Status | Notes |
|---|---|---|
| `#include "vmlinux.h"` in emitted C | ✅ | Auto-detected. Programs that read kernel-internal struct fields get the vmlinux.h header set; programs that just call helpers get the lighter `<linux/bpf.h>` |
| Auto-detection of CO-RE need | ✅ | Walks the AST for any field access on kernel-internal structs |
| `BPF_CORE_READ` for kernel-internal struct fields | ✅ | Single-level and chained access |
| Direct field access for UAPI BPF context structs | ✅ | `xdp_md`, `__sk_buff`, `bpf_sock_ops` are program contexts, not kernel data. CO-RE on them silently returned garbage at runtime; we now emit `ctx->field` directly |
| Kernel field name mapping | ✅ | `bpf:"<c_name>"` struct tag on each Go field; falls back to snake-case |
| Modeled context structs | ✅ | `XdpMd`, `SkBuff`, `SockOpsMd`, `PtRegs`, `LsmCtx`, `SyscallEnterCtx`, `SyscallExitCtx`, `ExecveEnterCtx`, `OpenatEnterCtx`, `TracepointCtx` |
| Arbitrary kernel struct stubs (e.g. `task_struct`) | 📋 | Need an auto-generator (`tools/genkernel`) that reads vmlinux.h |
| Direct field assignment (`ctx.Pid = 0`) | ❌ | Reads only |

### Verifier integration

| Feature | Status | Notes |
|---|---|---|
| Sourcemap emission (`.bpf.c.map`) | ✅ | |
| `gobee diagnose` (verifier output → Go positions) | ✅ | Pipe a verifier log on stdin, get an annotated copy on stdout |
| Auto-rewrite `VerifierError` in user driver | ✅ | Generated `Load<Stem>` embeds the sourcemap and intercepts `*ebpf.VerifierError` from `LoadAndAssign`, returning a wrapped error with `→ <go-file>:<line>:<col>` annotations on every C-line reference |
| `#pragma unroll` injection | 📋 | For verifier-friendly loops |
| Stack budget tracking (warn before verifier rejects) | 📋 | |
| Helper return-bounds checks at transpile time | 📋 | |

### Userspace bindings

| Feature | Status | Notes |
|---|---|---|
| Typed `<Stem>Programs`, `<Stem>Maps`, `<Stem>Objects` structs | ✅ | `ebpf:"<elf-name>"` tags. `objs.X` field access |
| `Load<Stem>(spec)` constructor | ✅ | Wraps `LoadAndAssign` |
| `(*Objects).Close()` | ✅ | Closes every program and map |
| Per-program `Attach<Name>(...)` helpers | ✅ | Generated from each `//bpf:section` directive. XDP takes ifindex; tracepoints / kprobes / kretprobes take none |
| `(*Objects).AttachAll(xdpIfindex int)` | ✅ | One call attaches every program; rolls back on failure |
| Re-publish user struct types | ✅ | Layout matches byte-for-byte, so `binary.Read` works |
| Re-publish user constants (capitalized) | ✅ | Lowercase `kindExec` becomes public `KindExec` |
| Kernel-version gate | ✅ | `Load<Stem>` runs [bpfvet](https://github.com/boratanrikulu/bpfvet)'s analyzer; refuses to load if running kernel is older than the spec needs |

### Build / integration

| Feature | Status | Notes |
|---|---|---|
| Pure-Go `gobee translate <dir>` | ✅ | No CGO, no subprocess deps |
| `--bindings-dir` flag | ✅ | Bindings file lands in this dir; package name is the dir's base name. Empty/omitted skips bindings (logs `bindings skipped` on stderr) |
| `GOBEE_*` env vars | ✅ | Every flag also reads from the matching `GOBEE_<NAME>` env var (e.g. `GOBEE_BINDINGS_DIR=./bpf`) |
| Sourcemap sidecar `.bpf.c.map` | ✅ | |
| Compile via clang | ❌ | User's responsibility (Makefile) |
| Load BPF at runtime | ✅ | Userspace uses generated bindings + `cilium/ebpf` |

---

## Directives

| Directive | Status | Notes |
|---|---|---|
| `//bpf:license <name>` | ✅ | File-level |
| `//bpf:section <name>` | ✅ | Function-level |
| Map declarations (no directive) | ✅ | Type-driven: `var X = bpf.<MapType>[...]{MaxEntries: N}` is detected by the parser. The `//bpf:map` directive was dropped: the Go type alone identifies the map kind |
| `//bpf:include <path>` | 📋 | For pulling in vmlinux.h or user headers from non-default paths |
| Unknown `//bpf:*` warning | 📋 | Currently silently ignored |

---

## CI

GitHub Actions on every push (`.github/workflows/ci.yml`):

1. `go test`, `go vet`, transpiler golden tests
2. Coverage matrix: every map type and `//bpf:section` kind has at least one example under `testdata/examples/`
3. clang compile of curated examples (`example/helloworld/`, `example/sysmon/`), then `bpfvet` portability report
4. Real-kernel verifier acceptance: `ebpf.NewCollectionWithOptions` on each `.bpf.o` (Ubuntu 24.04, kernel 6.x)

---

## How to read this file

- ✅ rows are committed and tested. If something marked ✅ doesn't work, that's a bug.
- 🚧 rows partially work. Use them, but expect to file or fix the rough edges.
- 📋 rows are not implemented. The validator will reject most attempts with a clear diagnostic.
- ❌ rows are intentional. We won't add them. If you need them, you're probably writing a userspace program in the wrong file.

When you add or remove support for something, update this file in the same commit.
