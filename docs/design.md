# Design

gobee converts a strict subset of Go into BPF C. It also generates typed Go bindings for the userspace side: `Load<Stem>`, `objs.X` field access, `AttachAll`, plus your BPF program struct types re-published. clang compiles the C. `cilium/ebpf` loads the result. gobee does not run clang and does not load programs into the kernel.

> The support matrix (Go subset, eBPF features, helpers, map types, program types) lives in [`status.md`](status.md). This file is about why the architecture looks the way it does.

## Why transpile

Go's compiler doesn't have a BPF backend. There's no `gc -target bpf` and adding one is a multi-year compiler project. Rust gets away with it because rustc is built on LLVM, and LLVM has a mature BPF backend.

Two paths were possible:

1. Generate BPF assembly directly. `miekg/bpf` tried this and got archived without ever shipping a working hello world. You inherit nothing from clang: no CO-RE, no BTF, no verifier-friendly codegen. You write all of it.
2. Generate C and run it through clang. You inherit clang's BPF backend, which is what every serious BPF project already uses.

Option 2 is less interesting on paper. It's more useful in practice.

## Why C and not LLVM IR

Same reason. Generating IR means writing a register allocator, instruction scheduler, and verifier hints by hand. Clang already does this. The output of `clang -target bpf` is what the kernel expects, and matching it byte for byte was not a worthwhile goal.

C is also a readable artifact. If gobee emits weird C, you can see it. If gobee emitted IR, debugging would mean reading SSA dumps.

## What gobee is

A pure-Go binary. Takes a directory of `.go` files (each with `//go:build ignore`), writes a `.bpf.c` file plus a sourcemap into the output dir, and writes a `<stem>_bindings.go` into the bindings dir. No CGO, no subprocess deps, runs on Linux, macOS, and Windows.

```
counter.go ─┐
            ├─ go/parser ─┐
            └─ go/types  ─┘
                          │
                          ▼
                 *Program (license, maps, programs, helpers, types, consts)
                          │
                          ▼
                       Validate
                          │
                          ▼
            ┌─────────────┴─────────────┐
            ▼                           ▼
        Emit C                    Emit bindings
            │                           │
            ▼                           ▼
      counter.bpf.c              counter_bindings.go
```

Three stages: parse + typecheck (`go/parser` + `go/types`), validate against the supported subset, emit. Each stage is its own file under `internal/transpile/`.

## What gobee is not

- It does not invoke clang.
- It does not invoke bpf2go.
- It does not load programs into the kernel.

The compile, embed, and load steps are well-served by existing tooling: `clang -target bpfel`, `cilium/ebpf`, and `go:embed`. Wrapping them inside gobee would mean owning every distro and arch include-path issue forever, so we don't. The hello-world example shows the full chain. Copy that pattern.

## The IR

After parsing, gobee builds a `*Program` with:

- A license string (from `//bpf:license`).
- Maps. Each carries the C kind (`array`, `hash`, `ringbuf`, …), max entries (where applicable), and the resolved Go types of its key and value via the generic instantiation. Per-object storage maps (`TaskStorage`, `SkStorage`, `InodeStorage`) skip max entries because the kernel sizes them dynamically.
- Programs. Functions tagged `//bpf:section`.
- Helpers. Top-level functions without `//bpf:section`. Emitted as `static __always_inline` so the verifier inlines them at every call site.
- User struct types. Re-emitted in C with the same layout, and re-published verbatim in the bindings file so userspace can decode events without redeclaring them.
- User constants. Inlined as literals in emitted C; re-published with capitalized names in bindings.

The validator walks every program and every helper and rejects anything outside the supported subset. Diagnostics use the standard `file:line:col: message` format.

The emitter is an imperative AST walker. No templates, no DSLs. It writes C the way you'd write it by hand. The only special case is the comma-ok pattern on map lookups and storage `Get`s: `count, ok := PktCount.Lookup(&key)` becomes `__u64 *count = bpf_map_lookup_elem(&PktCount, &key);` with `ok` aliased to the pointer's truthiness for later checks.

## Why a tiny Go subset

The verifier rejects most of what regular Go assumes: heap allocation, dynamic dispatch, unbounded loops, runtime panics. So the subset is small on purpose. It tracks what BPF programs already look like in C, just spelled with Go syntax.

If you find yourself wanting `range`, `switch`, or `defer`, you're probably writing a userspace program in the wrong file. Move it to your driver.

## Map declarations are type-driven

The original brief proposed `type PktCount uint64` with `PktCount.Lookup(&key)`. That doesn't type-check in Go: you can't call methods on a type. So gobee uses a generic struct literal:

```go
var PktCount = bpf.ArrayMap[uint32, uint64]{MaxEntries: 1}
```

`go/types` resolves the generic instantiation. Map kind comes from the Go type (`ArrayMap`, `HashMap`, `LruHashMap`, `RingBuf`, `BloomFilter`, …). K and V come from the type arguments. `MaxEntries` from the struct literal. The user gets normal Go type safety. gopls hover and autocomplete just work.

There is no `//bpf:map` directive. Earlier drafts had one. It got removed once the type-driven approach proved cleaner.

## CO-RE only where it belongs

CO-RE relocations apply to kernel-internal structs whose field offsets shift across kernel versions: `struct task_struct`, `struct sock`, `struct file`. Reading those needs `BPF_CORE_READ`, which expands to `bpf_probe_read_kernel`.

UAPI BPF context structs (`struct xdp_md`, `struct __sk_buff`, `struct bpf_sock_ops`) are different. They're program-context pointers managed by the verifier, with stable layouts. Direct field access (`ctx->ingress_ifindex`) is the right answer there. Using `BPF_CORE_READ` on a context pointer expands to `bpf_probe_read_kernel(&dst, sizeof(dst), &ctx->field)`, which silently returns garbage at runtime because a context pointer isn't a kernel-memory address.

This bit us once: XDP packet counters stuck at zero with no error in any log. The fix was to flip context structs to direct access in the type table. CO-RE stayed for the structs that actually need it.

## Bindings: covering ebpf-go's load and attach surface

The generated `<stem>_bindings.go` exists so userspace doesn't restate things the BPF program code already declared. Three pieces:

1. **Programs and maps as typed struct fields**, with `ebpf:"<elf-name>"` tags. Loads via `cilium/ebpf`'s `LoadAndAssign`, replacing `coll.Programs["X"]` and `coll.Maps["Y"]` with `objs.X` and `objs.Y`.
2. **Per-program `Attach<Name>` helpers**, derived from each `//bpf:section` directive. XDP gets an ifindex parameter; tracepoints, kprobes, kretprobes take none. Plus `AttachAll(xdpIfindex int)` that runs them all and rolls back on failure.
3. **User struct types and constants** re-published. The `Event` struct lands in bindings verbatim so `binary.Read` on the userspace side has byte-identical layout. Lowercase consts (`kindExec`) become public in bindings (`KindExec`) so userspace can pattern-match without redeclaring values.

`Load<Stem>` also runs [bpfvet](https://github.com/boratanrikulu/bpfvet)'s portability analyzer on the spec before calling `LoadAndAssign`. If the running kernel is too old, you get `bpf program needs kernel >= 5.8, host is 5.4` instead of an opaque `EINVAL` from the verifier.

## Comparison to neighbors

- **Aya (Rust)** has a real BPF backend in rustc. Better story for Rust shops. Different language ecosystem.
- **libbpf + bpf2go** is the C-side incumbent. You write C by hand, bpf2go generates Go bindings. gobee replaces the "write C by hand" part. Everything else (clang, cilium/ebpf, your Makefile) keeps working.
- **miekg/bpf** tried generating BPF asm directly, got stuck, archived. We picked the C path.
