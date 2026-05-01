# Examples

Small kernel-side `.go` fixtures, each demonstrating a different slice of the gobee surface. Inspired by [bpfvet's `testdata/src/`](https://github.com/boratanrikulu/bpfvet/tree/main/testdata) which uses one file per scenario.

These are not full programs (no userspace driver, no `main.go`). They're the kernel side only, used by `internal/transpile/examples_test.go` to confirm gobee handles each pattern end-to-end. Treat them as documentation by example.

| File | What it covers |
|---|---|
| `01_timestamps.go` | `KtimeGetNs` (zero-arg helper). `ArrayMap.Update` with a stack-local value. |
| `02_pidcount.go` | `GetCurrentPidTgid` (uint64 return used in arithmetic). `HashMap` with the standard "lookup, branch, atomic add or init" pattern. |
| `03_sample_drop.go` | `GetPrandomU32`. Returns `XdpDrop` on a fraction of packets. No maps. |
| `04_per_cpu_stats.go` | `GetSmpProcessorId`. CPU-keyed HashMap counter. |
| `05_combo.go` | Two helpers, two maps, branching. The `*prev` deref shows pointer-to-map-value semantics. |
| `06_tracepoint_openat.go` | Tracepoint program type. `//bpf:section tracepoint/syscalls/sys_enter_openat`. |
| `07_kprobe_tcp_connect.go` | Kprobe program type with `*bpf.PtRegs` context. |
| `08_uprobe_libc_malloc.go` | Uprobe section format `uprobe/<binary>:<sym>`. Same context as kprobe. |
| `09_sockops.go` | Sock-ops program type, `*bpf.SockOpsMd`, `bpf.SockOpsReturn` enum. |
| `10_tc_classifier.go` | TC classifier returning `bpf.TcOk`. `*bpf.SkBuff` context. |
| `11_cgroup_skb_egress.go` | Cgroup_skb egress program. `bpf.CgroupSkbAllow` return. |
| `12_lsm_file_open.go` | LSM hook with the generic `*bpf.LsmCtx` context. |
| `13_xdp_per_iface.go` | CO-RE field access on `ctx.IngressIfIndex` → `BPF_CORE_READ`. |
| `14_lru_hash.go` | `bpf.LruHashMap` (`type=lru_hash`). |
| `15_percpu_array.go` | `bpf.PerCPUArray` (`type=percpu_array`). |
| `16_ringbuf_exec.go` | Ringbuf event delivery: `bpf.RingBuf[Event]` with typed Reserve/Submit and a user struct payload. |
| `17_queue.go` | `bpf.Queue[T]` with `Push`. FIFO of values. |
| `18_stack.go` | `bpf.Stack[T]` with `Push`. LIFO of values. |
| `19_prog_array.go` | `bpf.ProgArray.TailCall(ctx, key)` for chained-program flows. |
| `20_perf_event_array.go` | `bpf.PerfEventArray[T].Output(ctx, &val)`. Legacy ringbuf alternative. |

For the full end-to-end demo (Makefile, clang invocation, userspace driver, attach to interface), see [`example/helloworld/`](../../example/helloworld/).

## Running

```bash
# Validate that all examples transpile cleanly
go test ./internal/transpile/ -run TestExamples

# Eyeball the C output for one
go run ./cmd/gobee translate ./testdata/examples
ls testdata/examples/*.bpf.c
```

## Adding a new example

1. Drop a kernel-side `.go` file under `testdata/examples/` with the next number prefix.
2. Pick something that isn't already covered. Aim for one new helper or one new pattern per example.
3. Add a row to the table above.
4. The test will pick it up automatically — no test changes needed.
