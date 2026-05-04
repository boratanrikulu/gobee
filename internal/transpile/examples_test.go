package transpile

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestExamples discovers every kernel-side .go fixture under
// testdata/examples/ and asserts that gobee parses, validates, and emits
// each one without errors. Per-example assertions check for the specific
// C symbols the example is meant to demonstrate, so a regression in helper
// auto-translation surfaces here even before the byte-level golden test
// would catch it.
func TestExamples(t *testing.T) {
	cases := []struct {
		file         string
		mustEmitC    []string
		mustNotEmitC []string
	}{
		{
			file: "01_timestamps.go",
			mustEmitC: []string{
				`bpf_ktime_get_ns()`,
				`SEC("xdp")`,
				`SEC(".maps")`,
				`bpf_map_update_elem(&LastSeen, &key, &now, BPF_ANY)`,
			},
		},
		{
			file: "02_pidcount.go",
			mustEmitC: []string{
				`bpf_get_current_pid_tgid()`,
				`bpf_map_lookup_elem(&PerPid, &pid)`,
				`__sync_fetch_and_add(count, 1)`,
				`BPF_MAP_TYPE_HASH`,
			},
		},
		{
			file: "03_sample_drop.go",
			mustEmitC: []string{
				`bpf_get_prandom_u32()`,
				`return XDP_DROP;`,
				`return XDP_PASS;`,
			},
		},
		{
			file: "04_per_cpu_stats.go",
			mustEmitC: []string{
				`bpf_get_smp_processor_id()`,
				`bpf_map_lookup_elem(&PerCPU, &cpu)`,
			},
		},
		{
			file: "05_combo.go",
			mustEmitC: []string{
				`bpf_get_current_pid_tgid()`,
				`bpf_ktime_get_ns()`,
				`bpf_map_lookup_elem(&LastSeen, &pid)`,
				`bpf_map_update_elem(&DeltaNs, &pid, &delta, BPF_ANY)`,
				`(__u32)(pidTgid >> 32)`, // type conversion → C cast
				`*prev`,                  // pointer dereference
			},
		},
		{
			file: "06_tracepoint_openat.go",
			mustEmitC: []string{
				`SEC("tracepoint/syscalls/sys_enter_openat")`,
				`int HandleOpenat(void *ctx)`,
				`bpf_map_lookup_elem(&Opens, &key)`,
				`return 0;`, // bpf.TpOk
			},
		},
		{
			file: "07_kprobe_tcp_connect.go",
			mustEmitC: []string{
				`SEC("kprobe/tcp_connect")`,
				`int TcpConnectEntry(struct pt_regs *ctx)`,
				`bpf_map_lookup_elem(&Connects, &key)`,
			},
		},
		{
			file: "08_uprobe_libc_malloc.go",
			mustEmitC: []string{
				`SEC("uprobe/libc.so.6:malloc")`,
				`int MallocEntry(struct pt_regs *ctx)`,
			},
		},
		{
			file: "09_sockops.go",
			mustEmitC: []string{
				`SEC("sockops")`,
				`int CountEstablished(struct bpf_sock_ops *ctx)`,
				`return 1;`, // bpf.SockOpsOk
			},
		},
		{
			file: "10_tc_classifier.go",
			mustEmitC: []string{
				`SEC("classifier/ingress")`,
				`int PassThrough(struct __sk_buff *ctx)`,
				`return TC_ACT_OK;`,
			},
		},
		{
			file: "11_cgroup_skb_egress.go",
			mustEmitC: []string{
				`SEC("cgroup_skb/egress")`,
				`int CountEgress(struct __sk_buff *ctx)`,
				`return 1;`, // CgroupSkbAllow
			},
		},
		{
			file: "12_lsm_file_open.go",
			mustEmitC: []string{
				`SEC("lsm/file_open")`,
				`int AllowFileOpen(void *ctx)`,
				`return 0;`, // LsmAllow
			},
		},
		{
			file: "13_xdp_per_iface.go",
			mustEmitC: []string{
				`__u32 ifindex = ctx->ingress_ifindex;`,
				`bpf_map_lookup_elem(&PerIface, &ifindex)`,
			},
		},
		{
			file: "14_lru_hash.go",
			mustEmitC: []string{
				`__uint(type, BPF_MAP_TYPE_LRU_HASH);`,
				`bpf_map_lookup_elem(&PerPort, &port)`,
			},
		},
		{
			file: "15_percpu_array.go",
			mustEmitC: []string{
				`__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);`,
				`bpf_map_lookup_elem(&PerCPU, &key)`,
			},
		},
		{
			file: "16_ringbuf_exec.go",
			mustEmitC: []string{
				`struct ExecEvent {`,
				`__u32 Pid;`,
				`__u8 Comm[16];`,
				`__uint(type, BPF_MAP_TYPE_RINGBUF);`,
				`struct ExecEvent *e = bpf_ringbuf_reserve(&Events, sizeof(struct ExecEvent), 0);`,
				`if (!e) {`,
				`e->Pid = (__u32)(bpf_get_current_pid_tgid() >> 32);`,
				`bpf_ringbuf_submit(e, 0);`,
			},
		},
		{
			file: "17_queue.go",
			mustEmitC: []string{
				`__uint(type, BPF_MAP_TYPE_QUEUE);`,
				`__type(value, __u32);`,
				`bpf_map_push_elem(&Iface, &idx, 0);`,
			},
		},
		{
			file: "18_stack.go",
			mustEmitC: []string{
				`__uint(type, BPF_MAP_TYPE_STACK);`,
				`bpf_map_push_elem(&Recent, &idx, 0);`,
			},
		},
		{
			file: "19_prog_array.go",
			mustEmitC: []string{
				`__uint(type, BPF_MAP_TYPE_PROG_ARRAY);`,
				`__type(key, __u32);`,
				`__type(value, __u32);`,
				`bpf_tail_call(ctx, &Stages, stage);`,
			},
		},
		{
			file: "20_perf_event_array.go",
			mustEmitC: []string{
				`__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);`,
				`bpf_perf_event_output(ctx, &Events, BPF_F_CURRENT_CPU, &e, sizeof(*&e));`,
			},
			mustNotEmitC: []string{
				// Omitted MaxEntries lets libbpf auto-size to nr_cpus; no
				// max_entries line should appear in the emitted .maps section.
				`max_entries`,
			},
		},
		{
			file: "34_blank_lookup.go",
			mustEmitC: []string{
				// Two presence-only lookups in the same scope must not
				// collide; the emitter mints distinct synthetic names.
				`__u8 *_lookup1 = bpf_map_lookup_elem(&Deny, &key);`,
				`__u8 *_lookup2 = bpf_map_lookup_elem(&Allow, &key);`,
				`if (_lookup1) {`,
				`if (!_lookup2) {`,
			},
			mustNotEmitC: []string{
				// The literal Go blank identifier must never reach C.
				`*_ =`,
				`__u8 *_ `,
			},
		},
		{
			file: "33_endian.go",
			mustEmitC: []string{
				`#include <bpf/bpf_endian.h>`,
				`SEC("sockops")`,
				`bpf_ntohl(ctx->remote_port)`,
			},
		},
		{
			file: "32_sockops_cb_flags.go",
			mustEmitC: []string{
				`SEC("sockops")`,
				`int InstallWriteHdrCb(struct bpf_sock_ops *ctx)`,
				`ctx->bpf_sock_ops_cb_flags`,
				`BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG`,
				`bpf_sock_ops_cb_flags_set(ctx, (__s32)(flags))`,
			},
			mustNotEmitC: []string{
				// UAPI BPF context fields use direct ctx->field access; a
				// CO-RE read on the context pointer silently returns garbage.
				`BPF_CORE_READ(ctx, bpf_sock_ops_cb_flags)`,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			path, err := filepath.Abs(filepath.Join("../../testdata/examples", tc.file))
			if err != nil {
				t.Fatal(err)
			}
			prog, err := ParseFile(path)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if d := Validate(prog); len(d) != 0 {
				t.Fatalf("validate produced unexpected diagnostics:\n%s", d.Error())
			}
			out, _, err := Emit(prog, tc.file)
			if err != nil {
				t.Fatalf("emit: %v", err)
			}
			c := string(out)
			for _, want := range tc.mustEmitC {
				if !strings.Contains(c, want) {
					t.Errorf("emitted C missing %q\n--- got ---\n%s", want, c)
				}
			}
			for _, banned := range tc.mustNotEmitC {
				if strings.Contains(c, banned) {
					t.Errorf("emitted C unexpectedly contains %q\n--- got ---\n%s", banned, c)
				}
			}
		})
	}
}
