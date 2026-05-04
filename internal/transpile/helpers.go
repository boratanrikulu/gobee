package transpile

import "fmt"

// bpfHelperFuncs holds explicit Go-to-C name overrides for things that don't
// follow the auto-derived `Foo` → `bpf_foo` rule. Mostly clang intrinsics
// and other special cases. The vast majority of helpers are auto-translated
// via goNameToBpfHelper instead.
var bpfHelperFuncs = map[string]string{
	"AtomicAdd64": "__sync_fetch_and_add",
}

// bpfHelperExpansions are typed sugar wrappers in the bpf package that
// expand to specific C expressions instead of a single helper-name swap.
// argStrs are the already-formatted C arguments.
var bpfHelperExpansions = map[string]func(argStrs []string) (string, error){
	"GetCurrentPid": func(_ []string) (string, error) {
		return "(__u32)(bpf_get_current_pid_tgid() >> 32)", nil
	},
	"GetCurrentTid": func(_ []string) (string, error) {
		return "(__u32)(bpf_get_current_pid_tgid())", nil
	},
	"GetCurrentUid": func(_ []string) (string, error) {
		return "(__u32)(bpf_get_current_uid_gid())", nil
	},
	"GetCurrentGid": func(_ []string) (string, error) {
		return "(__u32)(bpf_get_current_uid_gid() >> 32)", nil
	},
	"GetTaskComm": func(args []string) (string, error) {
		if len(args) != 1 {
			return "", fmt.Errorf("GetTaskComm expects exactly one *[16]byte argument")
		}
		return fmt.Sprintf("bpf_get_current_comm(%s, 16)", args[0]), nil
	},
	"GetUserString": func(args []string) (string, error) {
		if len(args) != 2 {
			return "", fmt.Errorf("GetUserString expects (*[128]byte, uint64)")
		}
		return fmt.Sprintf("bpf_probe_read_user_str(%s, sizeof(*%s), (const char *)%s)", args[0], args[0], args[1]), nil
	},
	"GetUserArgv": func(args []string) (string, error) {
		if len(args) != 2 {
			return "", fmt.Errorf("GetUserArgv expects (*[256]byte, uint64)")
		}
		return fmt.Sprintf("gobee_read_user_argv((char *)%s, sizeof(*%s), (const char *const *)%s)", args[0], args[0], args[1]), nil
	},
}

// bpfPreludeHelpers are static C helper functions that get emitted at
// the top of the generated .bpf.c when the corresponding bpf-package
// sugar function is used. Keyed by the Go function name on the bpf
// package; the value is the verbatim C source.
var bpfPreludeHelpers = map[string]string{
	"GetUserArgv": `/* Reads up to 8 args, each truncated to 32 bytes, packed into fixed
 * slots. Constant offsets and sizes are required by the BPF verifier;
 * variable-stride writes get rejected. buf_size is fixed at 256. */
static __always_inline void gobee_read_user_argv(char *buf, int buf_size, const char *const *argv) {
	__builtin_memset(buf, 0, 256);
	#pragma unroll
	for (int i = 0; i < 8; i++) {
		const char *p;
		if (bpf_probe_read_user(&p, sizeof(p), &argv[i]) || !p) break;
		bpf_probe_read_user_str(buf + i * 32, 32, p);
	}
	(void)buf_size;
}
`,
}

// goNameToBpfHelper converts a `bpf` package Go function name back to its
// libbpf C helper name. Inverse of tools/genhelpers's goNameFor.
//
//	MapLookupElem      → bpf_map_lookup_elem
//	KtimeGetNs         → bpf_ktime_get_ns
//	GetCurrentPidTgid  → bpf_get_current_pid_tgid
func goNameToBpfHelper(goName string) string {
	var b []byte
	for i, r := range goName {
		if i > 0 && r >= 'A' && r <= 'Z' {
			b = append(b, '_')
		}
		if r >= 'A' && r <= 'Z' {
			r += 'a' - 'A'
		}
		b = append(b, byte(r))
	}
	return "bpf_" + string(b)
}

// bpfConstants maps `bpf.<Name>` package-level constants to their C-side
// representation. Some map to libbpf macros (XDP_PASS); some are literal
// values that the kernel side conventionally returns (0 for tracepoints).
var bpfConstants = map[string]string{
	"XdpAborted":  "XDP_ABORTED",
	"XdpDrop":     "XDP_DROP",
	"XdpPass":     "XDP_PASS",
	"XdpTx":       "XDP_TX",
	"XdpRedirect": "XDP_REDIRECT",
	"TpOk":        "0",
	"KpOk":        "0",
	"SockOpsErr":  "0",
	"SockOpsOk":   "1",

	// Sock-ops op codes (kernel BPF_SOCK_OPS_* constants).
	"BpfSockOpsVoid":                 "BPF_SOCK_OPS_VOID",
	"BpfSockOpsTimeoutInit":          "BPF_SOCK_OPS_TIMEOUT_INIT",
	"BpfSockOpsRwndInit":             "BPF_SOCK_OPS_RWND_INIT",
	"BpfSockOpsTcpConnectCb":         "BPF_SOCK_OPS_TCP_CONNECT_CB",
	"BpfSockOpsActiveEstablishedCb":  "BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB",
	"BpfSockOpsPassiveEstablishedCb": "BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB",
	"BpfSockOpsNeedsEcn":             "BPF_SOCK_OPS_NEEDS_ECN",
	"BpfSockOpsBaseRtt":              "BPF_SOCK_OPS_BASE_RTT",
	"BpfSockOpsRtoCb":                "BPF_SOCK_OPS_RTO_CB",
	"BpfSockOpsRetransCb":            "BPF_SOCK_OPS_RETRANS_CB",
	"BpfSockOpsStateCb":              "BPF_SOCK_OPS_STATE_CB",
	"BpfSockOpsTcpListenCb":          "BPF_SOCK_OPS_TCP_LISTEN_CB",
	"BpfSockOpsRttCb":                "BPF_SOCK_OPS_RTT_CB",
	"BpfSockOpsParseHdrOptCb":        "BPF_SOCK_OPS_PARSE_HDR_OPT_CB",
	"BpfSockOpsHdrOptLenCb":          "BPF_SOCK_OPS_HDR_OPT_LEN_CB",
	"BpfSockOpsWriteHdrOptCb":        "BPF_SOCK_OPS_WRITE_HDR_OPT_CB",

	// Sock-ops callback flag bits (kernel BPF_SOCK_OPS_*_CB_FLAG).
	"BpfSockOpsRtoCbFlag":                "BPF_SOCK_OPS_RTO_CB_FLAG",
	"BpfSockOpsRetransCbFlag":            "BPF_SOCK_OPS_RETRANS_CB_FLAG",
	"BpfSockOpsStateCbFlag":              "BPF_SOCK_OPS_STATE_CB_FLAG",
	"BpfSockOpsRttCbFlag":                "BPF_SOCK_OPS_RTT_CB_FLAG",
	"BpfSockOpsParseAllHdrOptCbFlag":     "BPF_SOCK_OPS_PARSE_ALL_HDR_OPT_CB_FLAG",
	"BpfSockOpsParseUnknownHdrOptCbFlag": "BPF_SOCK_OPS_PARSE_UNKNOWN_HDR_OPT_CB_FLAG",
	"BpfSockOpsWriteHdrOptCbFlag":        "BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG",

	// TC actions (kernel pkt_cls.h enum).
	"TcUnspec":     "TC_ACT_UNSPEC",
	"TcOk":         "TC_ACT_OK",
	"TcReclassify": "TC_ACT_RECLASSIFY",
	"TcShot":       "TC_ACT_SHOT",
	"TcPipe":       "TC_ACT_PIPE",
	"TcStolen":     "TC_ACT_STOLEN",
	"TcQueued":     "TC_ACT_QUEUED",
	"TcRepeat":     "TC_ACT_REPEAT",
	"TcRedirect":   "TC_ACT_REDIRECT",
	"TcTrap":       "TC_ACT_TRAP",

	// cgroup_skb return values.
	"CgroupSkbDrop":  "0",
	"CgroupSkbAllow": "1",

	// LSM return values.
	"LsmAllow": "0",
	"LsmDeny":  "-1",
}

// mapTypeToC maps the directive value (`array`, `hash`) to the libbpf macro
// constant used in `__uint(type, ...)`.
var mapTypeToC = map[string]string{
	"array":            "BPF_MAP_TYPE_ARRAY",
	"hash":             "BPF_MAP_TYPE_HASH",
	"lru_hash":         "BPF_MAP_TYPE_LRU_HASH",
	"percpu_array":     "BPF_MAP_TYPE_PERCPU_ARRAY",
	"percpu_hash":      "BPF_MAP_TYPE_PERCPU_HASH",
	"lru_percpu_hash":  "BPF_MAP_TYPE_LRU_PERCPU_HASH",
	"bloom_filter":     "BPF_MAP_TYPE_BLOOM_FILTER",
	"lpm_trie":         "BPF_MAP_TYPE_LPM_TRIE",
	"ringbuf":          "BPF_MAP_TYPE_RINGBUF",
	"queue":            "BPF_MAP_TYPE_QUEUE",
	"stack":            "BPF_MAP_TYPE_STACK",
	"prog_array":       "BPF_MAP_TYPE_PROG_ARRAY",
	"perf_event_array": "BPF_MAP_TYPE_PERF_EVENT_ARRAY",
	"task_storage":     "BPF_MAP_TYPE_TASK_STORAGE",
	"sk_storage":       "BPF_MAP_TYPE_SK_STORAGE",
	"inode_storage":    "BPF_MAP_TYPE_INODE_STORAGE",
	"devmap":           "BPF_MAP_TYPE_DEVMAP",
	"cpumap":           "BPF_MAP_TYPE_CPUMAP",
	"xskmap":           "BPF_MAP_TYPE_XSKMAP",
}

// mapMethodToHelper maps the Go-side method name to the BPF helper. Bloom
// filter's Add and Contains are handled separately because they don't
// follow the lookup/update/delete pattern.
var mapMethodToHelper = map[string]string{
	"Lookup": "bpf_map_lookup_elem",
	"Update": "bpf_map_update_elem",
	"Delete": "bpf_map_delete_elem",
}

// kernelMapGoTypes is the set of Go types in the bpf package that
// represent BPF maps with the standard lookup/update/delete shape.
var kernelMapGoTypes = map[string]bool{
	"ArrayMap":      true,
	"HashMap":       true,
	"LruHashMap":    true,
	"PerCPUArray":   true,
	"PerCPUHash":    true,
	"LruPerCPUHash": true,
	"LpmTrie":       true,
}

// storageMapHelpers maps each per-object storage map type to its
// kernel helper functions. Get / GetOrCreate route to <scope>_get
// (with different flag args); Delete to <scope>_delete.
var storageMapHelpers = map[string]struct {
	GetFn    string
	DeleteFn string
}{
	"TaskStorage":  {"bpf_task_storage_get", "bpf_task_storage_delete"},
	"SkStorage":    {"bpf_sk_storage_get", "bpf_sk_storage_delete"},
	"InodeStorage": {"bpf_inode_storage_get", "bpf_inode_storage_delete"},
}

// redirectMapTypes is the set of Go-side map types whose `Redirect`
// method routes through bpf_redirect_map. They differ in what
// userspace puts in each slot (ifindex / cpu / xsk fd) but the
// kernel-side helper is the same.
var redirectMapTypes = map[string]bool{
	"DevMap": true,
	"CpuMap": true,
	"XskMap": true,
}

// bpfMapGoTypeToDirective maps each Go map type in the bpf package to its
// BPF map kind. Used by the parser to recognize package-level map
// declarations without a //bpf:map directive — the Go type alone tells us
// which kernel BPF_MAP_TYPE_* to emit.
var bpfMapGoTypeToDirective = map[string]string{
	"ArrayMap":       "array",
	"HashMap":        "hash",
	"LruHashMap":     "lru_hash",
	"PerCPUArray":    "percpu_array",
	"PerCPUHash":     "percpu_hash",
	"LruPerCPUHash":  "lru_percpu_hash",
	"BloomFilter":    "bloom_filter",
	"LpmTrie":        "lpm_trie",
	"RingBuf":        "ringbuf",
	"Queue":          "queue",
	"Stack":          "stack",
	"ProgArray":      "prog_array",
	"PerfEventArray": "perf_event_array",
	"TaskStorage":    "task_storage",
	"SkStorage":      "sk_storage",
	"InodeStorage":   "inode_storage",
	"DevMap":         "devmap",
	"CpuMap":         "cpumap",
	"XskMap":         "xskmap",
}
