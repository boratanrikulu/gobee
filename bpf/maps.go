package bpf

import "unsafe"

var _ = unsafe.Sizeof(0) // keep the import live across edits

// Maps are declared at package scope as a struct literal of one of the
// types in this file. The kind of map (array / hash / ringbuf / ...) is
// determined by the Go type. The MaxEntries field is required and sets
// the kernel's max_entries.
//
// Example:
//
//	var PktCount = bpf.ArrayMap[uint32, uint64]{MaxEntries: 1}
//	var PerPid   = bpf.HashMap[uint32, uint64]{MaxEntries: 4096}
//	var Events   = bpf.RingBuf[Event]{MaxEntries: 4096}

// ArrayMap is a BPF_MAP_TYPE_ARRAY with the given key and value types.
type ArrayMap[K, V any] struct {
	MaxEntries uint32
}

func (*ArrayMap[K, V]) Lookup(key *K) (*V, bool)      { panic(stubMsg) }
func (*ArrayMap[K, V]) Update(key *K, value *V) error { panic(stubMsg) }
func (*ArrayMap[K, V]) Delete(key *K) error           { panic(stubMsg) }

// HashMap is a BPF_MAP_TYPE_HASH.
type HashMap[K, V any] struct {
	MaxEntries uint32
}

func (*HashMap[K, V]) Lookup(key *K) (*V, bool)      { panic(stubMsg) }
func (*HashMap[K, V]) Update(key *K, value *V) error { panic(stubMsg) }
func (*HashMap[K, V]) Delete(key *K) error           { panic(stubMsg) }

// LruHashMap is a BPF_MAP_TYPE_LRU_HASH. Behaves like HashMap but evicts
// the least-recently-used entry when full.
type LruHashMap[K, V any] struct {
	MaxEntries uint32
}

func (*LruHashMap[K, V]) Lookup(key *K) (*V, bool)      { panic(stubMsg) }
func (*LruHashMap[K, V]) Update(key *K, value *V) error { panic(stubMsg) }
func (*LruHashMap[K, V]) Delete(key *K) error           { panic(stubMsg) }

// PerCPUArray is a BPF_MAP_TYPE_PERCPU_ARRAY. Each CPU has its own copy of
// every slot; kernel-side Lookup returns the current CPU's slot.
type PerCPUArray[K, V any] struct {
	MaxEntries uint32
}

func (*PerCPUArray[K, V]) Lookup(key *K) (*V, bool)      { panic(stubMsg) }
func (*PerCPUArray[K, V]) Update(key *K, value *V) error { panic(stubMsg) }
func (*PerCPUArray[K, V]) Delete(key *K) error           { panic(stubMsg) }

// PerCPUHash is a BPF_MAP_TYPE_PERCPU_HASH. Like PerCPUArray but keyed by
// a hashable type instead of a 32-bit index.
type PerCPUHash[K, V any] struct {
	MaxEntries uint32
}

func (*PerCPUHash[K, V]) Lookup(key *K) (*V, bool)      { panic(stubMsg) }
func (*PerCPUHash[K, V]) Update(key *K, value *V) error { panic(stubMsg) }
func (*PerCPUHash[K, V]) Delete(key *K) error           { panic(stubMsg) }

// LruPerCPUHash is a BPF_MAP_TYPE_LRU_PERCPU_HASH.
type LruPerCPUHash[K, V any] struct {
	MaxEntries uint32
}

func (*LruPerCPUHash[K, V]) Lookup(key *K) (*V, bool)      { panic(stubMsg) }
func (*LruPerCPUHash[K, V]) Update(key *K, value *V) error { panic(stubMsg) }
func (*LruPerCPUHash[K, V]) Delete(key *K) error           { panic(stubMsg) }

// BloomFilter is a BPF_MAP_TYPE_BLOOM_FILTER. Bloom filters answer "have
// I seen X?" with no false negatives but possible false positives.
// They have no per-key value and no Delete operation.
type BloomFilter[T any] struct {
	MaxEntries uint32
}

// Add inserts an element. Always succeeds (a bloom filter never rejects).
func (*BloomFilter[T]) Add(value *T) error { panic(stubMsg) }

// Contains reports whether `value` may be in the filter. False positives
// are possible (rate decided by MaxEntries and the kernel's hash count);
// false negatives are not.
func (*BloomFilter[T]) Contains(value *T) bool { panic(stubMsg) }

// LpmTrie is a BPF_MAP_TYPE_LPM_TRIE. Longest-prefix-match lookups, useful
// for IP routing-style tables.
//
// The key type K must start with a `__u32 prefixlen` field; the rest of K
// is the matched bytes (e.g. an IPv4 address).
type LpmTrie[K, V any] struct {
	MaxEntries uint32
}

func (*LpmTrie[K, V]) Lookup(key *K) (*V, bool)      { panic(stubMsg) }
func (*LpmTrie[K, V]) Update(key *K, value *V) error { panic(stubMsg) }
func (*LpmTrie[K, V]) Delete(key *K) error           { panic(stubMsg) }

// Queue is a BPF_MAP_TYPE_QUEUE — FIFO of T values.
type Queue[T any] struct {
	MaxEntries uint32
}

func (*Queue[T]) Push(value *T) error { panic(stubMsg) }
func (*Queue[T]) Pop(value *T) error  { panic(stubMsg) }
func (*Queue[T]) Peek(value *T) error { panic(stubMsg) }

// Stack is a BPF_MAP_TYPE_STACK — LIFO of T values.
type Stack[T any] struct {
	MaxEntries uint32
}

func (*Stack[T]) Push(value *T) error { panic(stubMsg) }
func (*Stack[T]) Pop(value *T) error  { panic(stubMsg) }
func (*Stack[T]) Peek(value *T) error { panic(stubMsg) }

// ProgArray is a BPF_MAP_TYPE_PROG_ARRAY: a uint32-indexed table of BPF
// program references, used for tail calls.
//
// Userspace populates entries with program FDs; the kernel-side calls
// TailCall to redirect execution into the program at the given index.
// On success TailCall does not return.
type ProgArray struct {
	MaxEntries uint32
}

// TailCall jumps into the program registered at key. On success this
// never returns; on failure (key out of range, no program registered,
// or tail-call limit reached) it returns and the calling program
// continues.
func (*ProgArray) TailCall(ctx unsafe.Pointer, key uint32) { panic(stubMsg) }

// PerfEventArray is a BPF_MAP_TYPE_PERF_EVENT_ARRAY: per-CPU perf event
// buffers used to deliver events to userspace. For new code prefer
// RingBuf — perf_event_array is the older mechanism kept for kernels
// before 5.8.
type PerfEventArray[T any] struct {
	MaxEntries uint32
}

// Output emits one event into the per-CPU perf buffer. ctx is the BPF
// program's context pointer.
func (*PerfEventArray[T]) Output(ctx unsafe.Pointer, value *T) int64 { panic(stubMsg) }

// XDP redirect-target maps. These don't store user state; they tell
// the verifier that XDP_REDIRECT is allowed to point at the entries
// userspace populates. Each one has a `Redirect(ctx, key, flags)`
// kernel-side method that returns the matching XdpAction
// (XDP_REDIRECT on success, XDP_ABORTED on failure).

// DevMap is a BPF_MAP_TYPE_DEVMAP: ifindex table for XDP redirect.
// Userspace populates each slot with a network-interface index. The
// XDP program calls Redirect(ctx, slot, flags) to forward the packet
// out that interface.
type DevMap struct {
	MaxEntries uint32
}

// Redirect hands the current packet to the interface stored at key.
// The return value is the XdpAction the BPF program should return
// (typically XDP_REDIRECT on success, XDP_ABORTED on failure). ctx is
// the XDP program context; it's accepted so the call site reads like
// every other ctx-taking helper, even though the underlying
// bpf_redirect_map helper doesn't use it.
func (*DevMap) Redirect(ctx *XdpMd, key uint32, flags uint64) XdpAction {
	panic(stubMsg)
}

// CpuMap is a BPF_MAP_TYPE_CPUMAP: per-CPU dispatch for XDP redirect.
// Userspace pins each slot to a CPU plus an optional follow-up BPF
// program. Redirect(ctx, slot, flags) re-queues the packet onto that
// CPU for kernel-stack processing on a different core than the one
// that ran XDP.
type CpuMap struct {
	MaxEntries uint32
}

func (*CpuMap) Redirect(ctx *XdpMd, key uint32, flags uint64) XdpAction {
	panic(stubMsg)
}

// XskMap is a BPF_MAP_TYPE_XSKMAP: AF_XDP socket table for zero-copy
// userspace networking. Userspace pins each slot to an AF_XDP socket
// fd. Redirect(ctx, slot, flags) hands the packet to that socket's
// rx queue without copying it through the kernel network stack.
type XskMap struct {
	MaxEntries uint32
}

func (*XskMap) Redirect(ctx *XdpMd, key uint32, flags uint64) XdpAction {
	panic(stubMsg)
}

// Per-object storage maps below. These keep one V per kernel object —
// task / socket / inode — and don't need MaxEntries (the kernel sizes
// the map dynamically). The "key" is implicit: the kernel object itself
// is passed to every method.

// TaskStorage is a BPF_MAP_TYPE_TASK_STORAGE. Stores one V per
// `struct task_struct *`. Pass a task pointer obtained via
// `bpf.GetCurrentTaskBtf()` (or any other source).
type TaskStorage[V any] struct{}

// Get returns the entry for task or nil if no entry exists.
func (*TaskStorage[V]) Get(task unsafe.Pointer) (*V, bool) { panic(stubMsg) }

// GetOrCreate returns the entry for task, creating it (initialised
// from value) if it doesn't exist.
func (*TaskStorage[V]) GetOrCreate(task unsafe.Pointer, value *V) *V { panic(stubMsg) }

// Delete removes the entry for task.
func (*TaskStorage[V]) Delete(task unsafe.Pointer) error { panic(stubMsg) }

// SkStorage is a BPF_MAP_TYPE_SK_STORAGE. Stores one V per
// `struct sock *`. Available in sock_ops, cgroup_skb, and tracing
// programs that get a sock pointer.
type SkStorage[V any] struct{}

func (*SkStorage[V]) Get(sk unsafe.Pointer) (*V, bool)              { panic(stubMsg) }
func (*SkStorage[V]) GetOrCreate(sk unsafe.Pointer, value *V) *V    { panic(stubMsg) }
func (*SkStorage[V]) Delete(sk unsafe.Pointer) error                { panic(stubMsg) }

// InodeStorage is a BPF_MAP_TYPE_INODE_STORAGE. Stores one V per
// `struct inode *`. Common in LSM hooks and file-related tracing.
type InodeStorage[V any] struct{}

func (*InodeStorage[V]) Get(inode unsafe.Pointer) (*V, bool)           { panic(stubMsg) }
func (*InodeStorage[V]) GetOrCreate(inode unsafe.Pointer, value *V) *V { panic(stubMsg) }
func (*InodeStorage[V]) Delete(inode unsafe.Pointer) error             { panic(stubMsg) }
