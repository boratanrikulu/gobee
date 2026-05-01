package bpf

const stubMsg = "gobee: kernel-only stub; this file must be transpiled with `gobee build`, not run as Go"

// AtomicAdd64 atomically adds delta to *addr. Transpiles to
// __sync_fetch_and_add(addr, delta) in BPF C.
func AtomicAdd64(addr *uint64, delta uint64) { panic(stubMsg) }
