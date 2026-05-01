//go:build ignore

// Counts kprobe hits per process using task_storage. The map's key is
// implicit (the task_struct pointer); only V is given. The kernel sizes
// the map dynamically so no MaxEntries is set.

package main

import "github.com/boratanrikulu/gobee/bpf"

//bpf:license GPL

type Counter struct {
	Hits uint64
}

var perTask = bpf.TaskStorage[Counter]{}

//bpf:section kprobe/__x64_sys_openat
func CountOpens(ctx *bpf.PtRegs) bpf.KpReturn {
	task := bpf.GetCurrentTaskBtf()
	c, ok := perTask.Get(task)
	if !ok {
		var zero Counter
		c = perTask.GetOrCreate(task, &zero)
	}
	bpf.AtomicAdd64(&c.Hits, 1)
	return bpf.KpOk
}

func main() {}
