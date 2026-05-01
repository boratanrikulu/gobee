//go:build linux

// sysmon attaches four BPF programs (XDP packet counter, tracepoints on
// execve and openat, and a kprobe on tcp_connect) and prints a unified
// log of system activity. Event-driven hits come over a shared ringbuf;
// per-interface packet counts are polled from a hash map.
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"example.com/sysmon/bpf"
)

func main() {
	all := flag.Bool("all", false, "show events from system daemons (root) too; default hides UID 0")
	showOpen := flag.Bool("show-open", false, "include [open] events; default skips them because openat fires for every shared-library load and floods the output")
	allExits := flag.Bool("all-exits", false, "include [exit] events for PIDs we never saw exec; default hides them (they're usually shell forks that never exec'd)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [flags] [<interface>]\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "<interface> is optional; pass it to also attach the XDP packet counter.")
		flag.PrintDefaults()
	}
	flag.Parse()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove memlock: %v", err)
	}

	var iface *net.Interface
	if flag.NArg() >= 1 {
		ifaceName := flag.Arg(0)
		i, err := net.InterfaceByName(ifaceName)
		if err != nil {
			log.Fatalf("interface %s: %v", ifaceName, err)
		}
		iface = i
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpf.Program))
	if err != nil {
		log.Fatalf("load spec: %v", err)
	}
	objs, err := bpf.LoadSysmon(spec)
	if err != nil {
		log.Fatalf("load sysmon: %v", err)
	}
	defer objs.Close()

	xdpIdx := 0
	if iface != nil {
		xdpIdx = iface.Index
	}
	links, err := objs.AttachAll(xdpIdx)
	if err != nil {
		log.Fatalf("attach: %v", err)
	}
	defer func() {
		for _, l := range links {
			l.Close()
		}
	}()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("ringbuf reader: %v", err)
	}
	defer rd.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	var stdoutMu sync.Mutex
	emit := func(s string) {
		stdoutMu.Lock()
		defer stdoutMu.Unlock()
		fmt.Println(s)
	}

	if iface != nil {
		emit(fmt.Sprintf("sysmon: tracing execve, openat, tcp_connect; XDP attached to %s. ctrl-c to stop.", iface.Name))
	} else {
		emit("sysmon: tracing execve, openat, tcp_connect (no XDP iface). ctrl-c to stop.")
	}

	// Goroutine 1: ringbuf reader
	done := make(chan struct{})
	go func() {
		defer close(done)
		var ev bpf.Event
		// Track which PIDs we've actually seen execve for, so we can hide
		// [exit] events from shell forks that never called exec (zsh
		// subshells, command substitution, etc.).
		seenExec := make(map[uint32]struct{})
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				emit(fmt.Sprintf("read: %v", err))
				continue
			}
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &ev); err != nil {
				emit(fmt.Sprintf("decode: %v", err))
				continue
			}
			if !*all && ev.Uid == 0 {
				continue
			}
			if !*showOpen && ev.Kind == bpf.KindOpen {
				continue
			}
			switch ev.Kind {
			case bpf.KindExec:
				seenExec[ev.Pid] = struct{}{}
			case bpf.KindProcExit:
				_, ok := seenExec[ev.Pid]
				if !ok && !*allExits {
					continue
				}
				delete(seenExec, ev.Pid)
			case bpf.KindExecFailed:
				// Pair this with the [exec] we already emitted; the
				// shell's [exit] for the same pid that follows is a
				// legitimate user event so we keep the pid in the set.
			}
			emit(formatEvent(&ev))
		}
	}()

	// Goroutine 2: periodic packet-count poll. Only runs if XDP was attached.
	if iface != nil {
		pkts := objs.PacketsByIface
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		readPkts := func() uint64 {
			key := uint32(iface.Index)
			var count uint64
			// ErrKeyNotExist means XDP fired zero times so far — report 0.
			_ = pkts.Lookup(&key, &count)
			return count
		}

		go func() {
			emit(fmt.Sprintf("[stats] iface=%s packets=%d", iface.Name, readPkts()))
			for range ticker.C {
				emit(fmt.Sprintf("[stats] iface=%s packets=%d", iface.Name, readPkts()))
			}
		}()
	}

	<-sig
	rd.Close()
	<-done
}

func formatEvent(ev *bpf.Event) string {
	switch ev.Kind {
	case bpf.KindExec:
		args := decodeArgs(ev.Args)
		return fmt.Sprintf("[exec] pid=%-6d uid=%-4d %-16s %s", ev.Pid, ev.Uid, cstr(ev.Comm[:]), args)
	case bpf.KindExecFailed:
		errno := syscall.Errno(-ev.Ret)
		return fmt.Sprintf("[fail] pid=%-6d uid=%-4d %-16s execve → %d (%s)", ev.Pid, ev.Uid, cstr(ev.Comm[:]), ev.Ret, errno.Error())
	case bpf.KindProcExit:
		return fmt.Sprintf("[exit] pid=%-6d uid=%-4d %-16s status=%d", ev.Pid, ev.Uid, cstr(ev.Comm[:]), ev.Ret)
	case bpf.KindOpen:
		return fmt.Sprintf("[open] pid=%-6d uid=%-4d %-16s %s", ev.Pid, ev.Uid, cstr(ev.Comm[:]), cstr(ev.Path[:]))
	case bpf.KindTcpConnect:
		return fmt.Sprintf("[tcp ] pid=%-6d uid=%-4d %-16s tcp_connect", ev.Pid, ev.Uid, cstr(ev.Comm[:]))
	default:
		return fmt.Sprintf("[??  ] kind=%d pid=%d", ev.Kind, ev.Pid)
	}
}

// decodeArgs joins the 8 fixed-size 32-byte slots produced by the
// kernel's gobee_read_user_argv helper into a single space-separated
// string. Empty slots terminate the list early.
func decodeArgs(buf [256]byte) string {
	parts := make([]string, 0, 8)
	for i := 0; i < 8; i++ {
		s := cstr(buf[i*32 : (i+1)*32])
		if s == "" {
			break
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, " ")
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}
