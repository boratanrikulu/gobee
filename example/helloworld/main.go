//go:build linux

// helloworld is the canonical gobee end-to-end example. It loads the
// counter.bpf.o produced by clang from gobee's emitted C, attaches the
// CountPackets XDP program to a network interface, and prints the packet
// counter every second. The userspace plumbing is plain cilium/ebpf — gobee
// does not appear at runtime.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"example.com/gobee-helloworld/bpf"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("usage: %s <interface>", os.Args[0])
	}
	ifaceName := os.Args[1]

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove memlock: %v", err)
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("interface %s: %v", ifaceName, err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpf.Program))
	if err != nil {
		log.Fatalf("load spec: %v", err)
	}
	objs, err := bpf.LoadCounter(spec)
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			log.Println("verifier rejected the program. Full log follows:")
			fmt.Fprintln(os.Stderr, "----- begin verifier log -----")
			fmt.Fprintln(os.Stderr, strings.Join(verr.Log, "\n"))
			fmt.Fprintln(os.Stderr, "----- end verifier log -----")
		}
		log.Fatalf("load counter: %v", err)
	}
	defer objs.Close()

	links, err := objs.AttachAll(iface.Index)
	if err != nil {
		log.Fatalf("attach: %v", err)
	}
	defer func() {
		for _, l := range links {
			l.Close()
		}
	}()
	log.Printf("attached XDP to %s, ctrl-c to detach", ifaceName)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	key := uint32(iface.Index)
	var count uint64
	for {
		select {
		case <-sig:
			log.Printf("final count on %s: %d", ifaceName, count)
			return
		case <-ticker.C:
			if err := objs.PerIface.Lookup(&key, &count); err != nil {
				if errors.Is(err, ebpf.ErrKeyNotExist) {
					log.Printf("packets on %s: 0 (no entry yet)", ifaceName)
					continue
				}
				log.Printf("lookup: %v", err)
				continue
			}
			log.Printf("packets on %s: %d", ifaceName, count)
		}
	}
}
