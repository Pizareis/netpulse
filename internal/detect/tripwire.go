package detect

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/Pizareis/netpulse/internal/model"
)

// Tripwire detects port scans with honeypot ports: it listens on ports
// nothing legitimate should use and treats any connection as suspicious.
// One source touching several of them within a short window is a scan.
type Tripwire struct {
	ports     []int
	threshold int
	window    time.Duration
	alerts    Raiser

	mu   sync.Mutex
	hits map[string][]hit // source ip -> recent hits
}

type hit struct {
	port int
	at   time.Time
}

func NewTripwire(ports []int, threshold int, window time.Duration, alerts Raiser) *Tripwire {
	return &Tripwire{ports: ports, threshold: threshold, window: window, alerts: alerts, hits: make(map[string][]hit)}
}

// Start opens the listeners and returns the ports that could be bound.
func (t *Tripwire) Start(ctx context.Context) []int {
	var active []int
	for _, p := range t.ports {
		ln, err := net.Listen("tcp4", fmt.Sprintf(":%d", p))
		if err != nil {
			log.Printf("tripwire: port %d unavailable: %v", p, err)
			continue
		}
		active = append(active, p)
		go func() { <-ctx.Done(); ln.Close() }()
		go t.serve(ln, p)
	}
	return active
}

func (t *Tripwire) serve(ln net.Listener, port int) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		src, _, _ := net.SplitHostPort(c.RemoteAddr().String())
		c.Close()
		t.Record(src, port, time.Now())
	}
}

// Record registers a connection from src to a tripwire port.
func (t *Tripwire) Record(src string, port int, now time.Time) {
	t.mu.Lock()
	recent := t.hits[src][:0]
	for _, h := range t.hits[src] {
		if now.Sub(h.at) <= t.window {
			recent = append(recent, h)
		}
	}
	recent = append(recent, hit{port, now})
	t.hits[src] = recent
	distinct := map[int]bool{}
	for _, h := range recent {
		distinct[h.port] = true
	}
	t.mu.Unlock()

	if len(distinct) >= t.threshold {
		ports := make([]int, 0, len(distinct))
		for p := range distinct {
			ports = append(ports, p)
		}
		sort.Ints(ports)
		t.alerts.Raise("port_scan", model.Critical, src, "Port scan detected",
			fmt.Sprintf("%s probed %d honeypot ports within %s: %v", src, len(ports), t.window, ports), src)
		return
	}
	t.alerts.Raise("tripwire", model.Warning, fmt.Sprintf("%s:%d", src, port), "Connection to honeypot port",
		fmt.Sprintf("%s connected to port %d, which no legitimate service uses.", src, port), src)
}
