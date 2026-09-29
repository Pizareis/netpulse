package discovery

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Pizareis/netpulse/internal/alert"
	"github.com/Pizareis/netpulse/internal/hub"
	"github.com/Pizareis/netpulse/internal/model"
	"github.com/Pizareis/netpulse/internal/store"
)

// Scanner periodically sweeps the subnet and keeps the device inventory.
type Scanner struct {
	local    *LocalNet
	store    *store.Store
	hub      *hub.Hub
	alerts   *alert.Manager
	interval time.Duration

	observers []func(ipToMAC map[string]string)
	trigger   chan struct{}
	scanning  atomic.Bool

	mu         sync.RWMutex
	devices    map[string]*model.Device // keyed by MAC
	lastScan   time.Time
	resolved   map[string]bool
	hadHistory bool
}

func NewScanner(local *LocalNet, st *store.Store, h *hub.Hub, am *alert.Manager, interval time.Duration) *Scanner {
	s := &Scanner{
		local:    local,
		store:    st,
		hub:      h,
		alerts:   am,
		interval: interval,
		trigger:  make(chan struct{}, 1),
		devices:  make(map[string]*model.Device),
		resolved: make(map[string]bool),
	}
	if known, err := st.Devices(); err == nil {
		for i := range known {
			d := known[i]
			s.devices[d.MAC] = &d
		}
		s.hadHistory = len(known) > 0
	}
	return s
}

// AddObserver registers a callback that receives every fresh ARP snapshot.
func (s *Scanner) AddObserver(fn func(ipToMAC map[string]string)) {
	s.observers = append(s.observers, fn)
}

// Trigger requests an immediate scan.
func (s *Scanner) Trigger() {
	select {
	case s.trigger <- struct{}{}:
	default:
	}
}

func (s *Scanner) Scanning() bool { return s.scanning.Load() }

func (s *Scanner) LastScan() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastScan
}

func (s *Scanner) Run(ctx context.Context) {
	s.scan(ctx)
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.scan(ctx)
		case <-s.trigger:
			s.scan(ctx)
		}
	}
}

func (s *Scanner) scan(ctx context.Context) {
	if !s.scanning.CompareAndSwap(false, true) {
		return
	}
	defer s.scanning.Store(false)
	started := time.Now()
	s.hub.Publish(model.Event{Type: "scan", Data: map[string]any{"state": "started"}})

	sweep(ctx, Hosts(s.local.Net, s.local.IP))
	select { // give ARP replies time to land in the neighbour table
	case <-ctx.Done():
		return
	case <-time.After(1500 * time.Millisecond):
	}

	entries, err := readARPTable(s.local.IP.String())
	if err != nil {
		log.Printf("scan: read ARP table: %v", err)
	}
	ipToMAC := map[string]string{}
	for _, e := range entries {
		if usableMAC(e.MAC) && isHostAddr(s.local.Net, net.ParseIP(e.IP)) {
			ipToMAC[e.IP] = e.MAC
		}
	}
	selfIP := s.local.IP.String()
	if s.local.MAC != "" {
		ipToMAC[selfIP] = s.local.MAC
	}

	now := time.Now()
	var fresh []model.Device
	s.mu.Lock()
	seen := map[string]bool{}
	for ip, mac := range ipToMAC {
		d, ok := s.devices[mac]
		if !ok {
			d = &model.Device{MAC: mac, FirstSeen: now}
			s.devices[mac] = d
		}
		if d.Vendor == "" {
			d.Vendor = LookupVendor(mac)
		}
		d.IP, d.LastSeen, d.Online = ip, now, true
		d.Gateway = ip == s.local.Gateway
		d.Self = ip == selfIP
		seen[mac] = true
		if !ok {
			fresh = append(fresh, *d)
		}
	}
	for mac, d := range s.devices {
		if !seen[mac] {
			d.Online = false
		}
	}
	s.lastScan = now
	firstBaseline := !s.hadHistory
	s.hadHistory = true
	s.mu.Unlock()

	for _, d := range s.snapshot() {
		if seen[d.MAC] {
			if err := s.store.UpsertDevice(d); err != nil {
				log.Printf("scan: store device: %v", err)
			}
		}
	}
	for _, fn := range s.observers {
		fn(ipToMAC)
	}

	if firstBaseline {
		s.alerts.Raise("baseline", model.Info, "first", "Initial scan complete",
			fmt.Sprintf("%d devices found on %s. They are now the known baseline.", len(ipToMAC), s.local.Net), selfIP)
	} else {
		for _, d := range fresh {
			label := d.Vendor
			if label == "" {
				label = "unknown vendor"
			}
			s.alerts.Raise("new_device", model.Warning, d.MAC, "New device joined the network",
				fmt.Sprintf("%s (%s, %s)", d.IP, d.MAC, label), d.IP)
		}
	}

	s.hub.Publish(model.Event{Type: "devices", Data: s.snapshot()})
	s.hub.Publish(model.Event{Type: "scan", Data: map[string]any{
		"state": "done", "count": len(ipToMAC), "duration_ms": time.Since(started).Milliseconds(),
	}})
	go s.resolveHostnames(ctx)
}

// sweep sends a tiny UDP datagram and a TCP SYN to every host. The packets
// themselves don't matter: they force the OS to ARP-resolve each address,
// which fills the neighbour table without needing raw sockets or admin rights.
func sweep(ctx context.Context, hosts []string) {
	sem := make(chan struct{}, 128)
	var wg sync.WaitGroup
	for _, h := range hosts {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(h string) {
			defer func() { <-sem; wg.Done() }()
			if c, err := net.Dial("udp4", net.JoinHostPort(h, "9")); err == nil {
				c.Write([]byte("netpulse"))
				c.Close()
			}
			if c, err := net.DialTimeout("tcp4", net.JoinHostPort(h, "80"), 300*time.Millisecond); err == nil {
				c.Close()
			}
		}(h)
	}
	wg.Wait()
}

// resolveHostnames does reverse DNS once per device that has no name yet.
func (s *Scanner) resolveHostnames(ctx context.Context) {
	s.mu.Lock()
	var todo []model.Device
	for _, d := range s.devices {
		if d.Hostname == "" && d.Online && !s.resolved[d.MAC] {
			s.resolved[d.MAC] = true
			todo = append(todo, *d)
		}
	}
	s.mu.Unlock()

	changed := false
	for _, d := range todo {
		lctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		names, err := net.DefaultResolver.LookupAddr(lctx, d.IP)
		cancel()
		if err != nil || len(names) == 0 {
			continue
		}
		name := strings.TrimSuffix(names[0], ".")
		s.mu.Lock()
		if cur, ok := s.devices[d.MAC]; ok {
			cur.Hostname = name
			d = *cur
		}
		s.mu.Unlock()
		s.store.UpsertDevice(d)
		changed = true
	}
	if changed {
		s.hub.Publish(model.Event{Type: "devices", Data: s.snapshot()})
	}
}

// Devices returns the inventory sorted by IP address.
func (s *Scanner) Devices() []model.Device { return s.snapshot() }

func (s *Scanner) snapshot() []model.Device {
	s.mu.RLock()
	out := make([]model.Device, 0, len(s.devices))
	for _, d := range s.devices {
		out = append(out, *d)
	}
	s.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		return bytes.Compare(net.ParseIP(out[i].IP).To4(), net.ParseIP(out[j].IP).To4()) < 0
	})
	return out
}
