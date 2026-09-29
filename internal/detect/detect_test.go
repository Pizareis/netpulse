package detect

import (
	"testing"
	"time"

	"github.com/Pizareis/netpulse/internal/model"
)

type captured struct {
	kind string
	sev  model.Severity
}

type fakeRaiser struct{ got []captured }

func (f *fakeRaiser) Raise(kind string, sev model.Severity, _, _, _, _ string) {
	f.got = append(f.got, captured{kind, sev})
}

func (f *fakeRaiser) has(kind string, sev model.Severity) bool {
	for _, c := range f.got {
		if c.kind == kind && c.sev == sev {
			return true
		}
	}
	return false
}

func TestARPWatchGatewayMACChange(t *testing.T) {
	r := &fakeRaiser{}
	w := NewARPWatch("192.168.1.1", r)
	w.Observe(map[string]string{"192.168.1.1": "aa:aa:aa:aa:aa:aa", "192.168.1.20": "bb:bb:bb:bb:bb:bb"})
	if len(r.got) != 0 {
		t.Fatalf("baseline raised alerts: %v", r.got)
	}
	w.Observe(map[string]string{"192.168.1.1": "bb:bb:bb:bb:bb:bb", "192.168.1.20": "bb:bb:bb:bb:bb:bb"})
	if !r.has("arp_spoof", model.Critical) {
		t.Fatalf("expected critical arp_spoof, got %v", r.got)
	}
}

func TestARPWatchDHCPReassignIsOnlyWarning(t *testing.T) {
	r := &fakeRaiser{}
	w := NewARPWatch("192.168.1.1", r)
	w.Observe(map[string]string{"192.168.1.1": "aa:aa:aa:aa:aa:aa", "192.168.1.50": "cc:cc:cc:cc:cc:cc"})
	w.Observe(map[string]string{"192.168.1.1": "aa:aa:aa:aa:aa:aa", "192.168.1.50": "dd:dd:dd:dd:dd:dd"})
	if !r.has("mac_change", model.Warning) || r.has("arp_spoof", model.Critical) {
		t.Fatalf("expected only a mac_change warning, got %v", r.got)
	}
}

func TestTripwirePortScan(t *testing.T) {
	r := &fakeRaiser{}
	tw := NewTripwire(nil, 3, time.Minute, r)
	now := time.Now()
	tw.Record("10.0.0.9", 21, now)
	tw.Record("10.0.0.9", 23, now.Add(time.Second))
	if r.has("port_scan", model.Critical) {
		t.Fatal("port scan flagged too early")
	}
	tw.Record("10.0.0.9", 5900, now.Add(2*time.Second))
	if !r.has("port_scan", model.Critical) {
		t.Fatalf("expected port_scan, got %v", r.got)
	}
}

func TestTripwireWindowExpires(t *testing.T) {
	r := &fakeRaiser{}
	tw := NewTripwire(nil, 3, time.Minute, r)
	now := time.Now()
	tw.Record("10.0.0.9", 21, now)
	tw.Record("10.0.0.9", 23, now.Add(2*time.Minute))
	tw.Record("10.0.0.9", 5900, now.Add(4*time.Minute))
	if r.has("port_scan", model.Critical) {
		t.Fatal("slow, spread-out hits should not count as a scan")
	}
}

func TestSpikeDetector(t *testing.T) {
	d := &SpikeDetector{Alpha: 0.05, Factor: 5, MinBps: 1024, Warmup: 30}
	for i := 0; i < 60; i++ {
		if spike, _ := d.Check(50_000 + float64(i%5)*1000); spike {
			t.Fatalf("steady traffic flagged at sample %d", i)
		}
	}
	if spike, _ := d.Check(5_000_000); !spike {
		t.Fatal("100x burst not flagged")
	}
}
