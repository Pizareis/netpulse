package discovery

import (
	"net"
	"testing"
)

func TestParseARPWindows(t *testing.T) {
	out := `
Interface: 192.168.1.34 --- 0xb
  Internet Address      Physical Address      Type
  192.168.1.1           a4-2b-b0-11-22-33     dynamic
  192.168.1.20          b8-27-eb-aa-bb-cc     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
`
	got := parseARP(out)
	if len(got) != 4 {
		t.Fatalf("got %d entries, want 4: %v", len(got), got)
	}
	if got[1].MAC != "b8:27:eb:aa:bb:cc" || got[1].IP != "192.168.1.20" {
		t.Fatalf("bad entry: %+v", got[1])
	}
	if usableMAC(got[2].MAC) || usableMAC(got[3].MAC) {
		t.Fatal("broadcast/multicast MACs must be filtered")
	}
}

func TestParseARPMacOS(t *testing.T) {
	got := parseARP("? (192.168.0.1) at 0:1a:2b:3c:4d:5e on en0 ifscope [ethernet]\n")
	if len(got) != 1 || got[0].MAC != "00:1a:2b:3c:4d:5e" {
		t.Fatalf("got %v", got)
	}
}

func TestHosts(t *testing.T) {
	_, n, _ := net.ParseCIDR("192.168.1.0/24")
	hosts := Hosts(n, net.ParseIP("192.168.1.34"))
	if len(hosts) != 254 || hosts[0] != "192.168.1.1" || hosts[253] != "192.168.1.254" {
		t.Fatalf("unexpected hosts: %d %s..%s", len(hosts), hosts[0], hosts[len(hosts)-1])
	}
	_, big, _ := net.ParseCIDR("10.0.0.0/8")
	if got := len(Hosts(big, net.ParseIP("10.1.2.3"))); got != 254 {
		t.Fatalf("large subnet should clamp to /24, got %d hosts", got)
	}
}

func TestVendor(t *testing.T) {
	if v := LookupVendor("b8:27:eb:00:00:01"); v != "Raspberry Pi" {
		t.Fatalf("got %q", v)
	}
	if v := LookupVendor("da:11:22:33:44:55"); v != "Private (randomized MAC)" {
		t.Fatalf("got %q", v)
	}
}
