package detect

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/Pizareis/netpulse/internal/model"
)

// ARPWatch detects ARP spoofing by tracking IP-to-MAC bindings over time.
//
// An attacker poisoning the LAN answers ARP requests for the gateway with
// their own MAC, so two symptoms appear in the neighbour table: the gateway's
// MAC suddenly changes, and one MAC ends up claiming both the gateway's IP
// and the attacker's own IP.
type ARPWatch struct {
	gateway string
	alerts  Raiser

	mu    sync.Mutex
	known map[string]string // ip -> mac
}

func NewARPWatch(gateway string, alerts Raiser) *ARPWatch {
	return &ARPWatch{gateway: gateway, alerts: alerts, known: make(map[string]string)}
}

func (w *ARPWatch) Observe(ipToMAC map[string]string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	for ip, mac := range ipToMAC {
		old, ok := w.known[ip]
		w.known[ip] = mac
		if !ok || old == mac {
			continue
		}
		if ip == w.gateway {
			w.alerts.Raise("arp_spoof", model.Critical, ip, "Gateway MAC changed - possible ARP spoofing",
				fmt.Sprintf("Gateway %s moved from %s to %s. If you did not replace your router, someone may be intercepting traffic.", ip, old, mac), ip)
		} else {
			w.alerts.Raise("mac_change", model.Warning, ip, "IP address changed hands",
				fmt.Sprintf("%s moved from %s to %s (usually DHCP reassignment).", ip, old, mac), ip)
		}
	}

	byMAC := map[string][]string{}
	for ip, mac := range ipToMAC {
		byMAC[mac] = append(byMAC[mac], ip)
	}
	gatewayMAC := ipToMAC[w.gateway]
	for mac, ips := range byMAC {
		if len(ips) < 2 {
			continue
		}
		sort.Strings(ips)
		list := strings.Join(ips, ", ")
		if gatewayMAC != "" && mac == gatewayMAC {
			w.alerts.Raise("arp_spoof", model.Critical, mac, "Gateway MAC is shared with another host - ARP spoofing suspected",
				fmt.Sprintf("%s answers for %s. Another device is impersonating the gateway.", mac, list), mac)
		} else {
			w.alerts.Raise("dup_mac", model.Warning, mac, "One MAC answers for several IPs",
				fmt.Sprintf("%s answers for %s. Normal behind a Wi-Fi repeater, suspicious otherwise.", mac, list), mac)
		}
	}
}
