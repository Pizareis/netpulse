package discovery

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ARPEntry is one IP-to-MAC mapping from the OS neighbour table.
type ARPEntry struct {
	IP  string
	MAC string
}

// Matches Windows ("192.168.1.1   aa-bb-cc-dd-ee-ff   dynamic") and BSD/macOS
// ("? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0") arp output.
var arpLineRe = regexp.MustCompile(`(\d{1,3}(?:\.\d{1,3}){3})\)?\s+(?:at\s+)?([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})\b`)

func parseARP(out string) []ARPEntry {
	var entries []ARPEntry
	for _, line := range strings.Split(out, "\n") {
		m := arpLineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		entries = append(entries, ARPEntry{IP: m[1], MAC: normalizeMAC(m[2])})
	}
	return entries
}

// parseProcARP parses Linux /proc/net/arp.
func parseProcARP(data string) []ARPEntry {
	var entries []ARPEntry
	lines := strings.Split(data, "\n")
	for _, line := range lines[1:] {
		f := strings.Fields(line)
		if len(f) < 4 || f[2] == "0x0" { // 0x0 = incomplete
			continue
		}
		entries = append(entries, ARPEntry{IP: f[0], MAC: normalizeMAC(f[3])})
	}
	return entries
}

// normalizeMAC converts any common MAC notation to lower-case aa:bb:cc:dd:ee:ff.
func normalizeMAC(s string) string {
	parts := strings.FieldsFunc(strings.ToLower(s), func(r rune) bool { return r == ':' || r == '-' })
	if len(parts) != 6 {
		return strings.ToLower(s)
	}
	for i, p := range parts {
		v, err := strconv.ParseUint(p, 16, 8)
		if err != nil {
			return strings.ToLower(s)
		}
		parts[i] = fmt.Sprintf("%02x", v)
	}
	return strings.Join(parts, ":")
}

// usableMAC filters out empty, broadcast and multicast addresses.
func usableMAC(mac string) bool {
	if mac == "" || mac == "00:00:00:00:00:00" || mac == "ff:ff:ff:ff:ff:ff" {
		return false
	}
	first, err := strconv.ParseUint(mac[:2], 16, 8)
	return err == nil && first&0x01 == 0
}
