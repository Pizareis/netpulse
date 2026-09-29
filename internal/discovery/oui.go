package discovery

import (
	"bufio"
	"os"
	"strings"
	"sync"
)

// A small built-in vendor table covering devices common on home networks.
// Load a full Wireshark "manuf" file with LoadOUIFile for complete coverage.
var ouiTable = map[string]string{
	"b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi", "d8:3a:dd": "Raspberry Pi", "2c:cf:67": "Raspberry Pi",
	"24:0a:c4": "Espressif", "30:ae:a4": "Espressif", "84:cc:a8": "Espressif", "a4:cf:12": "Espressif", "24:6f:28": "Espressif",
	"3c:71:bf": "Espressif", "8c:aa:b5": "Espressif", "ec:fa:bc": "Espressif", "60:01:94": "Espressif", "5c:cf:7f": "Espressif",
	"18:fe:34": "Espressif", "cc:50:e3": "Espressif", "98:f4:ab": "Espressif",
	"00:50:56": "VMware", "00:0c:29": "VMware", "00:05:69": "VMware",
	"08:00:27": "VirtualBox", "00:15:5d": "Microsoft Hyper-V", "52:54:00": "QEMU/KVM",
	"00:1a:11": "Google", "f4:f5:d8": "Google", "f4:f5:e8": "Google", "3c:5a:b4": "Google", "54:60:09": "Google",
	"44:65:0d": "Amazon", "74:c2:46": "Amazon", "fc:65:de": "Amazon", "68:37:e9": "Amazon",
	"00:03:93": "Apple", "00:0a:95": "Apple", "00:1b:63": "Apple", "00:1e:c2": "Apple", "00:25:00": "Apple",
	"28:cf:e9": "Apple", "3c:07:54": "Apple", "40:6c:8f": "Apple", "ac:bc:32": "Apple", "f0:18:98": "Apple",
	"a4:83:e7": "Apple", "8c:85:90": "Apple", "f0:99:bf": "Apple",
	"50:c7:bf": "TP-Link", "f4:f2:6d": "TP-Link", "14:cc:20": "TP-Link", "c0:25:e9": "TP-Link", "98:de:d0": "TP-Link",
	"ec:08:6b": "TP-Link", "60:e3:27": "TP-Link",
	"64:09:80": "Xiaomi", "f8:a4:5f": "Xiaomi", "28:6c:07": "Xiaomi", "78:11:dc": "Xiaomi", "50:64:2b": "Xiaomi",
	"00:17:88": "Philips Hue", "00:0e:58": "Sonos", "5c:aa:fd": "Sonos", "b8:e9:37": "Sonos",
	"00:09:bf": "Nintendo", "98:b6:e9": "Nintendo",
	"24:a4:3c": "Ubiquiti", "f0:9f:c2": "Ubiquiti", "78:8a:20": "Ubiquiti", "fc:ec:da": "Ubiquiti",
	"00:1b:21": "Intel",
}

var ouiMu sync.RWMutex

// LoadOUIFile merges a Wireshark "manuf" file (prefix<TAB>short<TAB>long) into
// the vendor table. It returns the number of entries loaded.
func LoadOUIFile(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	loaded := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 2 || strings.Contains(fields[0], "/") {
			continue
		}
		prefix := strings.ToLower(strings.ReplaceAll(fields[0], "-", ":"))
		if len(prefix) != 8 {
			continue
		}
		name := fields[1]
		if len(fields) > 2 && fields[2] != "" {
			name = fields[2]
		}
		loaded[prefix] = name
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	ouiMu.Lock()
	for k, v := range loaded {
		ouiTable[k] = v
	}
	ouiMu.Unlock()
	return len(loaded), nil
}

// LookupVendor returns the manufacturer for a normalized MAC address.
func LookupVendor(mac string) string {
	if len(mac) < 8 {
		return ""
	}
	ouiMu.RLock()
	v, ok := ouiTable[mac[:8]]
	ouiMu.RUnlock()
	if ok {
		return v
	}
	// Locally administered bit: phones and laptops randomize their MAC.
	if first := mac[1]; strings.ContainsRune("26ae", rune(first)) {
		return "Private (randomized MAC)"
	}
	return ""
}
