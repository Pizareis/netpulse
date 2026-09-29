//go:build !windows

package discovery

import (
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func readARPTable(string) ([]ARPEntry, error) {
	if data, err := os.ReadFile("/proc/net/arp"); err == nil {
		return parseProcARP(string(data)), nil
	}
	out, err := exec.Command("arp", "-an").Output()
	if err != nil {
		return nil, err
	}
	return parseARP(string(out)), nil
}

func defaultGateway(string) string {
	if data, err := os.ReadFile("/proc/net/route"); err == nil {
		for _, line := range strings.Split(string(data), "\n")[1:] {
			f := strings.Fields(line)
			if len(f) < 3 || f[1] != "00000000" {
				continue
			}
			v, err := strconv.ParseUint(f[2], 16, 32)
			if err != nil {
				continue
			}
			return net.IPv4(byte(v), byte(v>>8), byte(v>>16), byte(v>>24)).String()
		}
	}
	out, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if gw, ok := strings.CutPrefix(line, "gateway:"); ok {
			return strings.TrimSpace(gw)
		}
	}
	return ""
}
