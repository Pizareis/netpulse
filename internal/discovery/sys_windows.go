//go:build windows

package discovery

import (
	"os/exec"
	"regexp"
	"strings"
	"syscall"
)

// hiddenCmd runs a console tool without flashing a window.
func hiddenCmd(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd
}

func readARPTable(localIP string) ([]ARPEntry, error) {
	out, err := hiddenCmd("arp", "-a", "-N", localIP).Output()
	if err != nil && len(out) == 0 {
		return nil, err
	}
	return parseARP(string(out)), nil
}

// Active route line: "0.0.0.0   0.0.0.0   192.168.1.1   192.168.1.34   35".
var defaultRouteRe = regexp.MustCompile(`^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)`)

func defaultGateway(localIP string) string {
	out, err := hiddenCmd("route", "print", "-4", "0.0.0.0").Output()
	if err != nil {
		return ""
	}
	first := ""
	for _, line := range strings.Split(string(out), "\n") {
		m := defaultRouteRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		if m[2] == localIP {
			return m[1]
		}
		if first == "" {
			first = m[1]
		}
	}
	return first
}
