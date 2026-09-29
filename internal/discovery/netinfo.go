package discovery

import (
	"encoding/binary"
	"errors"
	"net"
)

// LocalNet describes the interface NetPulse monitors.
type LocalNet struct {
	Iface   string
	IP      net.IP
	MAC     string
	Net     *net.IPNet
	Gateway string
}

// DetectLocal finds the interface used for outbound traffic. If cidr is set it
// overrides the subnet that gets scanned.
func DetectLocal(cidr string) (*LocalNet, error) {
	ip := outboundIP()
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var ln *LocalNet
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok || ipnet.IP.To4() == nil {
				continue
			}
			match := ip != nil && ipnet.IP.Equal(ip)
			fallback := ip == nil && ln == nil && ipnet.IP.IsPrivate()
			if match || fallback {
				ln = &LocalNet{
					Iface: iface.Name,
					IP:    ipnet.IP.To4(),
					MAC:   normalizeMAC(iface.HardwareAddr.String()),
					Net:   &net.IPNet{IP: ipnet.IP.Mask(ipnet.Mask).To4(), Mask: ipnet.Mask},
				}
			}
		}
	}
	if ln == nil {
		return nil, errors.New("no active IPv4 interface found")
	}
	if cidr != "" {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}
		ln.Net = n
	}
	ln.Gateway = defaultGateway(ln.IP.String())
	return ln, nil
}

// outboundIP asks the OS which local address would route to the internet.
// Dialing UDP sends no packets.
func outboundIP() net.IP {
	conn, err := net.Dial("udp4", "1.1.1.1:80")
	if err != nil {
		return nil
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.To4()
}

// Hosts lists every usable host address in n. Subnets larger than /22 are
// clamped to the /24 around self so a sweep stays fast and polite.
func Hosts(n *net.IPNet, self net.IP) []string {
	ones, bits := n.Mask.Size()
	if bits != 32 {
		return nil
	}
	base := n.IP.Mask(n.Mask).To4()
	if ones < 22 {
		ones = 24
		base = self.Mask(net.CIDRMask(24, 32)).To4()
	}
	size := uint32(1) << (32 - ones)
	if size <= 2 {
		return nil
	}
	start := binary.BigEndian.Uint32(base)
	out := make([]string, 0, size-2)
	for i := uint32(1); i < size-1; i++ {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, start+i)
		out = append(out, ip.String())
	}
	return out
}

// isHostAddr reports whether ip is inside n and is not its network or
// broadcast address.
func isHostAddr(n *net.IPNet, ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil || !n.Contains(ip4) {
		return false
	}
	network := n.IP.Mask(n.Mask).To4()
	broadcast := make(net.IP, 4)
	for i := range broadcast {
		broadcast[i] = network[i] | ^n.Mask[len(n.Mask)-4+i]
	}
	return !ip4.Equal(network) && !ip4.Equal(broadcast)
}
