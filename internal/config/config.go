// Package config parses command-line flags and environment variables.
package config

import (
	"flag"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Addr              string
	DBPath            string
	Subnet            string
	OUIFile           string
	ScanInterval      time.Duration
	TripwirePorts     []int
	PortScanThreshold int
	PortScanWindow    time.Duration
	SpikeFactor       float64
	SpikeMinBps       float64
	AlertCooldown     time.Duration
	TelegramToken     string
	TelegramChatID    string
	DiscordWebhook    string
}

func Load() Config {
	var c Config
	var ports string
	var spikeMinKB float64

	flag.StringVar(&c.Addr, "addr", env("NETPULSE_ADDR", "127.0.0.1:8080"), "dashboard listen address")
	flag.StringVar(&c.DBPath, "db", env("NETPULSE_DB", "netpulse.db"), "SQLite database path")
	flag.StringVar(&c.Subnet, "subnet", env("NETPULSE_SUBNET", ""), "subnet to scan in CIDR form (auto-detected when empty)")
	flag.StringVar(&c.OUIFile, "oui", env("NETPULSE_OUI", ""), "optional Wireshark 'manuf' file for full vendor lookup")
	flag.DurationVar(&c.ScanInterval, "scan-interval", 60*time.Second, "time between network discovery sweeps")
	flag.StringVar(&ports, "tripwire-ports", "21,23,1433,5900,8888", "comma-separated honeypot ports used to detect port scans")
	flag.IntVar(&c.PortScanThreshold, "scan-threshold", 3, "distinct tripwire ports hit by one source to call it a port scan")
	flag.DurationVar(&c.PortScanWindow, "scan-window", time.Minute, "window for counting tripwire hits")
	flag.Float64Var(&c.SpikeFactor, "spike-factor", 5, "traffic spike threshold as a multiple of the baseline")
	flag.Float64Var(&spikeMinKB, "spike-min-kbs", 1024, "ignore spikes below this rate (KB/s)")
	flag.DurationVar(&c.AlertCooldown, "cooldown", 5*time.Minute, "suppress duplicate alerts for this long")
	flag.StringVar(&c.TelegramToken, "telegram-token", env("NETPULSE_TELEGRAM_TOKEN", ""), "Telegram bot token")
	flag.StringVar(&c.TelegramChatID, "telegram-chat", env("NETPULSE_TELEGRAM_CHAT", ""), "Telegram chat ID")
	flag.StringVar(&c.DiscordWebhook, "discord-webhook", env("NETPULSE_DISCORD_WEBHOOK", ""), "Discord webhook URL")
	flag.Parse()

	c.TripwirePorts = parsePorts(ports)
	c.SpikeMinBps = spikeMinKB * 1024
	return c
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func parsePorts(s string) []int {
	var out []int
	for _, p := range strings.Split(s, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err == nil && n > 0 && n < 65536 {
			out = append(out, n)
		}
	}
	return out
}
