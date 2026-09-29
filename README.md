# NetPulse

**Lightweight network monitor and anomaly detector, as a single Go binary.**

NetPulse discovers every device on your LAN, graphs throughput live in a web dashboard and alerts you
(in the browser, on Telegram or Discord) when something looks wrong: ARP spoofing, port scans,
unknown devices and sudden traffic spikes.

- **Zero dependencies at runtime.** Pure Go, `CGO_ENABLED=0`, no Npcap or libpcap, and no admin rights needed.
- **Single ~11 MB executable.** The dashboard is embedded with `go:embed`.
- **Cross-platform.** Windows, Linux and macOS.

## Features

| | How it works |
|---|---|
| **Device discovery** | Sends a tiny UDP/TCP probe to every host in the subnet so the OS ARP-resolves them, then reads the neighbour table (`arp -a`, `/proc/net/arp`). Vendor lookup comes from the MAC OUI, and randomized "private" MACs are detected. Reverse DNS supplies hostnames. |
| **ARP spoofing detection** | Tracks IP→MAC bindings. Two cases raise a critical alert: the gateway's MAC changes, or one MAC answers for both the gateway and another IP. |
| **Port scan detection** | Honeypot "tripwire" ports (default `21,23,1433,5900,8888`). Any connection is suspicious. A source touching ≥3 of them within a minute is flagged as a scan. |
| **Traffic spike detection** | Samples interface counters once a second and keeps an EWMA baseline plus variance. Throughput above `max(5× baseline, baseline + 4σ, 1 MB/s)` raises an alert. |
| **New device alerts** | The first scan becomes the known baseline. Any MAC seen after that raises an alert. |
| **Live dashboard** | Server-Sent Events stream traffic, device and alert updates. The chart is drawn on a plain canvas with no JS dependencies. |
| **Notifications** | Telegram bot and/or Discord webhook for warning and critical alerts, with per-alert cooldown to avoid spam. |
| **Persistence** | SQLite via the pure-Go `modernc.org/sqlite` driver. |

## Quick start

```bash
go install github.com/Pizareis/netpulse/cmd/netpulse@latest
netpulse
# open http://127.0.0.1:8080
```

Or build from source:

```bash
git clone https://github.com/Pizareis/netpulse && cd netpulse
go build -o netpulse ./cmd/netpulse
./netpulse
# open http://127.0.0.1:8080
```

On Windows run `netpulse.exe`. On first start, allow it through the firewall on **private networks**
so the honeypot ports can see LAN traffic.

### Try the detectors

```powershell
# Simulate a port scan against the honeypot ports (PowerShell)
foreach ($p in 21,23,5900) { $c = New-Object Net.Sockets.TcpClient; $c.Connect("127.0.0.1", $p); $c.Close() }
```

```bash
# ...or from another machine on the LAN
nmap -p 21,23,5900 <netpulse-host-ip>
```

## Configuration

| Flag | Env | Default | |
|---|---|---|---|
| `-addr` | `NETPULSE_ADDR` | `127.0.0.1:8080` | Dashboard address. Use `0.0.0.0:8080` to expose it on the LAN. |
| `-db` | `NETPULSE_DB` | `netpulse.db` | SQLite file |
| `-subnet` | `NETPULSE_SUBNET` | auto | CIDR to scan. Subnets larger than /22 are clamped to your /24. |
| `-scan-interval` | | `60s` | Discovery sweep interval |
| `-tripwire-ports` | | `21,23,1433,5900,8888` | Honeypot ports |
| `-scan-threshold` / `-scan-window` | | `3` / `1m` | Port scan rule |
| `-spike-factor` / `-spike-min-kbs` | | `5` / `1024` | Traffic spike rule |
| `-cooldown` | | `5m` | Duplicate alert suppression |
| `-oui` | `NETPULSE_OUI` | | Path to a Wireshark [`manuf`](https://www.wireshark.org/download/automated/data/manuf) file for full vendor names |
| `-telegram-token` / `-telegram-chat` | `NETPULSE_TELEGRAM_TOKEN` / `NETPULSE_TELEGRAM_CHAT` | | Telegram notifications |
| `-discord-webhook` | `NETPULSE_DISCORD_WEBHOOK` | | Discord notifications |

## Architecture

```
cmd/netpulse          wiring, graceful shutdown
internal/discovery    subnet sweep, ARP table parsing, gateway detection, OUI vendors
internal/detect       ARPWatch, Tripwire (port scans), TrafficMonitor + SpikeDetector
internal/alert        dedup/cooldown -> SQLite -> SSE hub -> notifiers
internal/notify       Telegram, Discord
internal/store        SQLite persistence
internal/web          JSON API, SSE stream, embedded dashboard
```

| Endpoint | |
|---|---|
| `GET /api/info` | Interface, subnet, gateway and alert counts |
| `GET /api/devices` | Device inventory |
| `GET /api/alerts` | Latest 100 alerts |
| `GET /api/traffic` | Last 5 minutes of throughput |
| `POST /api/scan` | Trigger a sweep now |
| `GET /api/events` | Server-Sent Events: `traffic`, `devices`, `alert`, `scan` |

## Tests

```bash
go test ./...
```

## Responsible use

Only run NetPulse on networks you own or are authorized to monitor. The discovery sweep is lightweight
(one packet per host per minute), but active probing may still be against the policy of shared
networks such as campus, office or public Wi-Fi.
