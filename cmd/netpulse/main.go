// NetPulse is a lightweight network monitor: it discovers devices on the LAN,
// graphs throughput live and alerts on ARP spoofing, port scans and traffic
// spikes.
package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Pizareis/netpulse/internal/alert"
	"github.com/Pizareis/netpulse/internal/config"
	"github.com/Pizareis/netpulse/internal/detect"
	"github.com/Pizareis/netpulse/internal/discovery"
	"github.com/Pizareis/netpulse/internal/hub"
	"github.com/Pizareis/netpulse/internal/model"
	"github.com/Pizareis/netpulse/internal/notify"
	"github.com/Pizareis/netpulse/internal/store"
	"github.com/Pizareis/netpulse/internal/web"
)

func main() {
	cfg := config.Load()
	log.SetFlags(log.Ltime)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer st.Close()

	if cfg.OUIFile != "" {
		if n, err := discovery.LoadOUIFile(cfg.OUIFile); err != nil {
			log.Printf("oui: %v", err)
		} else {
			log.Printf("oui: loaded %d vendors", n)
		}
	}

	var notifiers []alert.Notifier
	if cfg.TelegramToken != "" && cfg.TelegramChatID != "" {
		notifiers = append(notifiers, notify.Telegram{Token: cfg.TelegramToken, ChatID: cfg.TelegramChatID})
	}
	if cfg.DiscordWebhook != "" {
		notifiers = append(notifiers, notify.Discord{Webhook: cfg.DiscordWebhook})
	}

	h := hub.New()
	alerts := alert.NewManager(st, h, notifiers, cfg.AlertCooldown)

	local, err := discovery.DetectLocal(cfg.Subnet)
	if err != nil {
		log.Fatalf("detect network: %v", err)
	}
	log.Printf("interface %q  ip %s  subnet %s  gateway %s", local.Iface, local.IP, local.Net, local.Gateway)

	scanner := discovery.NewScanner(local, st, h, alerts, cfg.ScanInterval)
	scanner.AddObserver(detect.NewARPWatch(local.Gateway, alerts).Observe)

	tripwire := detect.NewTripwire(cfg.TripwirePorts, cfg.PortScanThreshold, cfg.PortScanWindow, alerts)
	activePorts := tripwire.Start(ctx)
	log.Printf("tripwire ports: %v", activePorts)

	traffic := detect.NewTrafficMonitor(local.Iface, cfg.SpikeFactor, cfg.SpikeMinBps, alerts, func(s model.TrafficSample) {
		h.Publish(model.Event{Type: "traffic", Data: s})
	})

	go scanner.Run(ctx)
	go traffic.Run(ctx)

	srv := &web.Server{
		Local: local, Scanner: scanner, Traffic: traffic, Store: st, Hub: h,
		TripwirePorts: activePorts, Started: time.Now(),
	}
	httpSrv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx }, // ends SSE streams on shutdown
	}
	go func() {
		log.Printf("dashboard: http://%s", cfg.Addr)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("http: %v", err)
		}
	}()

	<-ctx.Done()
	log.Print("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	httpSrv.Shutdown(shutdownCtx)
}
