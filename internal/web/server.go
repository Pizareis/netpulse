// Package web serves the dashboard, the JSON API and the live event stream.
package web

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"time"

	"github.com/Pizareis/netpulse/internal/detect"
	"github.com/Pizareis/netpulse/internal/discovery"
	"github.com/Pizareis/netpulse/internal/hub"
	"github.com/Pizareis/netpulse/internal/store"
)

//go:embed static
var staticFS embed.FS

type Server struct {
	Local         *discovery.LocalNet
	Scanner       *discovery.Scanner
	Traffic       *detect.TrafficMonitor
	Store         *store.Store
	Hub           *hub.Hub
	TripwirePorts []int
	Started       time.Time
}

func (s *Server) Handler() http.Handler {
	static, _ := fs.Sub(staticFS, "static")
	mux := http.NewServeMux()
	mux.Handle("GET /", http.FileServerFS(static))
	mux.HandleFunc("GET /api/info", s.info)
	mux.HandleFunc("GET /api/devices", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, s.Scanner.Devices())
	})
	mux.HandleFunc("GET /api/traffic", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, s.Traffic.History())
	})
	mux.HandleFunc("GET /api/alerts", func(w http.ResponseWriter, r *http.Request) {
		alerts, err := s.Store.RecentAlerts(100)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, alerts)
	})
	mux.HandleFunc("POST /api/scan", func(w http.ResponseWriter, r *http.Request) {
		s.Scanner.Trigger()
		w.WriteHeader(http.StatusAccepted)
	})
	mux.HandleFunc("GET /api/events", s.events)
	return mux
}

func (s *Server) info(w http.ResponseWriter, r *http.Request) {
	total, critical, _ := s.Store.CountAlertsSince(time.Now().Add(-24 * time.Hour))
	ones, _ := s.Local.Net.Mask.Size()
	writeJSON(w, map[string]any{
		"iface":          s.Local.Iface,
		"ip":             s.Local.IP.String(),
		"subnet":         fmt.Sprintf("%s/%d", s.Local.Net.IP, ones),
		"gateway":        s.Local.Gateway,
		"tripwire_ports": s.TripwirePorts,
		"started":        s.Started,
		"last_scan":      s.Scanner.LastScan(),
		"scanning":       s.Scanner.Scanning(),
		"alerts_24h":     total,
		"critical_24h":   critical,
	})
}

// events streams hub events to the browser as Server-Sent Events.
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch, unsubscribe := s.Hub.Subscribe()
	defer unsubscribe()
	fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case e := <-ch:
			data, err := json.Marshal(e.Data)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", e.Type, data)
			flusher.Flush()
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
