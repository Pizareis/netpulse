// Package alert deduplicates, stores, broadcasts and forwards alerts.
package alert

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/Pizareis/netpulse/internal/hub"
	"github.com/Pizareis/netpulse/internal/model"
	"github.com/Pizareis/netpulse/internal/store"
)

// Notifier forwards an alert to an external channel (Telegram, Discord...).
type Notifier interface {
	Name() string
	Notify(ctx context.Context, a model.Alert) error
}

type Manager struct {
	store     *store.Store
	hub       *hub.Hub
	notifiers []Notifier
	cooldown  time.Duration
	minNotify model.Severity

	mu   sync.Mutex
	last map[string]time.Time
}

func NewManager(st *store.Store, h *hub.Hub, notifiers []Notifier, cooldown time.Duration) *Manager {
	return &Manager{
		store:     st,
		hub:       h,
		notifiers: notifiers,
		cooldown:  cooldown,
		minNotify: model.Warning,
		last:      make(map[string]time.Time),
	}
}

// Raise records an alert unless one with the same kind and key fired within
// the cooldown window.
func (m *Manager) Raise(kind string, sev model.Severity, key, title, detail, source string) {
	now := time.Now()
	dedup := kind + "|" + key
	m.mu.Lock()
	if t, ok := m.last[dedup]; ok && now.Sub(t) < m.cooldown {
		m.mu.Unlock()
		return
	}
	m.last[dedup] = now
	m.mu.Unlock()

	a := model.Alert{Time: now, Kind: kind, Severity: sev, Title: title, Detail: detail, Source: source}
	if err := m.store.InsertAlert(&a); err != nil {
		log.Printf("alert: store: %v", err)
	}
	log.Printf("[ALERT][%s] %s - %s", sev, title, detail)
	m.hub.Publish(model.Event{Type: "alert", Data: a})

	if sev.Rank() < m.minNotify.Rank() {
		return
	}
	for _, n := range m.notifiers {
		go func(n Notifier) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := n.Notify(ctx, a); err != nil {
				log.Printf("alert: %s: %v", n.Name(), err)
			}
		}(n)
	}
}
