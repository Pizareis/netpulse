// Package hub fans out live events to connected dashboard clients.
package hub

import (
	"sync"

	"github.com/Pizareis/netpulse/internal/model"
)

type Hub struct {
	mu   sync.Mutex
	subs map[chan model.Event]struct{}
}

func New() *Hub {
	return &Hub{subs: make(map[chan model.Event]struct{})}
}

// Subscribe returns a channel of events and a function to unsubscribe.
func (h *Hub) Subscribe() (<-chan model.Event, func()) {
	ch := make(chan model.Event, 64)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		delete(h.subs, ch)
		h.mu.Unlock()
	}
}

// Publish delivers e to every subscriber. Slow clients drop events rather
// than blocking the producers.
func (h *Hub) Publish(e model.Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- e:
		default:
		}
	}
}
