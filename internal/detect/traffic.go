package detect

import (
	"context"
	"fmt"
	"log"
	"math"
	"sync"
	"time"

	psnet "github.com/shirou/gopsutil/v4/net"

	"github.com/Pizareis/netpulse/internal/model"
)

// SpikeDetector flags values far above an exponentially weighted baseline.
type SpikeDetector struct {
	Alpha  float64 // EWMA smoothing factor
	Factor float64 // spike when value > baseline * Factor
	MinBps float64 // never flag below this absolute rate
	Warmup int     // samples to learn before alerting

	mean, variance float64
	n              int
}

// Check feeds v into the detector and reports whether it is a spike.
func (d *SpikeDetector) Check(v float64) (spike bool, baseline float64) {
	d.n++
	baseline = d.mean
	if d.n > d.Warmup {
		threshold := math.Max(d.MinBps, math.Max(d.mean*d.Factor, d.mean+4*math.Sqrt(d.variance)))
		spike = v > threshold
	}
	alpha := d.Alpha
	if d.n == 1 {
		alpha = 1
	} else if spike {
		alpha /= 5 // adapt slowly so a sustained burst keeps registering
	}
	diff := v - d.mean
	d.mean += alpha * diff
	d.variance = (1 - alpha) * (d.variance + alpha*diff*diff)
	return spike, baseline
}

// TrafficMonitor samples interface counters every second.
type TrafficMonitor struct {
	iface    string
	alerts   Raiser
	onSample func(model.TrafficSample)
	rx, tx   *SpikeDetector

	mu      sync.RWMutex
	history []model.TrafficSample
}

const historySize = 300 // five minutes at 1 Hz

func NewTrafficMonitor(iface string, factor, minBps float64, alerts Raiser, onSample func(model.TrafficSample)) *TrafficMonitor {
	newDet := func() *SpikeDetector {
		return &SpikeDetector{Alpha: 0.05, Factor: factor, MinBps: minBps, Warmup: 30}
	}
	return &TrafficMonitor{iface: iface, alerts: alerts, onSample: onSample, rx: newDet(), tx: newDet()}
}

func (m *TrafficMonitor) History() []model.TrafficSample {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]model.TrafficSample(nil), m.history...)
}

func (m *TrafficMonitor) counters() (rx, tx uint64, err error) {
	stats, err := psnet.IOCounters(true)
	if err != nil {
		return 0, 0, err
	}
	for _, s := range stats {
		if s.Name == m.iface {
			return s.BytesRecv, s.BytesSent, nil
		}
	}
	// Interface name not matched: fall back to all interfaces combined.
	for _, s := range stats {
		rx += s.BytesRecv
		tx += s.BytesSent
	}
	return rx, tx, nil
}

func (m *TrafficMonitor) Run(ctx context.Context) {
	prevRx, prevTx, err := m.counters()
	if err != nil {
		log.Printf("traffic: %v", err)
		return
	}
	prevT := time.Now()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			rx, tx, err := m.counters()
			if err != nil {
				continue
			}
			dt := now.Sub(prevT).Seconds()
			if rx >= prevRx && tx >= prevTx && dt > 0 {
				m.record(model.TrafficSample{
					Time:  now,
					RxBps: float64(rx-prevRx) / dt,
					TxBps: float64(tx-prevTx) / dt,
				})
			}
			prevRx, prevTx, prevT = rx, tx, now
		}
	}
}

func (m *TrafficMonitor) record(s model.TrafficSample) {
	m.mu.Lock()
	m.history = append(m.history, s)
	if len(m.history) > historySize {
		m.history = m.history[len(m.history)-historySize:]
	}
	m.mu.Unlock()
	m.onSample(s)

	if spike, base := m.rx.Check(s.RxBps); spike {
		m.raise("download", s.RxBps, base)
	}
	if spike, base := m.tx.Check(s.TxBps); spike {
		m.raise("upload", s.TxBps, base)
	}
}

func (m *TrafficMonitor) raise(dir string, rate, base float64) {
	ratio := "n/a"
	if base > 0 {
		ratio = fmt.Sprintf("%.0fx", rate/base)
	}
	m.alerts.Raise("traffic_spike", model.Warning, dir, "Traffic spike ("+dir+")",
		fmt.Sprintf("%s rate is %s, baseline ~%s (%s).", dir, HumanRate(rate), HumanRate(base), ratio), m.iface)
}

// HumanRate formats bytes per second.
func HumanRate(bps float64) string {
	units := []string{"B/s", "KB/s", "MB/s", "GB/s"}
	i := 0
	for bps >= 1024 && i < len(units)-1 {
		bps /= 1024
		i++
	}
	return fmt.Sprintf("%.1f %s", bps, units[i])
}
