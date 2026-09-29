// Package model holds the data types shared across NetPulse.
package model

import "time"

// Device is a host discovered on the local network, identified by MAC.
type Device struct {
	MAC       string    `json:"mac"`
	IP        string    `json:"ip"`
	Vendor    string    `json:"vendor"`
	Hostname  string    `json:"hostname"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Online    bool      `json:"online"`
	Gateway   bool      `json:"gateway"`
	Self      bool      `json:"self"`
}

type Severity string

const (
	Info     Severity = "info"
	Warning  Severity = "warning"
	Critical Severity = "critical"
)

// Rank orders severities so they can be compared.
func (s Severity) Rank() int {
	switch s {
	case Critical:
		return 2
	case Warning:
		return 1
	default:
		return 0
	}
}

type Alert struct {
	ID       int64     `json:"id"`
	Time     time.Time `json:"time"`
	Kind     string    `json:"kind"`
	Severity Severity  `json:"severity"`
	Title    string    `json:"title"`
	Detail   string    `json:"detail"`
	Source   string    `json:"source"`
}

// TrafficSample is the throughput of the monitored interface over one tick.
type TrafficSample struct {
	Time  time.Time `json:"t"`
	RxBps float64   `json:"rx"`
	TxBps float64   `json:"tx"`
}

// Event is pushed to dashboard clients over Server-Sent Events.
type Event struct {
	Type string `json:"type"`
	Data any    `json:"data"`
}
