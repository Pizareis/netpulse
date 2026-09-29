// Package store persists devices and alerts in SQLite (pure Go driver, no CGO).
package store

import (
	"database/sql"
	"time"

	_ "modernc.org/sqlite"

	"github.com/Pizareis/netpulse/internal/model"
)

const schema = `
CREATE TABLE IF NOT EXISTS devices (
	mac        TEXT PRIMARY KEY,
	ip         TEXT NOT NULL,
	vendor     TEXT NOT NULL DEFAULT '',
	hostname   TEXT NOT NULL DEFAULT '',
	first_seen INTEGER NOT NULL,
	last_seen  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts (
	id       INTEGER PRIMARY KEY AUTOINCREMENT,
	ts       INTEGER NOT NULL,
	kind     TEXT NOT NULL,
	severity TEXT NOT NULL,
	title    TEXT NOT NULL,
	detail   TEXT NOT NULL,
	source   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS alerts_ts ON alerts(ts);
`

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) UpsertDevice(d model.Device) error {
	_, err := s.db.Exec(`
		INSERT INTO devices (mac, ip, vendor, hostname, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(mac) DO UPDATE SET
			ip = excluded.ip, vendor = excluded.vendor,
			hostname = excluded.hostname, last_seen = excluded.last_seen`,
		d.MAC, d.IP, d.Vendor, d.Hostname, d.FirstSeen.UnixMilli(), d.LastSeen.UnixMilli())
	return err
}

func (s *Store) Devices() ([]model.Device, error) {
	rows, err := s.db.Query(`SELECT mac, ip, vendor, hostname, first_seen, last_seen FROM devices`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Device
	for rows.Next() {
		var d model.Device
		var first, last int64
		if err := rows.Scan(&d.MAC, &d.IP, &d.Vendor, &d.Hostname, &first, &last); err != nil {
			return nil, err
		}
		d.FirstSeen, d.LastSeen = time.UnixMilli(first), time.UnixMilli(last)
		out = append(out, d)
	}
	return out, rows.Err()
}

// InsertAlert stores a and fills in its ID.
func (s *Store) InsertAlert(a *model.Alert) error {
	res, err := s.db.Exec(`INSERT INTO alerts (ts, kind, severity, title, detail, source) VALUES (?, ?, ?, ?, ?, ?)`,
		a.Time.UnixMilli(), a.Kind, string(a.Severity), a.Title, a.Detail, a.Source)
	if err != nil {
		return err
	}
	a.ID, err = res.LastInsertId()
	return err
}

func (s *Store) RecentAlerts(limit int) ([]model.Alert, error) {
	rows, err := s.db.Query(`SELECT id, ts, kind, severity, title, detail, source FROM alerts ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Alert{}
	for rows.Next() {
		var a model.Alert
		var ts int64
		var sev string
		if err := rows.Scan(&a.ID, &ts, &a.Kind, &sev, &a.Title, &a.Detail, &a.Source); err != nil {
			return nil, err
		}
		a.Time, a.Severity = time.UnixMilli(ts), model.Severity(sev)
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) CountAlertsSince(t time.Time) (total, critical int, err error) {
	err = s.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(severity = 'critical'), 0) FROM alerts WHERE ts >= ?`,
		t.UnixMilli()).Scan(&total, &critical)
	return
}
