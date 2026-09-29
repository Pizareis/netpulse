// Package detect contains NetPulse's anomaly detectors.
package detect

import "github.com/Pizareis/netpulse/internal/model"

// Raiser is the subset of alert.Manager the detectors need. Keeping it an
// interface lets the tests capture alerts without a database.
type Raiser interface {
	Raise(kind string, sev model.Severity, key, title, detail, source string)
}
