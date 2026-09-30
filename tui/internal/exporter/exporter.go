// Package exporter writes cached activity rows to NDJSON or CSV (PRD FR-10,
// arch §6 export formats). CSV goes through encoding/csv so the free-text
// `data` field is properly quoted/escaped.
package exporter

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/0xnhsec/vlh-ctf/tui/internal/collector"
)

// ExportNDJSON writes rows as newline-delimited JSON (one object per line,
// field order: ts, identifier, is_authenticated, data, latency, unit).
func ExportNDJSON(rows []collector.ActivityRow, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create export dir: %w", err)
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	enc := json.NewEncoder(f)
	for i := range rows {
		if err := enc.Encode(rows[i]); err != nil {
			f.Close() //nolint:errcheck // already failing
			return fmt.Errorf("ndjson encode: %w", err)
		}
	}
	return f.Close()
}

// ExportCSV writes rows as CSV with the arch §6 field set:
// timestamp,identifier,is_authenticated,data,latency,unit.
func ExportCSV(rows []collector.ActivityRow, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create export dir: %w", err)
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	w := csv.NewWriter(f)
	if err := w.Write([]string{"timestamp", "identifier", "is_authenticated", "data", "latency", "unit"}); err != nil {
		f.Close() //nolint:errcheck // already failing
		return fmt.Errorf("csv write header: %w", err)
	}
	for i := range rows {
		rec := []string{
			rows[i].TS,
			rows[i].Identifier,
			strconv.FormatBool(rows[i].IsAuthenticated),
			rows[i].Data,
			strconv.FormatFloat(rows[i].Latency, 'f', -1, 64),
			rows[i].Unit,
		}
		if err := w.Write(rec); err != nil {
			f.Close() //nolint:errcheck // already failing
			return fmt.Errorf("csv write row: %w", err)
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		f.Close() //nolint:errcheck // already failing
		return fmt.Errorf("csv flush: %w", err)
	}
	return f.Close()
}
