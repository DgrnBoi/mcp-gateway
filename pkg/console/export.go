package console

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/antigravity/mcp-gateway/pkg/audit"
	"github.com/antigravity/mcp-gateway/pkg/server"
)

// Exporter streams forensic quarantine exports directly from
// violations.log as gzip to the client, so exporting millions of events
// never materializes more than one scan buffer in memory (Stage 5,
// Ticket 21). The Ingester is consulted only when an identity filter is
// requested: the violations.log line format carries no identity, so the
// matching audit entry is looked up by quarantine_id.
type Exporter struct {
	ing      *Ingester
	violPath string
}

// NewExporter constructs an Exporter bound to the violations log. An
// empty path refuses every export request — the gateway never guesses.
func NewExporter(ing *Ingester, violationsPath string) *Exporter {
	return &Exporter{ing: ing, violPath: violationsPath}
}

const (
	exportMaxLines   = 1 << 22 // 4M entries per export cap — SOC teams page instead
	exportBufLines   = 512
)

// HandleExport serves GET /api/export. Query params: start_time and
// end_time are mandatory RFC3339; identity is an optional caller
// fingerprint filter. Unbounded exports are refused.
func (e *Exporter) HandleExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	startStr, endStr := q.Get("start_time"), q.Get("end_time")
	if startStr == "" || endStr == "" {
		http.Error(w, "start_time and end_time are mandatory (RFC3339)", http.StatusBadRequest)
		return
	}
	start, err := time.Parse(time.RFC3339, startStr)
	if err != nil {
		http.Error(w, "start_time is not valid RFC3339", http.StatusBadRequest)
		return
	}
	end, err := time.Parse(time.RFC3339, endStr)
	if err != nil {
		http.Error(w, "end_time is not valid RFC3339", http.StatusBadRequest)
		return
	}
	if end.Before(start) {
		http.Error(w, "end_time is before start_time", http.StatusBadRequest)
		return
	}
	if end.Sub(start) > 180*24*time.Hour {
		http.Error(w, "export window exceeds 180 days", http.StatusBadRequest)
		return
	}
	identity := q.Get("identity")

	f, err := os.Open(e.violPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// No violations yet — an empty export is a valid answer, never an error.
			w.Header().Set("Content-Type", "application/gzip")
			w.Header().Set("Content-Disposition", `attachment; filename="violations-export.jsonl.gz"`)
			gzw := gzip.NewWriter(w)
			_ = gzw.Close()
			return
		}
		http.Error(w, "violations log unavailable", http.StatusServiceUnavailable)
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", `attachment; filename="violations-export.jsonl.gz"`)
	w.Header().Set("Transfer-Encoding", "chunked")

	gzw := gzip.NewWriter(w)
	lineBuf := make([]byte, 0, 8192)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(lineBuf, 1<<20)
	wrote := 0
	for scanner.Scan() {
		if wrote >= exportMaxLines {
			break
		}
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var v audit.ViolationEntry
		if json.Unmarshal(line, &v) != nil {
			continue // skip unparseable lines rather than aborting the export
		}
		ts, err := time.Parse(audit.RFC3339Milli, v.Timestamp)
		if err != nil {
			continue
		}
		if ts.Before(start) || ts.After(end) {
			continue
		}
		if identity != "" {
			entry, ok := e.ing.LookupEntryByQuarantineID(v.QuarantineID)
			if !ok || server.Fingerprint(entry.Identity) != identity {
				continue
			}
		}
		if _, err := gzw.Write(append(line, '\n')); err != nil {
			return // client disconnected mid-stream; abort cleanly
		}
		wrote++
	}
	if err := gzw.Close(); err != nil {
		return
	}
}
