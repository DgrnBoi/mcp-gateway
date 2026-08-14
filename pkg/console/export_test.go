package console

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/antigravity/mcp-gateway/pkg/audit"
	"github.com/antigravity/mcp-gateway/pkg/core"
	"github.com/antigravity/mcp-gateway/pkg/server"
)

// --- fixture: a small violations.log with mixed timestamps and identities ------
// violations.log stores timestamps in the RFC3339Milli form used across the
// audit surface, so fixtures must match that shape exactly.

func writeFixtureViolations(t *testing.T, lines []string) string {
	t.Helper()
	path := t.TempDir() + "/violations.log"
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// auditLine builds a violations.log JSON line. Only the fields the exporter
// filters on are populated; raw keeps the quarantine contents intact.
func auditLine(ts, qid, rule, clientID, tool, raw string) string {
	return `{"quarantine_id":"` + qid + `","timestamp":"` + ts +
		`","rule_id":"` + rule +
		`","client_id":"` + clientID +
		`","tool":"` + tool + `","original_raw_params":` + raw + "}"
}

// --- endpoint plumbing ---------------------------------------------------------

func rbacServer(t *testing.T, violationsPath string, obs ...audit.AuditEntry) (*Server, []byte, *Ingester) {
	t.Helper()
	ing := NewIngester(100, 0)
	for _, e := range obs {
		ing.Observe(e)
	}
	secret := []byte("export-secret")
	users := UsersFile{
		"admin-e": userEntry{Username: "admin-e", PasswordHash: hashPassword("p"), Role: RoleAdmin},
	}
	srv := NewServerWithAuth(ing, users, secret)
	srv.Exporter = NewExporter(ing, violationsPath)
	return srv, secret, ing
}

func getExport(t *testing.T, srv *Server, secret []byte, user, query string) *httptest.ResponseRecorder {
	t.Helper()
	req := withAuth(httptest.NewRequest(http.MethodGet, "/_console/api/export?"+query, nil),
		tokenFor(t, srv, secret, user))
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)
	return rec
}

// --- tests ----------------------------------------------------------------------

func TestExport_TimeBoundsRequired(t *testing.T) {
	srv, secret, _ := rbacServer(t, writeFixtureViolations(t, nil))

	cases := []struct {
		name  string
		query string
	}{
		{"no params", ""},
		{"only start", "start_time=2025-01-01T00:00:00Z"},
		{"only end", "end_time=2025-12-31T00:00:00Z"},
		{"bad format", "start_time=01-01-2025&end_time=12-31-2025"},
	}
	for _, c := range cases {
		rec := getExport(t, srv, secret, "admin-e", c.query)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d want 400", c.name, rec.Code)
		}
	}
}

func TestExport_WindowTooWide(t *testing.T) {
	srv, secret, _ := rbacServer(t, writeFixtureViolations(t, nil))
	rec := getExport(t, srv, secret, "admin-e",
		"start_time=2024-01-01T00:00:00Z&end_time=2026-01-01T00:00:00Z")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("oversized window: status %d want 400", rec.Code)
	}
}

func TestExport_EndBeforeStart(t *testing.T) {
	srv, secret, _ := rbacServer(t, writeFixtureViolations(t, nil))
	rec := getExport(t, srv, secret, "admin-e",
		"start_time=2025-07-01T00:00:00Z&end_time=2025-06-01T00:00:00Z")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("reversed bounds: status %d want 400", rec.Code)
	}
}

func TestExport_GzipStreamContents(t *testing.T) {
	lines := []string{
		auditLine("2025-06-01T10:00:00.000Z", "Q-000001", "R-001", "agent-a", "db.exec", `{"sql":"DROP"}`),
		auditLine("2025-06-01T11:00:00.000Z", "Q-000002", "R-002", "agent-b", "mail.send", `{"to":"x"}`),
		auditLine("2025-06-02T10:00:00.000Z", "Q-000003", "R-001", "agent-a", "db.exec", `{"sql":"SELECT"}`),
	}
	srv, secret, _ := rbacServer(t, writeFixtureViolations(t, lines))

	rec := getExport(t, srv, secret, "admin-e",
		"start_time=2025-06-01T00:00:00Z&end_time=2025-06-01T23:59:59Z")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/gzip" {
		t.Errorf("content-type %q want application/gzip", ct)
	}
	if !strings.Contains(rec.Header().Get("Content-Disposition"), "violations-export.jsonl.gz") {
		t.Error("missing Content-Disposition attachment")
	}

	gz, err := gzip.NewReader(bytes.NewReader(rec.Body.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(gz)
	if err != nil {
		t.Fatal(err)
	}
	body := string(data)
	if !strings.Contains(body, "Q-000001") || !strings.Contains(body, "Q-000002") {
		t.Errorf("windowed lines missing: %s", body)
	}
	if strings.Contains(body, "Q-000003") {
		t.Errorf("out-of-window line leaked into export: %s", body)
	}
}

func TestExport_IdentityFilter(t *testing.T) {
	// The exporter resolves an identity filter via the quarantine-id -> audit
	// entry map on the Ingester, so observers must carry the caller identity.
	obs := []audit.AuditEntry{
		{QuarantineID: "Q-000001", Identity: core.CallerIdentity{ClientID: "agent-a"}},
		{QuarantineID: "Q-000002", Identity: core.CallerIdentity{ClientID: "agent-b"}},
	}
	lines := []string{
		auditLine("2025-06-01T10:00:00.000Z", "Q-000001", "R-001", "agent-a", "db.exec", `{"sql":"DROP"}`),
		auditLine("2025-06-01T10:00:00.000Z", "Q-000002", "R-002", "agent-b", "mail.send", `{"to":"x"}`),
	}
	srv, secret, ing := rbacServer(t, writeFixtureViolations(t, lines), obs...)

	rec := getExport(t, srv, secret, "admin-e",
		"start_time=2025-06-01T00:00:00Z&end_time=2025-06-01T23:59:59Z&identity="+fingerprintOf(ing))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	gz, err := gzip.NewReader(bytes.NewReader(rec.Body.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(gz)
	body := string(data)
	if !strings.Contains(body, "Q-000001") {
		t.Errorf("filtered identity line missing: %s", body)
	}
	if strings.Contains(body, "Q-000002") {
		t.Errorf("non-matching identity leaked: %s", body)
	}
}

func TestExport_EmptyWindowStreamStillValid(t *testing.T) {
	srv, secret, _ := rbacServer(t, writeFixtureViolations(t, nil))
	rec := getExport(t, srv, secret, "admin-e",
		"start_time=2020-01-01T00:00:00Z&end_time=2020-01-01T23:59:59Z")
	if rec.Code != http.StatusOK {
		t.Fatalf("empty match: status %d", rec.Code)
	}
	// An empty but well-formed gzip stream.
	gz, err := gzip.NewReader(bytes.NewReader(rec.Body.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(gz)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 0 {
		t.Errorf("empty window must yield 0 bytes, got %d", len(data))
	}
}

func TestExport_MissingLogEmitsEmptyArchive(t *testing.T) {
	srv, secret, _ := rbacServer(t, "/nonexistent/violations.log")
	rec := getExport(t, srv, secret, "admin-e",
		"start_time=2025-06-01T00:00:00Z&end_time=2025-06-01T23:59:59Z")
	if rec.Code != http.StatusOK {
		t.Fatalf("no log yet must yield empty archive: status %d", rec.Code)
	}
	gz, err := gzip.NewReader(bytes.NewReader(rec.Body.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(gz)
	if err != nil || len(data) != 0 {
		t.Error("expected well-formed empty gzip stream")
	}
}

func TestExport_UnconfiguredRefused(t *testing.T) {
	srv, secret, _ := rbacServer(t, writeFixtureViolations(t, nil))
	srv.Exporter = nil // simulate gateway started without --violations
	rec := getExport(t, srv, secret, "admin-e",
		"start_time=2025-06-01T00:00:00Z&end_time=2025-06-01T23:59:59Z")
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("no exporter: status %d want 503", rec.Code)
	}
}

func TestExport_AuditorDenied(t *testing.T) {
	ing := NewIngester(100, 0)
	secret := []byte("export-secret-2")
	users := UsersFile{
		"auditor-e": userEntry{Username: "auditor-e", PasswordHash: hashPassword("p"), Role: RoleAuditor},
	}
	srv := NewServerWithAuth(ing, users, secret)
	srv.Exporter = NewExporter(ing, t.TempDir()+"/violations.log")
	req := httptest.NewRequest(http.MethodGet, "/_console/api/export?start_time=2025-06-01T00:00:00Z&end_time=2025-06-01T23:59:59Z", nil)
	tok, err := Login(users, secret, "auditor-e", "p")
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("auditor must be 403 on export: status %d", rec.Code)
	}
}

// fingerprintOf returns the SHA-256 fingerprint the exporter filters on for
// the fixed test identity (agent-a).
func fingerprintOf(ing *Ingester) string {
	entry, ok := ing.LookupEntryByQuarantineID("Q-000001")
	if !ok {
		panic("test fixture observer missing for Q-000001")
	}
	return server.Fingerprint(entry.Identity)
}
