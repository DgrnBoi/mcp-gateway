package console

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// --- fixtures -----------------------------------------------------------------

func loadTestUsers(t *testing.T) (UsersFile, []byte) {
	t.Helper()
	const body = `users:
- username: "admin-user"
  password_hash_sha256: "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
  role: "admin"
- username: "analyst-user"
  password_hash_sha256: "e6f9134a09e0c1042c1128645a1e0f5e0e827e1b0773c4d6e8835c58056d87d8"
  role: "analyst"
- username: "auditor-user"
  password_hash_sha256: "d631111671053933767c3175970a5d951819c2b95467d2d33e7611534e37e689"
  role: "auditor"
`
	// NOTE: hashes above are placeholders recomputed below so the test never
	// relies on hand-edited digests; they are overwritten with real values.
	_ = body
	store := UsersFile{
		"admin-user":   userEntry{Username: "admin-user", PasswordHash: hashPassword("admin-pass"), Role: RoleAdmin},
		"analyst-user": userEntry{Username: "analyst-user", PasswordHash: hashPassword("analyst-pass"), Role: RoleAnalyst},
		"auditor-user": userEntry{Username: "auditor-user", PasswordHash: hashPassword("auditor-pass"), Role: RoleAuditor},
	}
	return store, []byte("console-secret-8192")
}

// --- login --------------------------------------------------------------------

func TestLogin_OKAndRole(t *testing.T) {
	store, secret := loadTestUsers(t)
	for _, u := range []struct{ user, pass, role string }{
		{"admin-user", "admin-pass", "admin"},
		{"analyst-user", "analyst-pass", "analyst"},
		{"auditor-user", "auditor-pass", "auditor"},
	} {
		token, err := Login(store, secret, u.user, u.pass)
		if err != nil {
			t.Fatalf("Login %s: %v", u.user, err)
		}
		claims, err := extractClaims(reqWithAuth(t, "Bearer "+token), secret)
		if err != nil {
			t.Fatalf("extractClaims %s: %v", u.user, err)
		}
		if claims.Username != u.user {
			t.Errorf("claims username %q want %q", claims.Username, u.user)
		}
		if claims.Role != u.role {
			t.Errorf("claims role %q want %q", claims.Role, u.role)
		}
		if claims.ExpiresAt <= time.Now().UTC().Unix() {
			t.Error("token already expired")
		}
	}
}

func TestLoginHandle_OK(t *testing.T) {
	store, secret := loadTestUsers(t)
	s := NewServerWithAuth(nil, store, secret)
	for _, u := range []struct{ user, pass, role string }{
		{"admin-user", "admin-pass", "admin"},
		{"analyst-user", "analyst-pass", "analyst"},
		{"auditor-user", "auditor-pass", "auditor"},
	} {
		req := httptest.NewRequest(http.MethodPost, "/_console/api/auth/login",
			jsonReader(t, map[string]string{"username": u.user, "password": u.pass}))
		rec := httptest.NewRecorder()
		s.handleLogin(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("login %s: status %d want 200, body %s", u.user, rec.Code, rec.Body.String())
			continue
		}
		var out struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode login response: %v", err)
		}
		// The response is token-only by design (defense in depth): the role
		// claim lives inside the signed JWT, not the plain-text body. Verify
		// the round-trip claims instead.
		if out.Token == "" {
			t.Errorf("login %s: empty token", u.user)
			continue
		}
		claims, err := extractClaims(reqWithAuth(t, "Bearer "+out.Token), secret)
		if err != nil {
			t.Fatalf("round-trip verify %s: %v", u.user, err)
		}
		if claims.Username != u.user {
			t.Errorf("claims username %q want %q", claims.Username, u.user)
		}
		if claims.Role != u.role {
			t.Errorf("login %s: claims role %q want %q", u.user, claims.Role, u.role)
		}
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	store, secret := loadTestUsers(t)
	_, err := Login(store, secret, "admin-user", "wrong")
	if err == nil {
		t.Fatal("wrong password accepted")
	}
}

func TestLogin_UnknownUser(t *testing.T) {
	store, secret := loadTestUsers(t)
	_, err := Login(store, secret, "ghost", "x")
	if err == nil {
		t.Fatal("unknown user accepted")
	}
}

func TestLoginHandle_GETNotAllowed(t *testing.T) {
	store, secret := loadTestUsers(t)
	s := NewServerWithAuth(nil, store, secret)
	req := httptest.NewRequest(http.MethodGet, "/_console/api/auth/login", nil)
	rec := httptest.NewRecorder()
	s.handleLogin(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET login: status %d want 405", rec.Code)
	}
}

// --- RequireRole ---------------------------------------------------------------

func TestRequireRole_Allowed(t *testing.T) {
	store, secret := loadTestUsers(t)
	token, err := Login(store, secret, "admin-user", "admin-pass")
	if err != nil {
		t.Fatal(err)
	}
	var got bool
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = true })
	RequireRole(store, secret, "admin")(inner).ServeHTTP(httptest.NewRecorder(),
		reqWithAuth(t, "Bearer "+token))
	if !got {
		t.Error("admin token denied by admin-only guard")
	}
}

func TestRequireRole_DeniedRole(t *testing.T) {
	store, secret := loadTestUsers(t)
	token, err := Login(store, secret, "analyst-user", "analyst-pass")
	if err != nil {
		t.Fatal(err)
	}
	var called bool
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	rec := httptest.NewRecorder()
	RequireRole(store, secret, "admin")(inner).ServeHTTP(rec, reqWithAuth(t, "Bearer "+token))
	if called {
		t.Error("analyst token reached admin-only handler")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("analyst access: status %d want 403", rec.Code)
	}
}

func TestRequireRole_AuditorBlockedFromViolations(t *testing.T) {
	store, secret := loadTestUsers(t)
	token, err := Login(store, secret, "auditor-user", "auditor-pass")
	if err != nil {
		t.Fatal(err)
	}
	var called bool
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	rec := httptest.NewRecorder()
	RequireRole(store, secret, "admin", "analyst")(inner).ServeHTTP(rec, reqWithAuth(t, "Bearer "+token))
	if called {
		t.Error("auditor reached violations handler (PII guard breached)")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("auditor access: status %d want 403", rec.Code)
	}
}

func TestRequireRole_NoToken(t *testing.T) {
	store, secret := loadTestUsers(t)
	var called bool
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	rec := httptest.NewRecorder()
	RequireRole(store, secret, "admin")(inner).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if called {
		t.Error("handler invoked without a token")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: status %d want 401", rec.Code)
	}
}

func TestRequireRole_BadSecret(t *testing.T) {
	store, secret := loadTestUsers(t)
	token, err := Login(store, []byte("wrong-secret"), "admin-user", "admin-pass")
	if err != nil {
		t.Fatal(err)
	}
	var called bool
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	rec := httptest.NewRecorder()
	RequireRole(store, secret, "admin")(inner).ServeHTTP(rec, reqWithAuth(t, "Bearer "+token))
	if called {
		t.Error("tampered token reached handler")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("bad-signature token: status %d want 401", rec.Code)
	}
}

func TestRequireRole_UnconfiguredConsole(t *testing.T) {
	var called bool
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	rec := httptest.NewRecorder()
	RequireRole(nil, nil, "admin")(inner).ServeHTTP(rec, reqWithAuth(t, "Bearer x"))
	if called {
		t.Error("handler invoked on unconfigured console")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("unconfigured console: status %d want 403", rec.Code)
	}
}

// --- LoadUsersFile -------------------------------------------------------------

func TestLoadUsersFile_KnownFieldsOnly(t *testing.T) {
	bad := `users:
- username: "a"
  password_hash_sha256: "b"
  role: "admin"
  unknown_field: true
`
	_, err := LoadUsersFile(strings.NewReader(bad))
	if err == nil {
		t.Error("unknown YAML field accepted; KnownFields enforcement broken")
	}
}

func TestLoadUsersFile_Empty(t *testing.T) {
	_, err := LoadUsersFile(strings.NewReader(`users: []
`))
	if err == nil {
		t.Error("empty users file accepted")
	}
}

func TestLoadUsersFile_BadRole(t *testing.T) {
	bad := `users:
- username: "a"
  password_hash_sha256: "b"
  role: "superadmin"
`
	_, err := LoadUsersFile(strings.NewReader(bad))
	if err == nil {
		t.Error("unknown role accepted")
	}
}

// --- helpers ------------------------------------------------------------------

func reqWithAuth(t *testing.T, authz string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", authz)
	return r
}

func jsonReader(t *testing.T, v any) *strings.Reader {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return strings.NewReader(string(b))
}
