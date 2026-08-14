package console

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Role constants for the console JWT claims. The role matrix (Stage 5,
// Ticket 20) is enforced per route, not per session:
//
//	admin   — dashboard, quarantine payloads, GitOps rule generation
//	analyst — dashboard and quarantine payloads only
//	auditor — dashboard metadata only; quarantine payloads return 403 so
//	          auditors never see raw quarantined content (PII/secret guard)
const (
	RoleAdmin   = "admin"
	RoleAnalyst = "analyst"
	RoleAuditor = "auditor"
)

// userEntry is one line of users.yaml — the static credential store.
type userEntry struct {
	Username     string `yaml:"username"`
	PasswordHash string `yaml:"password_hash_sha256"`
	Role         string `yaml:"role"`
}

// UsersFile is the decoded users.yaml credential store (username -> entry).
type UsersFile map[string]userEntry

// consoleTokenClaims are the claims minted on login.
type consoleTokenClaims struct {
	Username  string `json:"sub"`
	Role      string `json:"role"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

// LoadUsersFile decodes a YAML users.yaml into the credential store. The
// file must declare at least one user with a permitted role; an empty or
// malformed store is a load-time failure so the console never starts with
// silent open access.
func LoadUsersFile(r io.Reader) (UsersFile, error) {
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)

	var entries []userEntry
	for {
		var e userEntry
		err := dec.Decode(&e)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parsing users file: %w", err)
		}
		entries = append(entries, e)
	}
	if len(entries) == 0 {
		return nil, errors.New("users file contains no users")
	}
	store := make(UsersFile, len(entries))
	for _, e := range entries {
		if strings.TrimSpace(e.Username) == "" {
			return nil, errors.New("users file entry with empty username")
		}
		if _, exists := store[e.Username]; exists {
			return nil, fmt.Errorf("duplicate username: %s", e.Username)
		}
		switch e.Role {
		case RoleAdmin, RoleAnalyst, RoleAuditor:
		default:
			return nil, fmt.Errorf("user %q has unknown role %q (admin/analyst/auditor)", e.Username, e.Role)
		}
		store[e.Username] = e
	}
	return store, nil
}

// Login authenticates against the static store and mints a console JWT.
// Tokens are HS256, bound to the secret via HMAC, and expire after 8h —
// long enough for a triage session, short enough to limit console
// exposure from a leaked token.
func Login(store UsersFile, secret []byte, username, password string) (string, error) {
	e, ok := store[username]
	if !ok {
		return "", errors.New("invalid credentials")
	}
	if hashPassword(password) != e.PasswordHash {
		return "", errors.New("invalid credentials")
	}
	now := time.Now().UTC()
	claims := consoleTokenClaims{
		Username:  username,
		Role:      e.Role,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(8 * time.Hour).Unix(),
	}
	return mintJWT(secret, claims)
}

// RequireRole is an HTTP middleware that validates the Authorization
// bearer JWT and enforces the per-route role matrix. If the user's role
// is not in allowed, the request fails with 403 (not 401 — the token
// itself was valid, the role simply does not hold this capability).
// Without a UsersFile (console started with no --console-users) every
// API request is refused with 403: the dashboard shell still renders,
// but no data ever leaves the gateway.
func RequireRole(store UsersFile, secret []byte, allowed ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if store == nil || len(secret) == 0 {
				http.Error(w, "console RBAC not configured: gateway started without --console-users", http.StatusForbidden)
				return
			}
			claims, err := extractClaims(r, secret)
			if err != nil {
				http.Error(w, "authentication required", http.StatusUnauthorized)
				return
			}
			if _, ok := store[claims.Username]; !ok {
				http.Error(w, "user no longer exists", http.StatusUnauthorized)
				return
			}
			for _, role := range allowed {
				if claims.Role == role {
					next.ServeHTTP(w, r)
					return
				}
			}
			http.Error(w, "role not authorized for this endpoint", http.StatusForbidden)
		})
	}
}

// extractClaims validates the bearer JWT signature (HMAC-SHA256), parses
// and checks exp, and returns the claims. Signature failure or expiry
// always returns an error — the middleware never trusts the payload
// before verifying the signature.
func extractClaims(r *http.Request, secret []byte) (consoleTokenClaims, error) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return consoleTokenClaims{}, errors.New("missing bearer token")
	}
	token := strings.TrimSpace(h[7:])
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return consoleTokenClaims{}, errors.New("malformed token")
	}
	// Verify signature over header.payload BEFORE parsing claims.
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return consoleTokenClaims{}, errors.New("malformed token signature")
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	if !hmac.Equal(mac.Sum(nil), sig) {
		return consoleTokenClaims{}, errors.New("invalid token signature")
	}
	// Header must declare HS256 — no algorithm confusion.
	hdr, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return consoleTokenClaims{}, errors.New("malformed token header")
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if json.Unmarshal(hdr, &header) != nil || header.Alg != "HS256" {
		return consoleTokenClaims{}, errors.New("unsupported token algorithm")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return consoleTokenClaims{}, errors.New("malformed token payload")
	}
	var claims consoleTokenClaims
	if json.Unmarshal(payload, &claims) != nil {
		return consoleTokenClaims{}, errors.New("malformed token claims")
	}
	if time.Now().UTC().Unix() > claims.ExpiresAt {
		return consoleTokenClaims{}, errors.New("token expired")
	}
	return claims, nil
}

func mintJWT(secret []byte, claims consoleTokenClaims) (string, error) {
	hdr, err := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	h, p := base64.RawURLEncoding.EncodeToString(hdr), base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(h + "." + p))
	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func hashPassword(password string) string {
	sum := sha256.Sum256([]byte(password))
	return fmt.Sprintf("%x", sum)
}
