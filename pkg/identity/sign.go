package identity

import (
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"bytes"
	"fmt"
	"time"
)

// Upstream identity injection (Stage 6, Ticket 21 — README.md "Upstream
// identity injection"). Once a caller clears JWT/mTLS validation and policy
// evaluation, the gateway mints a short-lived (30s) Ed25519 JWT and injects
// it as X-Mcpgw-Identity on the forwarded upstream request, so the upstream
// MCP server can enforce secondary row-level security on gateway-attested
// claims. An unsigned header is worthless — only the verified signature
// proves the gateway vouched for the identity.
//
// Header: {alg: "EdDSA", typ: "JWT", kid: base64url(SHA-256(public key))}.
// Claims: {sub: verified caller identity, aud: upstream alias, iat, exp(+30s)}.

// IdentityHeader is injected onto the forwarded upstream request.
const IdentityHeader = "X-Mcpgw-Identity"

// IdentityTokenLifetime is the attestation validity window. Thirty seconds is
// long enough to cover an MCP tool call round-trip, short enough to make a
// leaked attestation useless.
const IdentityTokenLifetime = 30 * time.Second

// SigningKey is the gateway's Ed25519 identity key.
type SigningKey ed25519.PrivateKey

// ed25519PKCS8Prefix is the DER-encoded PKCS#8 wrapper up to (but not
// including) the 32-byte raw seed. Any PKCS#8 key whose DER does not start
// with this prefix is structurally not Ed25519 (RSA/ECDSA have different
// AlgorithmIdentifier OIDs) and is refused at startup — never a silent
// passthrough.
// Ed25519's PKCS#8 AlgorithmIdentifier is OID 1.3.101.112 encoded as
// 06 03 55 1d 70 — so the full DER prefix before the 32-byte seed is
// exactly these 16 bytes (RFC 8410, §7).
var ed25519PKCS8Prefix = []byte{
	// SEQUENCE(46) INTEGER(0) SEQUENCE(OID 1.3.101.112) OCTET STRING(34) OCTET STRING
	0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
	0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
}

// parseEd25519 validates the DER against the RFC 8410 prefix and extracts
// the raw seed. Anything else — RSA, ECDSA, or a malformed blob — fails
// closed.

// ParseSigningKey decodes a PKCS#8 Ed25519 private key from PEM. A
// non-Ed25519 key is a hard startup failure — never a silent passthrough.
func ParseSigningKey(pemBytes []byte) (SigningKey, error) {
	der, _ := pemToDER(pemBytes, "PRIVATE KEY")
	if der == nil {
		return nil, errors.New("identity signing key: no PKCS#8 private key block found")
	}
	key, err := parseEd25519(der)
	if err != nil {
		return nil, err
	}
	return SigningKey(key), nil
}

func parseEd25519(der []byte) (ed25519.PrivateKey, error) {
	if len(der) != len(ed25519PKCS8Prefix)+ed25519.SeedSize {
		return nil, fmt.Errorf("identity signing key: not an Ed25519 PKCS#8 key (%d bytes)", len(der))
	}
	if !bytes.HasPrefix(der, ed25519PKCS8Prefix) {
		return nil, errors.New("identity signing key: PKCS#8 structure is not Ed25519 (wrong OID)")
	}
	return ed25519.NewKeyFromSeed(der[len(der)-ed25519.SeedSize:]), nil
}

// kid derives the key identifier: base64url(SHA-256(public key)) — stable
// across restarts and unambiguous under key rotation.
func (k SigningKey) kid() string {
	pub := sha256.Sum256(ed25519.PrivateKey(k).Public().(ed25519.PublicKey))
	return base64.RawURLEncoding.EncodeToString(pub[:])
}

// MintIdentityJWT mints the upstream attestation JWT. sub is the verified
// caller identity (spiffe://… or token-sha256:…); aud is the upstream alias
// so each upstream can restrict which attestations it trusts.
func (k SigningKey) MintIdentityJWT(sub, aud string) (string, error) {
	if len(k) == 0 {
		return "", errors.New("identity signing key: no key configured")
	}
	now := time.Now().UTC()
	header := map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": k.kid()}
	claims := map[string]any{
		"sub": sub,
		"aud": aud,
		"iat": now.Unix(),
		"exp": now.Add(IdentityTokenLifetime).Unix(),
	}
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	h, c := b64u(hb), b64u(cb)
	sig := ed25519.Sign(ed25519.PrivateKey(k), []byte(h+"."+c))
	if err != nil {
		return "", fmt.Errorf("identity signing: %w", err)
	}
	return h + "." + c + "." + b64u(sig), nil
}

// IdentityClaim returns the verified identity string for the request: the
// SPIFFE subject takes precedence over the token hash, so mTLS identities
// always present their full principal.
func IdentityClaim(tokenHash, mtlsSubject string) string {
	switch {
	case mtlsSubject != "":
		return mtlsSubject
	case tokenHash != "":
		return "token-sha256:" + tokenHash
	default:
		return "unidentified"
	}
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// PublicBytes returns the raw 32-byte public key for PEM export (tests,
// Kubernetes secrets).
func (k SigningKey) PublicBytes() []byte {
	return []byte(ed25519.PrivateKey(k).Public().(ed25519.PublicKey))
}

// Ensure SigningKey satisfies crypto.Signer so it can slot into any
// downstream library that expects one.
var _ crypto.Signer = (ed25519.PrivateKey)(nil)

// pemToDER extracts the DER bytes of the first PEM block of the given type.
func pemToDER(data []byte, blockType string) ([]byte, bool) {
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, false
		}
		if block.Type == blockType {
			return block.Bytes, true
		}
		if len(rest) == 0 {
			return nil, false
		}
	}
}
