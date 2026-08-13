"""Upstream verifier for X-Mcpgw-Identity (Stage 4 / Ticket 21).

This is exactly the verification logic an upstream MCP server implements:
base64url-decode the JWT, verify the Ed25519 signature over
header.claims with the gateway's public key, then inspect claims.
"""
import base64
import json
import os
import subprocess
import sys

if len(sys.argv) != 3:
    print(f"usage: {sys.argv[0]} <jwt> <gateway_pubkey.pem>")
    sys.exit(2)
tok, pub_path = sys.argv[1], sys.argv[2]
parts = tok.split(".")
if len(parts) != 3:
    print(f"FAIL: token has {len(parts)} segments, expected 3")
    sys.exit(1)

# Extract the public key bytes from the PEM (SubjectPublicKeyInfo).
out = subprocess.run(["openssl", "pkey", "-pubin", "-in", pub_path,
                      "-outform", "DER"], capture_output=True, check=True)
pub_bytes = out.stdout

sig = base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4))
signed = f"{parts[0]}.{parts[1]}".encode()

# openssl pkeyutl needs seekable inputs (it cannot size stdin in
# oneshot mode), and it cannot take both the signed payload and the raw
# signature over stdin, so both are staged in temp files.
msg_path = f"/tmp/.mcpgw-msg-{os.getpid()}"
sig_path = f"/tmp/.mcpgw-sig-{os.getpid()}"
try:
    with open(msg_path, "wb") as fh:
        fh.write(signed)
    with open(sig_path, "wb") as fh:
        fh.write(sig)
    ok = subprocess.run(["openssl", "pkeyutl", "-verify",
                         "-pubin", "-inkey", pub_path,
                         "-rawin", "-in", msg_path, "-sigfile", sig_path],
                        capture_output=True)
finally:
    for p in (msg_path, sig_path):
        try:
            os.remove(p)
        except OSError:
            pass
if ok.returncode != 0:
    print("FAIL: ed25519 signature verification failed")
    sys.exit(1)

hb = base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4))
cb = base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4))
h, c = json.loads(hb), json.loads(cb)
print(f"PASS: ed25519 signature valid | alg={h.get('alg')} kid={h.get('kid')}")
print(f"      claims: sub={c.get('sub')} aud={c.get('aud')} "
      f"iat={c.get('iat')} exp={c.get('exp')}")
if h.get("alg") != "EdDSA" or c.get("exp", 0) <= c.get("iat", 0):
    sys.exit(1)
