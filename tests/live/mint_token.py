#!/usr/bin/env python3
"""Mints an ES256 JWT signed by the gateway's test private key.

Usage: python3 mint_token.py [--kid KID] [--aud AUDIENCE] [--exp SECONDS]

The testdata key is a P-256 EC key, so the token is signed ES256 (the
gateway validator also accepts RS256/384/512 and EdDSA against the
same configured public key material).
Prints the signed JWT to stdout. --exp sets the token lifetime in seconds
from now (default 600). Used by the live Stage 3 test to exercise the
gateway's JWT-bound identity path with real cryptography.
"""
import argparse
import base64
import json
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

KEY_PATH = "/home/ubuntu/verify/mcp-gateway/pkg/identity/testdata/gateway-key.pem"

parser = argparse.ArgumentParser()
parser.add_argument("--kid", default="gateway-key", help="JWK key id (default gateway-key)")
parser.add_argument("--aud", default=None, help="audience claim (default mcpgw-test)")
parser.add_argument("--exp", type=int, default=600, help="token lifetime in seconds from now (default 600)")
parser.add_argument("--key", default=KEY_PATH, help="private key PEM (default testdata gateway-key.pem)")
args = parser.parse_args()
KEY_PATH = args.key

with open(KEY_PATH, "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

header = {"alg": "ES256", "typ": "JWT", "kid": args.kid}
now = int(time.time())
payload = {
    "sub": "hr-agent",
    "iss": "mcpgw-test",
    "iat": now,
    "exp": now + args.exp,
    "nbf": now - 10,
}
if args.aud:
    payload["aud"] = args.aud


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


seg1 = b64u(json.dumps(header, separators=(",", ":")).encode())
seg2 = b64u(json.dumps(payload, separators=(",", ":")).encode())
signing_input = f"{seg1}.{seg2}".encode()
der_sig = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
# RFC 7515 ES256 requires the raw fixed-length r||s form, not DER.
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

r, s = decode_dss_signature(der_sig)
curve_bytes = private_key.key_size // 8
sig = r.to_bytes(curve_bytes, "big") + s.to_bytes(curve_bytes, "big")
print(f"{seg1}.{seg2}.{b64u(sig)}")  # RFC 7515 fixed-length r||s
