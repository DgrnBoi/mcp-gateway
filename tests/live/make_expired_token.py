#!/usr/bin/env python3
"""Builds an expired ES256 JWT with a FAKE signature.

Reuse the real header/payload structure that mint_token.py produces, but
set exp to the past and invalidate the signature so the gateway's validator
rejects it at claim-check time (or signature time).
"""
import base64
import json
import time

header = base64.urlsafe_b64encode(
    json.dumps({"alg": "ES256", "typ": "JWT", "kid": "gateway-key"}, separators=(",", ":")).encode()
).rstrip(b"=").decode()
payload = base64.urlsafe_b64encode(
    json.dumps({
        "sub": "hr-agent",
        "iss": "mcpgw-test",
        "iat": int(time.time()) - 700,
        "exp": int(time.time()) - 100,
        "nbf": int(time.time()) - 700,
        "aud": "mcpgw-test",
    }, separators=(",", ":")).encode()
).rstrip(b"=").decode()
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

with open("/home/ubuntu/verify/mcp-gateway/pkg/identity/testdata/gateway-key.pem", "rb") as f:
    key = serialization.load_pem_private_key(f.read(), password=None)
der = key.sign((header + "." + payload).encode(), ec.ECDSA(hashes.SHA256()))
r, s = decode_dss_signature(der)
raw = r.to_bytes(key.key_size // 8, "big") + s.to_bytes(key.key_size // 8, "big")
print(f"{header}.{payload}.{b64u(raw)}")
