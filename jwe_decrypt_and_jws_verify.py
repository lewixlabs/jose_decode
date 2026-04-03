#!/usr/bin/env python3
"""
JWE (decrypt) + JWS (verify) end-to-end in a single script.

Typical scenario:
- You receive a JWE in "compact" serialization (5 dot-separated segments) encrypted FOR YOU:
    alg = RSA-OAEP-256   -> the CEK is encrypted with your *public key*
    enc = A256GCM        -> the content is encrypted with AES-256-GCM using the CEK
- After decryption, the plaintext contains a JWS/JWT in "compact" serialization (3 dot-separated segments)
  signed by the SENDER:
    alg = RS256 -> RSA PKCS#1 v1.5 + SHA-256

Dependencies:
  pip install jwcrypto cryptography

Usage:
  python jwe_decrypt_and_jws_verify.py private_key_pkcs8.pem jwe.txt sender_cert_or_pubkey.pem

Required files:
- private_key_pkcs8.pem: RSA private key in PKCS#8 PEM format (-----BEGIN PRIVATE KEY-----)
- jwe.txt: JWE compact token (5 dot-separated segments)
- sender_cert_or_pubkey.pem: sender X.509 certificate in PEM format (-----BEGIN CERTIFICATE-----)
  or sender public key in PEM format (-----BEGIN PUBLIC KEY-----) used to verify RS256.
"""

from __future__ import annotations

import base64
import json
import sys
from typing import Tuple, Dict, Any

from jwcrypto import jwe, jwk
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


# ----------------------------
# Utility: I/O and base64url
# ----------------------------

def read_text(path: str) -> str:
    """Read a text file and strip leading/trailing whitespace."""
    with open(path, "r", encoding="utf-8") as f:
        return f.read().strip()


def b64url_decode(data: str) -> bytes:
    """
    Decode base64url (RFC 7515/7516) where padding '=' is often omitted.
    """
    rem = len(data) % 4
    if rem:
        data += "=" * (4 - rem)
    return base64.urlsafe_b64decode(data.encode("ascii"))


# ----------------------------
# Step 1: Decrypt JWE
# ----------------------------

def decrypt_jwe_compact(jwe_compact: str, recipient_private_pkcs8_pem: str) -> Tuple[Dict[str, Any], bytes]:
    """
    Decrypt a compact JWE using the recipient's private key.

    Returns:
      - protected header (dict) of the JWE
      - plaintext (bytes)
    """
    # Import the recipient private key (PKCS#8 PEM) as JWK for jwcrypto
    recipient_key = jwk.JWK.from_pem(recipient_private_pkcs8_pem.encode("utf-8"))

    jwe_obj = jwe.JWE()
    jwe_obj.deserialize(jwe_compact)

    # Decrypt: RSA-OAEP-256 -> get CEK; then A256GCM -> plaintext + verify GCM tag.
    jwe_obj.decrypt(recipient_key)

    # jose_header: includes the protected header; useful for debugging/telemetry
    return jwe_obj.jose_header, jwe_obj.payload


# ----------------------------
# Step 2: Verify JWS (RS256)
# ----------------------------

def load_public_key_from_pem(path: str):
    """
    Load a public key from:
    - an X.509 PEM certificate (BEGIN CERTIFICATE), or
    - a PEM public key (BEGIN PUBLIC KEY)
    """
    pem = open(path, "rb").read()

    if b"BEGIN CERTIFICATE" in pem:
        cert = x509.load_pem_x509_certificate(pem)
        return cert.public_key()

    return serialization.load_pem_public_key(pem)


def verify_jws_rs256(jws_compact: str, sender_pubkey_or_cert_path: str) -> Tuple[Dict[str, Any], bytes]:
    """
    Verify a compact JWS signed with RS256.
    Returns:
      - JWS header (dict)
      - JWS payload (bytes) (typically UTF-8 JSON)
    """
    parts = jws_compact.strip().split(".")
    if len(parts) != 3:
        raise ValueError(
            f"The plaintext is not a valid compact JWS: expected 3 segments, found {len(parts)}."
        )

    header_b64, payload_b64, sig_b64 = parts

    # Header and signature bytes
    header = json.loads(b64url_decode(header_b64))
    signature = b64url_decode(sig_b64)

    # Signed input = "<b64url(header)>.<b64url(payload)>"
    signing_input = (header_b64 + "." + payload_b64).encode("ascii")

    public_key = load_public_key_from_pem(sender_pubkey_or_cert_path)

    # RS256 = RSA PKCS#1 v1.5 padding + SHA-256
    public_key.verify(
        signature,
        signing_input,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )

    payload_bytes = b64url_decode(payload_b64)
    return header, payload_bytes


# ----------------------------
# Main: pipeline end-to-end
# ----------------------------

def main() -> int:
    if len(sys.argv) < 4:
        print("Usage: python jwe_decrypt_and_jws_verify.py <recipient_private_key.pem> <jwe.txt> <sender_cert_or_pubkey.pem>")
        return 2

    recipient_priv_path = sys.argv[1]
    jwe_path = sys.argv[2]
    sender_pub_path = sys.argv[3]

    recipient_priv_pem = read_text(recipient_priv_path)
    jwe_token = read_text(jwe_path)

    # Sanity check: a compact JWE has 5 segments
    jwe_segments = jwe_token.split(".")
    if len(jwe_segments) != 5:
        print(f"WARNING: expected a compact JWE with 5 parts, but got {len(jwe_segments)} segments.")
        print("If this file contains extra text beyond the token, clean it up and try again.")
        return 2

    # 1) Decrypt JWE -> get JWS (plaintext)
    jwe_header, plaintext = decrypt_jwe_compact(jwe_token, recipient_priv_pem)

    print("JWE decryption: OK")
    print("JWE protected header:")
    print(json.dumps(jwe_header, indent=2, ensure_ascii=False))

    # The plaintext is expected to be a compact JWS: must be ASCII
    try:
        jws_token = plaintext.decode("ascii").strip()
    except UnicodeDecodeError:
        print("Plaintext is not ASCII: does not appear to be a compact JWS. Printing raw bytes and exiting.")
        print(plaintext)
        return 1

    # Sanity check: a compact JWS has 3 segments
    jws_segments = jws_token.split(".")
    if len(jws_segments) != 3:
        print(f"WARNING: expected a compact JWS with 3 parts, but got {len(jws_segments)} segments.")
        print("Likely truncated plaintext or not a JWS.")
        print("First 120 chars:", jws_token[:120])
        return 1

    # 2) Verify JWS RS256 -> get "trusted" payload
    jws_header, payload_bytes = verify_jws_rs256(jws_token, sender_pub_path)

    print("\nJWS signature verification: OK")
    print("JWS header:")
    print(json.dumps(jws_header, indent=2, ensure_ascii=False))

    # 3) Decode payload (often JSON)
    print("\nJWS payload:")
    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    except Exception:
        # se non è JSON UTF-8, stampa raw
        try:
            print(payload_bytes.decode("utf-8", errors="replace"))
        except Exception:
            print(payload_bytes)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())