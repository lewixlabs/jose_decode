#!/usr/bin/env python3
"""
Flask web interface for JWE decrypt + JWS verify.

Usage:
  pip install flask
  python app.py
  then open http://127.0.0.1:5000 in your browser
"""

from __future__ import annotations

import base64
import json
import traceback
from typing import Tuple, Dict, Any

from flask import Flask, request, jsonify, send_from_directory
from jwcrypto import jwe, jwk
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

app = Flask(__name__, static_folder=".", static_url_path="")


# ----------------------------
# Crypto helpers
# ----------------------------

def b64url_decode(data: str) -> bytes:
    rem = len(data) % 4
    if rem:
        data += "=" * (4 - rem)
    return base64.urlsafe_b64decode(data.encode("ascii"))


def decrypt_jwe_compact(jwe_compact: str, recipient_private_pem: bytes) -> Tuple[Dict[str, Any], bytes]:
    recipient_key = jwk.JWK.from_pem(recipient_private_pem)
    jwe_obj = jwe.JWE()
    jwe_obj.deserialize(jwe_compact)
    jwe_obj.decrypt(recipient_key)
    return jwe_obj.jose_header, jwe_obj.payload


def load_public_key_from_pem_content(pem_content: bytes):
    """Accepts either a PEM certificate (BEGIN CERTIFICATE) or a PEM public key."""
    if b"BEGIN CERTIFICATE" in pem_content:
        cert = x509.load_pem_x509_certificate(pem_content)
        return cert.public_key()
    return serialization.load_pem_public_key(pem_content)


def verify_jws_rs256(jws_compact: str, public_key) -> Tuple[Dict[str, Any], bytes]:
    parts = jws_compact.strip().split(".")
    if len(parts) != 3:
        raise ValueError(f"JWS non valido: attesi 3 segmenti, trovati {len(parts)}.")

    header_b64, payload_b64, sig_b64 = parts
    header = json.loads(b64url_decode(header_b64))
    signature = b64url_decode(sig_b64)
    signing_input = (header_b64 + "." + payload_b64).encode("ascii")

    public_key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())

    payload_bytes = b64url_decode(payload_b64)
    return header, payload_bytes


# ----------------------------
# Routes
# ----------------------------

@app.route("/")
def index():
    return send_from_directory(".", "index.html")


@app.route("/api/decrypt", methods=["POST"])
def api_decrypt():
    try:
        # Validate presence of required files/fields
        for field in ("private_key", "public_key"):
            if field not in request.files or request.files[field].filename == "":
                labels = {"private_key": "Chiave privata", "public_key": "Chiave pubblica"}
                return jsonify({"error": f"{labels[field]} mancante."}), 400

        jwe_token = request.form.get("jwe_token", "").strip()
        if not jwe_token:
            return jsonify({"error": "Payload JWE mancante."}), 400

        private_key_pem = request.files["private_key"].read()
        public_key_pem  = request.files["public_key"].read()

        # Validate JWE segment count
        if len(jwe_token.split(".")) != 5:
            n = len(jwe_token.split("."))
            return jsonify({"error": f"JWE non valido: attesi 5 segmenti, trovati {n}."}), 400

        # ── Step 1: Decrypt JWE ──────────────────────────────────────────────
        jwe_header, plaintext = decrypt_jwe_compact(jwe_token, private_key_pem)

        # ── Step 2: plaintext deve essere un JWS ASCII ───────────────────────
        try:
            jws_token = plaintext.decode("ascii").strip()
        except UnicodeDecodeError:
            return jsonify({
                "jwe_decryption": "OK",
                "jwe_header": jwe_header,
                "error": "Il plaintext non è ASCII; non sembra un JWS compact.",
                "plaintext_hex": plaintext.hex(),
            })

        if len(jws_token.split(".")) != 3:
            n = len(jws_token.split("."))
            return jsonify({
                "jwe_decryption": "OK",
                "jwe_header": jwe_header,
                "error": f"Il plaintext non è un JWS compact valido: attesi 3 segmenti, trovati {n}.",
                "plaintext_preview": jws_token[:200],
            })

        # ── Step 3: Verify JWS RS256 ─────────────────────────────────────────
        public_key = load_public_key_from_pem_content(public_key_pem)
        jws_header, payload_bytes = verify_jws_rs256(jws_token, public_key)

        # ── Step 4: Decode payload ───────────────────────────────────────────
        try:
            payload = json.loads(payload_bytes.decode("utf-8"))
        except Exception:
            payload = payload_bytes.decode("utf-8", errors="replace")

        return jsonify({
            "jwe_decryption": "OK",
            "jws_verification": "OK",
            "jwe_header": jwe_header,
            "jws_header": jws_header,
            "payload": payload,
        })

    except Exception as exc:
        return jsonify({
            "error": str(exc),
            "detail": traceback.format_exc(),
        }), 500


if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=5000)
