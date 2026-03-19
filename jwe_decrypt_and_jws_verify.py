#!/usr/bin/env python3
"""
JWE (decrypt) + JWS (verify) end-to-end in un unico script.

Scenario tipico (il tuo):
- Ricevi un JWE "compact" (5 segmenti) cifrato per TE:
    alg = RSA-OAEP-256   -> la CEK è cifrata con la tua *chiave pubblica*
    enc = A256GCM        -> il contenuto è cifrato con AES-256-GCM usando la CEK
- Dopo la decifratura, il plaintext contiene un JWS/JWT "compact" (3 segmenti)
  firmato dal MITTENTE:
    alg = RS256 -> RSA PKCS#1 v1.5 + SHA-256

Quindi il flusso è:  JWS (sign) -> JWE (encrypt)
Tu fai il contrario: JWE (decrypt) -> JWS (verify)

Dipendenze:
  pip install jwcrypto cryptography

Uso:
  python jwe_decrypt_and_jws_verify.py private_key_pkcs8.pem jwe.txt sender_cert_or_pubkey.pem

File richiesti:
- private_key_pkcs8.pem: chiave privata RSA in formato PKCS#8 PEM (-----BEGIN PRIVATE KEY-----)
- jwe.txt: JWE compact (5 segmenti separati da '.')
- sender_cert_or_pubkey.pem: certificato X.509 PEM (-----BEGIN CERTIFICATE-----)
  oppure chiave pubblica PEM (-----BEGIN PUBLIC KEY-----) del mittente per verificare RS256.
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
# Utility: I/O e base64url
# ----------------------------

def read_text(path: str) -> str:
    """Legge un file di testo e fa strip degli spazi ai bordi."""
    with open(path, "r", encoding="utf-8") as f:
        return f.read().strip()


def b64url_decode(data: str) -> bytes:
    """
    Decodifica base64url (RFC 7515/7516) dove il padding '=' spesso è omesso.
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
    Decifra un JWE in compact serialization usando la private key del destinatario.

    Ritorna:
      - protected header (dict) del JWE
      - plaintext (bytes)
    """
    # Import della chiave privata (PKCS#8 PEM) in formato JWK per jwcrypto
    recipient_key = jwk.JWK.from_pem(recipient_private_pkcs8_pem.encode("utf-8"))

    jwe_obj = jwe.JWE()
    jwe_obj.deserialize(jwe_compact)

    # Decifra: RSA-OAEP-256 -> ottiene CEK; poi A256GCM -> plaintext + verifica tag GCM.
    jwe_obj.decrypt(recipient_key)

    # jose_header: include header protetto; utile per debug/telemetria
    return jwe_obj.jose_header, jwe_obj.payload


# ----------------------------
# Step 2: Verify JWS (RS256)
# ----------------------------

def load_public_key_from_pem(path: str):
    """
    Carica una chiave pubblica da:
    - certificato X.509 PEM (BEGIN CERTIFICATE) oppure
    - public key PEM (BEGIN PUBLIC KEY)
    """
    pem = open(path, "rb").read()

    if b"BEGIN CERTIFICATE" in pem:
        cert = x509.load_pem_x509_certificate(pem)
        return cert.public_key()

    return serialization.load_pem_public_key(pem)


def verify_jws_rs256(jws_compact: str, sender_pubkey_or_cert_path: str) -> Tuple[Dict[str, Any], bytes]:
    """
    Verifica un JWS compact firmato con RS256.
    Ritorna:
      - header del JWS (dict)
      - payload del JWS (bytes) (tipicamente JSON UTF-8)
    """
    parts = jws_compact.strip().split(".")
    if len(parts) != 3:
        raise ValueError(
            f"Il plaintext non è un JWS compact valido: attesi 3 segmenti, trovati {len(parts)}."
        )

    header_b64, payload_b64, sig_b64 = parts

    # Header e signature in bytes
    header = json.loads(b64url_decode(header_b64))
    signature = b64url_decode(sig_b64)

    # Input firmato = "<b64url(header)>.<b64url(payload)>"
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

    # Sanity check: un JWE compact ha 5 segmenti
    jwe_segments = jwe_token.split(".")
    if len(jwe_segments) != 5:
        print(f"ATTENZIONE: mi aspettavo un JWE compact a 5 parti, ma ho {len(jwe_segments)} segmenti.")
        print("Se questo file contiene altro testo oltre al token, puliscilo e riprova.")
        return 2

    # 1) Decrypt JWE -> ottengo JWS (plaintext)
    jwe_header, plaintext = decrypt_jwe_compact(jwe_token, recipient_priv_pem)

    print("JWE decryption: OK")
    print("JWE protected header:")
    print(json.dumps(jwe_header, indent=2, ensure_ascii=False))

    # Il plaintext nel tuo caso è un JWS compact: deve essere ASCII
    try:
        jws_token = plaintext.decode("ascii").strip()
    except UnicodeDecodeError:
        print("Plaintext non è ASCII: non sembra un JWS compact. Stampo raw bytes e termino.")
        print(plaintext)
        return 1

    # Sanity check: un JWS compact ha 3 segmenti
    jws_segments = jws_token.split(".")
    if len(jws_segments) != 3:
        print(f"ATTENZIONE: mi aspettavo un JWS compact a 3 parti, ma ho {len(jws_segments)} segmenti.")
        print("Probabile plaintext troncato o non è un JWS.")
        print("Prime 120 chars:", jws_token[:120])
        return 1

    # 2) Verify JWS RS256 -> ottengo payload "trusted"
    jws_header, payload_bytes = verify_jws_rs256(jws_token, sender_pub_path)

    print("\nJWS signature verification: OK")
    print("JWS header:")
    print(json.dumps(jws_header, indent=2, ensure_ascii=False))

    # 3) Decodifica payload (spesso JSON)
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