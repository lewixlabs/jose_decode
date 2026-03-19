# JWE Decrypt + JWS Verify

This repository contains a single Python script that performs an end-to-end JOSE pipeline:

1. **Decrypt a JWE (compact serialization)** using the recipient’s **RSA private key**.
2. **Verify a JWS (compact serialization)** found inside the decrypted plaintext using the **sender’s public key or X.509 certificate**.
3. Print the verified payload (typically JSON).

## Typical scenario

You receive a **JWE compact token** (5 dot-separated parts) encrypted **for you**:

- `alg = RSA-OAEP-256`  
  The content-encryption key (CEK) is encrypted with the recipient’s **public key** (RSA OAEP SHA-256).
- `enc = A256GCM`  
  The message content is encrypted with **AES-256-GCM** using the CEK.

After decrypting the JWE, the plaintext contains a **JWS/JWT compact token** (3 dot-separated parts) **signed by the sender**:

- `alg = RS256`  
  RSA PKCS#1 v1.5 + SHA-256 signature.

So the producer flow is usually:

- **JWS (sign)** → **JWE (encrypt)**

And the consumer (this script) does the reverse:

- **JWE (decrypt)** → **JWS (verify)**

## Requirements

- Python 3.9+ recommended

Python dependencies:

```bash
pip install jwcrypto cryptography
```

## Usage

```bash
python jwe_decrypt_and_jws_verify.py private_key_pkcs8.pem jwe.txt sender_cert_or_pubkey.pem
```

## Required input files

### 1) Recipient private key (PKCS#8 PEM)

`private_key_pkcs8.pem`

- Must be an RSA private key in **PKCS#8 PEM** format:
  - `-----BEGIN PRIVATE KEY-----`
  - `-----END PRIVATE KEY-----`

This key is used to decrypt the incoming JWE.

### 2) JWE token (compact serialization)

`jwe.txt`

- A single line containing the JWE compact token.
- Must have **5** dot-separated segments:

`protected_header.encrypted_key.iv.ciphertext.tag`

### 3) Sender public material for RS256 verification

`sender_cert_or_pubkey.pem`

Either:

- An **X.509 certificate** (PEM):
  - `-----BEGIN CERTIFICATE-----`
  - `-----END CERTIFICATE-----`

or:

- A **public key** (PEM):
  - `-----BEGIN PUBLIC KEY-----`
  - `-----END PUBLIC KEY-----`

This key/certificate is used to verify the RS256 signature of the JWS found inside the decrypted JWE plaintext.

## Notes

- If the file in `jwe.txt` does not contain exactly 5 segments, the input is not a valid JWE compact token (or the file contains extra text).
- The decrypted plaintext must be a **JWS compact token** with exactly **3 segments**. If it only has 2 segments (`header.payload`), the signature part is missing and the JWS cannot be verified.
- Decrypting the JWE provides confidentiality and integrity (AES-GCM tag), while verifying the inner JWS provides authenticity/integrity of the signed content (assuming you verify using the correct sender key).

## Script

See: `jwe_decrypt_and_jws_verify.py`
