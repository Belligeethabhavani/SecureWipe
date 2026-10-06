# SecureWipe

> **NIST SP 800-88 compliant secure data destruction with cryptographically-signed, independently-verifiable PDF certificates.**

[![Python](https://img.shields.io/badge/Python-3.11+-blue)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Standard](https://img.shields.io/badge/Standard-NIST%20SP%20800--88%20Rev.1-blue)](#)
[![Crypto](https://img.shields.io/badge/Crypto-Ed25519%20%7C%20HKDF%20%7C%20DPAPI-purple)](#)

---

## What is SecureWipe?

Windows `Delete` doesn't delete. It removes the directory entry — the underlying data sits intact on disk until overwritten. Any basic recovery tool recovers it in seconds.

SecureWipe provides:
- **Secure multi-pass file overwriting** following NIST SP 800-88 and DoD 5220.22-M standards
- **Raw sector drive wiping** — writes every byte sector-by-sector, covering deleted files, slack space, and unallocated clusters
- **Cryptographically-signed PDF certificates** — Ed25519-signed, device-attested, independently verifiable offline

---

## Screenshots

*(Run the app — it speaks for itself.)*

---

## Features

| Feature | Detail |
|---|---|
| Wipe Algorithms | NIST Clear (1-pass), DoD 5220.22-M (3-pass), Gutmann (7-pass) |
| File Overwrite | SHA-256 pre-wipe hash, multi-pass random/ones/zeros + fsync, UUID rename, truncate-delete |
| Folder Wipe | Recursive, all files + directory cleanup |
| USB / Drive Detection | Detects USB-connected SSDs via `wmic InterfaceType=USB` (not just removable-flag) |
| Raw Sector Wipe | Writes `\\.\PHYSICALDRIVEn` from byte 0 to end — no filesystem bypass possible |
| Signed PDF Certificate | Whole PDF hashed + Ed25519 signed; signature appended after `%%EOF` |
| Device Attestation | Machine GUID + MAC + Windows SID embedded in signed PDF |
| DPAPI Key Storage | Signing seed encrypted with Windows DPAPI (machine + account bound) |
| Hardware-Derived Key | HKDF-SHA256 over seed + hardware fingerprint → deterministic per-machine key |
| Offline Verification | `verify.html` — drag PDF + paste public key → browser verifies Ed25519 |
| Tamper Detection | Any character change in PDF invalidates signature; double-marker → FORGED |
| Audit Log | Chained SHA-256 log — tamper-evident event chain |

---

## Requirements

- **Windows 10 / 11** (DPAPI + wmic required)
- **Python 3.11+**
- **Run as Administrator** for raw drive wipe (file wipe works without)

### Dependencies

```bash
pip install -r requirements.txt
```

```
PySide6
reportlab
cryptography
qrcode[pil]
pillow
psutil
```

---

## Installation & Usage

```bash
# Clone or extract
cd SecureWipe

# Install dependencies
pip install -r requirements.txt

# Run (standard — file wipe only)
py main.py

# Run as Administrator (required for raw drive wipe)
# Right-click → Run as administrator  →  py main.py
```

---

## How to Wipe Files

1. Open the **Files & Folders** tab
2. Click **Add Files** or **Add Folder**
3. Select algorithm in the right panel *(DoD 3-pass recommended)*
4. Click **🗑 Start Secure Wipe**
5. A signed PDF certificate is saved to your **Desktop**

---

## How to Wipe a Drive (Raw Sector)

> ⚠️ Run SecureWipe as **Administrator** for this.

1. Open the **USB Devices** tab
2. Click **Refresh** — your USB-connected drives appear (including SSDs)
3. Select the drive
4. Click **Wipe Entire Drive** — shows confirmation with model, capacity, physical path
5. Confirm → raw sector wipe begins, progress shown in GB
6. Certificate generated on completion

**What this covers:** Every sector — including deleted files, slack space, unallocated clusters, MFT, and previously deleted partitions.

**SSD Note:** Due to wear-leveling, software-level sector overwrite cannot guarantee every flash cell is re-written. For maximum assurance on SSDs, use the manufacturer's ATA Secure Erase tool in addition. NIST SP 800-88 specifically recommends "Sanitize" for SSDs.

---

## Verifying a Certificate

No SecureWipe installation required. Just a modern browser (Chrome 113+, Firefox 123+, Safari 17+).

1. Open `verify.html` in your browser (or visit the hosted version)
2. Drag & drop the PDF certificate
3. Paste the **Device Public Key** from page 1 (or scan the QR code)
4. Click **Verify Certificate**

The browser:
- Finds the signature block (exactly one — two = FORGED)
- Hashes the entire PDF body with SHA-256
- Verifies the Ed25519 signature using the Web Crypto API

✅ = The PDF has not been modified since it was signed.

---

## The Cryptography Stack

```
Ed25519 (RFC 8032)        ← digital signature
SHA-256                   ← PDF body hash + HKDF
HKDF-SHA256               ← hardware-derived key derivation
Windows DPAPI             ← seed encryption (machine + account bound)
Web Crypto API            ← browser-side verification (no library)
```

### Key Binding

The private key is not stored — it's derived on every run:
```
DPAPI_decrypt(device_seed.enc) → seed
HKDF(ikm=seed, info="SecureWipe-v1|" + machine_guid + mac + username + sid)
→ Ed25519 private key
→ Public key (printed on certificate page 1)
```

The public key is a deterministic fingerprint of the specific machine + user account.

---

## Security Properties

| Threat | Outcome |
|---|---|
| Edit any PDF content | SHA-256 changes → signature invalid |
| Swap file records | Signed → invalid |
| Generate fresh keypair and forge | Public key ≠ what's signed in PDF body |
| Double-marker injection | Policy: exactly one marker → FORGED |
| Replay a different machine's cert | Machine GUID + MAC don't match device |
| Extract private key | DPAPI-bound → useless on any other machine |

---

## License

MIT License — see [LICENSE](../LICENSE)

---

## Compliance References

- **NIST SP 800-88 Rev. 1** — Guidelines for Media Sanitization  
- **DoD 5220.22-M** — National Industrial Security Program Operating Manual  
- **RFC 8032** — Edwards-Curve Digital Signature Algorithm (EdDSA)  
- **FIPS 180-4** — SHA-256  
- **RFC 5869** — HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
