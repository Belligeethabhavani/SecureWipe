


def verify_qr_payload(qr_string: str) -> dict:
    
    import base64, json
    result = {
        "valid":       False,
        "cert_id":     None,
        "pub_key_hex": None,
        "record_hash": None,
        "issues":      [],
    }

    try:
        raw = qr_string.strip()
        if not raw.startswith("SWCERT1:"):
            result["issues"].append("Not a SecureWipe QR payload (must start with SWCERT1:)")
            return result

        b64 = raw[len("SWCERT1:"):]
        b64 += "=" * (-len(b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(b64))
    except Exception as e:
        result["issues"].append(f"Cannot decode QR payload: {e}")
        return result

    result["cert_id"]     = payload.get("id")
    result["pub_key_hex"] = payload.get("pub")
    result["record_hash"] = payload.get("rhash")

    for field in ("id", "pub", "sig", "rhash"):
        if not payload.get(field):
            result["issues"].append(f"Missing field: '{field}'")

    if not result["issues"]:
        try:
            sig_len = len(bytes.fromhex(payload["sig"]))
            pub_len = len(bytes.fromhex(payload["pub"]))
            if sig_len != 64:
                result["issues"].append(f"Signature is {sig_len} bytes — expected 64")
            if pub_len != 32:
                result["issues"].append(f"Public key is {pub_len} bytes — expected 32")
        except ValueError as e:
            result["issues"].append(f"Hex decode error: {e}")

    result["valid"]   = len(result["issues"]) == 0
    result["payload"] = payload
    return result
