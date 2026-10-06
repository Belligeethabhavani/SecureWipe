

import json
import hashlib


def build_record(cert_id: str, timestamp: str, algorithm: str,
                 passes: int, wiped_files: dict,
                 device_fp: dict = None,
                 storage_devices: list = None) -> dict:
    
    record = {
        "cert_id":   cert_id,
        "timestamp": timestamp,
        "algorithm": algorithm,
        "passes":    passes,
        "files":     [
            {"path": path, "sha256": sha256}
            for path, sha256 in wiped_files.items()
        ],
    }
    if device_fp:
        record["device"] = {
            "machine_name": device_fp.get("machine_name", ""),
            "username":     device_fp.get("username", ""),
            "machine_guid": device_fp.get("machine_guid", ""),
            "mac_address":  device_fp.get("mac_address", ""),
            "windows_sid":  device_fp.get("windows_sid", ""),
            "os_version":   device_fp.get("os_version", ""),
        }
    if storage_devices:
        record["storage_devices"] = storage_devices
    return record


def _canonical_bytes(record: dict) -> bytes:
    """Deterministic JSON bytes,same input always produces same bytes."""
    return json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_record(record: dict, private_key) -> str:
    """
    Sign the canonical record bytes with Ed25519.
    Returns the signature as a lowercase hex string (128 hex chars = 64 bytes).
    """
    sig_bytes = private_key.sign(_canonical_bytes(record))
    return sig_bytes.hex()


def verify_record(record: dict, signature_hex: str, public_key_hex: str) -> bool:
    """
    Verify an Ed25519 signature over a wipe record.
    Returns True if valid, False otherwise.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    try:
        sig_bytes = bytes.fromhex(signature_hex)
        pub_bytes = bytes.fromhex(public_key_hex)
        pub_key   = Ed25519PublicKey.from_public_bytes(pub_bytes)
        pub_key.verify(sig_bytes, _canonical_bytes(record))
        return True
    except (InvalidSignature, ValueError, Exception):
        return False
