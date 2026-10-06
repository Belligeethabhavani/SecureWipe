

import os
import ctypes
import ctypes.wintypes

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from core.device_info import get_device_fingerprint, fingerprint_string


KEY_DIR  = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "SecureWipe")
KEY_FILE = os.path.join(KEY_DIR, "device_seed.enc")   # stores DPAPI-encrypted random seed


# ── Windows DPAPI wrappers ────────────────────────────────────────────────────

class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", ctypes.wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_char)),
    ]


def _dpapi_encrypt(plaintext: bytes) -> bytes:
    buf      = ctypes.create_string_buffer(plaintext)
    blob_in  = _DataBlob(len(plaintext), buf)
    blob_out = _DataBlob()
    ok = ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)
    )
    if not ok:
        raise RuntimeError("DPAPI CryptProtectData failed")
    result = ctypes.string_at(blob_out.pbData, blob_out.cbData)
    ctypes.windll.kernel32.LocalFree(blob_out.pbData)
    return result


def _dpapi_decrypt(ciphertext: bytes) -> bytes:
    buf      = ctypes.create_string_buffer(ciphertext)
    blob_in  = _DataBlob(len(ciphertext), buf)
    blob_out = _DataBlob()
    ok = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)
    )
    if not ok:
        raise RuntimeError(
            "DPAPI decryption failed — key was created on a different machine or account."
        )
    result = ctypes.string_at(blob_out.pbData, blob_out.cbData)
    ctypes.windll.kernel32.LocalFree(blob_out.pbData)
    return result


# ── Key derivation ────────────────────────────────────────────────────────────

def _derive_key_from_seed(seed: bytes, fp: dict) -> bytes:
    """
    HKDF-SHA256: derive a 32-byte Ed25519 seed from the random seed + hardware info.

    The `info` parameter encodes the device fingerprint — changing any part of it
    (different machine, different user, different MAC) produces a completely
    different key.
    """
    info = ("SecureWipe-v1|" + fingerprint_string(fp)).encode("utf-8")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    )
    return hkdf.derive(seed)


# ── Public API ────────────────────────────────────────────────────────────────

def get_or_create_device_key() -> tuple:
    """
    Return (private_key_obj, public_key_bytes_raw, device_fingerprint_dict).

    Generates a random seed on first run, encrypts it with DPAPI, and derives
    the Ed25519 key using HKDF with the machine's hardware fingerprint as info.
    """
    os.makedirs(KEY_DIR, exist_ok=True)
    fp = get_device_fingerprint()

    if os.path.isfile(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            encrypted_seed = f.read()
        seed = _dpapi_decrypt(encrypted_seed)
    else:
        # Generate a fresh random 32-byte seed, encrypt, persist
        import secrets
        seed          = secrets.token_bytes(32)
        encrypted_seed = _dpapi_encrypt(seed)
        with open(KEY_FILE, "wb") as f:
            f.write(encrypted_seed)

    derived     = _derive_key_from_seed(seed, fp)
    private_key = Ed25519PrivateKey.from_private_bytes(derived)
    pub_bytes   = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    return private_key, pub_bytes, fp


def get_public_key_hex() -> str:
    _, pub, _ = get_or_create_device_key()
    return pub.hex()
