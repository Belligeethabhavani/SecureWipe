"""
Device fingerprint collection for SecureWipe certificates.

Gathers machine-specific identifiers that are baked into:
  1. The Ed25519 key derivation (so the key IS the device's identity)
  2. The signed PDF certificate (so replay/forgery is visually detectable)

For full-drive wipes, also collects storage device details
(model, serial, filesystem, capacity) to tie the cert to the exact hardware.
"""

import os
import platform
import subprocess
import uuid
import socket
import winreg
import psutil


# ── Machine fingerprint ───────────────────────────────────────────────────────

def get_machine_guid() -> str:
    """Read the Windows MachineGuid from registry — unique per Windows install."""
    try:
        key  = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                               r"SOFTWARE\Microsoft\Cryptography")
        guid = winreg.QueryValueEx(key, "MachineGuid")[0]
        winreg.CloseKey(key)
        return guid
    except Exception:
        return "UNKNOWN"


def get_mac_address() -> str:
    """Return the primary MAC address as a colon-separated hex string."""
    try:
        mac_int = uuid.getnode()
        return ":".join(f"{(mac_int >> (8 * i)) & 0xff:02x}"
                        for i in reversed(range(6)))
    except Exception:
        return "UNKNOWN"


def get_windows_sid() -> str:
    """Return the current user's Windows Security Identifier (SID)."""
    try:
        result = subprocess.run(
            ["whoami", "/user"],
            capture_output=True, text=True, timeout=5
        )
        # Last token on the last non-empty line is the SID
        for line in reversed(result.stdout.strip().splitlines()):
            parts = line.split()
            if parts:
                return parts[-1]
    except Exception:
        pass
    return "UNKNOWN"


def get_device_fingerprint() -> dict:
    """
    Return a dict of machine-specific identifiers.

    This dict is included in the signed PDF (human-readable) and used
    as HKDF `info` in key derivation — tying the private key to this
    machine + account combination.
    """
    return {
        "machine_name":    platform.node(),
        "username":        os.environ.get("USERNAME", os.getlogin()),
        "machine_guid":    get_machine_guid(),
        "mac_address":     get_mac_address(),
        "windows_sid":     get_windows_sid(),
        "os_version":      platform.version(),
    }


def fingerprint_string(fp: dict) -> str:
    """Stable one-liner used as HKDF `info` — sorted, joined."""
    keys = ["machine_name", "username", "machine_guid", "mac_address", "windows_sid"]
    return "|".join(f"{k}={fp.get(k, '')}" for k in keys)


# ── Storage device details (for full-drive wipes) ─────────────────────────────

def get_drive_details(mount_point: str) -> dict:
    """
    Return model, serial, filesystem, and capacity for the drive at mount_point.

    Uses psutil for filesystem/capacity and wmic for model/serial.
    Falls back gracefully if wmic is unavailable.
    """
    info = {
        "mount_point": mount_point,
        "filesystem":  "UNKNOWN",
        "total_gb":    0.0,
        "model":       "UNKNOWN",
        "serial":      "UNKNOWN",
    }

    # psutil: filesystem and capacity
    try:
        for part in psutil.disk_partitions(all=True):
            if os.path.normpath(part.mountpoint) == os.path.normpath(mount_point):
                info["filesystem"] = part.fstype or "UNKNOWN"
                try:
                    usage = psutil.disk_usage(mount_point)
                    info["total_gb"] = round(usage.total / (1024 ** 3), 2)
                except Exception:
                    pass
                break
    except Exception:
        pass

    # wmic: drive model and serial
    try:
        drive_letter = os.path.splitdrive(mount_point)[0].upper()
        # Map logical disk to physical disk, then get model/serial
        result = subprocess.run(
            ["wmic", "logicaldisk", "where",
             f'DeviceID="{drive_letter}"',
             "assoc", "/resultclass:win32_diskdrive",
             "/all"],
            capture_output=True, text=True, timeout=6
        )
        # Fallback: just get volume serial number from logicaldisk
        r2 = subprocess.run(
            ["wmic", "logicaldisk", "where",
             f'DeviceID="{drive_letter}"',
             "get", "VolumeSerialNumber,FileSystem"],
            capture_output=True, text=True, timeout=5
        )
        lines = [l.strip() for l in r2.stdout.strip().splitlines() if l.strip()]
        if len(lines) >= 2:
            parts = lines[1].split()
            if len(parts) >= 2:
                info["filesystem"] = parts[0]
                info["serial"] = parts[1]
    except Exception:
        pass

    # Try getting disk model from wmic diskdrive
    try:
        drive_letter = os.path.splitdrive(mount_point)[0].upper()
        r3 = subprocess.run(
            ["wmic", "diskdrive", "get", "Model,SerialNumber"],
            capture_output=True, text=True, timeout=5
        )
        lines = [l.strip() for l in r3.stdout.strip().splitlines()
                 if l.strip() and "Model" not in l]
        if lines:
            # Take first physical disk (approximate)
            parts = lines[0].rsplit(None, 1)
            if len(parts) == 2:
                info["model"]  = parts[0].strip()
                if info["serial"] == "UNKNOWN":
                    info["serial"] = parts[1].strip()
    except Exception:
        pass

    return info
