

import subprocess
import psutil
import os


def get_usb_drives() -> list:
    
    drives = []
    seen_mountpoints = set()

    # ── Method 1: wmic — most reliable for USB SSDs ───────────────────────────
    try:
        usb_drives = _wmic_usb_drives()  # list of {device_id, model}
        logical_map = _wmic_logical_map()  # physical → [logical_letters]

        for drv in usb_drives:
            letters = logical_map.get(drv["device_id"], [])
            if not letters:
                # Try matching by index (less precise but better than nothing)
                idx = drv.get("index", "")
                letters = logical_map.get(f"Disk #{idx}", [])

            for letter in letters:
                mount = letter.rstrip("\\") + "\\"
                if mount in seen_mountpoints:
                    continue
                entry = _drive_entry(mount, model=drv.get("model", ""))
                if entry:
                    drives.append(entry)
                    seen_mountpoints.add(mount)
    except Exception:
        pass

    # ── Method 2: psutil removable flag (fallback) ────────────────────────────
    try:
        for part in psutil.disk_partitions(all=False):
            if part.mountpoint in seen_mountpoints:
                continue
            if "removable" in part.opts.lower():
                entry = _drive_entry(part.mountpoint)
                if entry:
                    drives.append(entry)
                    seen_mountpoints.add(part.mountpoint)
    except Exception:
        pass

    return drives


# ── Helpers ───────────────────────────────────────────────────────────────────

def _wmic_usb_drives() -> list:
    """Return list of {device_id, model, index} for all USB-interface disk drives."""
    result = subprocess.run(
        ["wmic", "diskdrive",
         "where", "InterfaceType='USB'",
         "get", "DeviceID,Model,Index"],
        capture_output=True, text=True, timeout=8
    )
    drives = []
    lines = [l.strip() for l in result.stdout.strip().splitlines() if l.strip()]
    # Skip header line
    for line in lines[1:]:
        parts = line.rsplit(None, 2)
        if len(parts) >= 2:
            # Last token = Index (int), middle = Model, first = DeviceID
            # e.g. \\.\PHYSICALDRIVE1   Samsung T7 USB Device   1
            device_id = parts[0]
            model     = parts[1] if len(parts) >= 3 else ""
            idx       = parts[-1] if parts[-1].isdigit() else ""
            drives.append({"device_id": device_id, "model": model, "index": idx})
    return drives


def _wmic_logical_map() -> dict:
    """
    Map physical disk DeviceID → list of logical drive letters using wmic.
    Also maps "Disk #N" → letters as a secondary key.
    """
    result = subprocess.run(
        ["wmic", "logicaldisk", "get", "DeviceID,DriveType"],
        capture_output=True, text=True, timeout=8
    )
    # Drive types: 2=Removable, 3=Fixed, 4=Network, 5=CD
    # We want type 2 and 3 (some USB SSDs show as fixed)
    logical = {}

    # Use a more targeted wmic path association query
    try:
        assoc = subprocess.run(
            ["wmic", "path", "win32_logicaldisktopartition", "get",
             "antecedent,dependent"],
            capture_output=True, text=True, timeout=8
        )
        for line in assoc.stdout.strip().splitlines()[1:]:
            line = line.strip()
            if not line:
                continue
            # Antecedent: Win32_DiskPartition.DeviceID="Disk #1, Partition #0"
            # Dependent:  Win32_LogicalDisk.DeviceID="E:"
            try:
                ant, dep = line.split('",')
                disk_num = ant.split("Disk #")[1].split(",")[0].strip()
                letter   = dep.split('DeviceID="')[1].rstrip('"') + "\\"
                key = f"Disk #{disk_num}"
                logical.setdefault(key, []).append(letter)
            except Exception:
                continue
    except Exception:
        pass

    return logical


def _drive_entry(mount: str, model: str = "") -> dict | None:
    """Build a drive dict for the given mount point. Returns None if inaccessible."""
    try:
        usage = psutil.disk_usage(mount)
        # Find filesystem from psutil partitions
        fstype = ""
        for part in psutil.disk_partitions(all=True):
            if os.path.normpath(part.mountpoint) == os.path.normpath(mount):
                fstype = part.fstype
                break
        return {
            "device":     mount.rstrip("\\"),
            "mountpoint": mount,
            "fstype":     fstype or "UNKNOWN",
            "total_gb":   usage.total / (1024 ** 3),
            "free_gb":    usage.free  / (1024 ** 3),
            "model":      model or "External Drive",
        }
    except (PermissionError, FileNotFoundError):
        return None
