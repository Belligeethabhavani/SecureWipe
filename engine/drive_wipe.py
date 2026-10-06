

import os
import ctypes
import ctypes.wintypes
import subprocess

from engine.file_wipe import ALGORITHMS

# 1MB chunks for all write operations
CHUNK = 1024 * 1024

# ── Windows API helpers ───────────────────────────────────────────────────────

GENERIC_WRITE        = 0x40000000
GENERIC_READ         = 0x80000000
FILE_SHARE_READ      = 0x00000001
FILE_SHARE_WRITE     = 0x00000002
OPEN_EXISTING        = 3
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

# IOCTL to get drive length
IOCTL_DISK_GET_LENGTH_INFO = 0x0007405C


def _drive_size_bytes(handle) -> int:
    """Return the total byte size of the drive via DeviceIoControl."""
    length = ctypes.c_int64(0)
    returned = ctypes.c_ulong(0)
    ok = ctypes.windll.kernel32.DeviceIoControl(
        handle,
        IOCTL_DISK_GET_LENGTH_INFO,
        None, 0,
        ctypes.byref(length), ctypes.sizeof(length),
        ctypes.byref(returned),
        None,
    )
    if not ok:
        raise OSError("DeviceIoControl failed — cannot determine drive size")
    return length.value


def _write_chunk(handle, data: bytes) -> int:
    """Write bytes to the open handle. Returns bytes written."""
    buf         = ctypes.create_string_buffer(data)
    bytes_written = ctypes.c_ulong(0)
    ctypes.windll.kernel32.WriteFile(
        handle, buf, len(data), ctypes.byref(bytes_written), None
    )
    return bytes_written.value


def _seek_to_start(handle):
    """Seek to byte 0 of the handle."""
    ctypes.windll.kernel32.SetFilePointerEx(
        handle, ctypes.c_longlong(0), None, 0  # FILE_BEGIN
    )


# ── Public API ────────────────────────────────────────────────────────────────

def logical_to_physical_drive(mount_point: str) -> str:
    """
    Map a logical drive letter (e.g. 'E:\\') to its physical drive path
    (e.g. '\\\\.\\PHYSICALDRIVE1').

    Uses IOCTL_STORAGE_GET_DEVICE_NUMBER via wmic as a fallback.
    """
    drive_letter = mount_point.rstrip("\\").rstrip("/").upper()
    if not drive_letter.endswith(":"):
        drive_letter += ":"

    # Method: wmic path win32_logicaldisktopartition
    try:
        r = subprocess.run(
            ["wmic", "path", "win32_logicaldisktopartition",
             "where", f'Dependent like "%{drive_letter}%"',
             "get", "Antecedent"],
            capture_output=True, text=True, timeout=8
        )
        for line in r.stdout.splitlines():
            if "Disk #" in line:
                disk_num = line.split("Disk #")[1].split(",")[0].strip()
                return f"\\\\.\\PHYSICALDRIVE{disk_num}"
    except Exception:
        pass

    # Fallback via IOCTL_STORAGE_GET_DEVICE_NUMBER
    try:
        vol_path = f"\\\\.\\{drive_letter}"
        handle = ctypes.windll.kernel32.CreateFileW(
            vol_path,
            0,  # no read/write, just metadata
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None, OPEN_EXISTING, 0, None,
        )
        if handle != INVALID_HANDLE_VALUE:
            class _DevNum(ctypes.Structure):
                _fields_ = [("DeviceType", ctypes.c_ulong),
                             ("DeviceNumber", ctypes.c_ulong),
                             ("PartitionNumber", ctypes.c_ulong)]
            dn       = _DevNum()
            returned = ctypes.c_ulong(0)
            IOCTL_STORAGE_GET_DEVICE_NUMBER = 0x2D1080
            ctypes.windll.kernel32.DeviceIoControl(
                handle, IOCTL_STORAGE_GET_DEVICE_NUMBER,
                None, 0,
                ctypes.byref(dn), ctypes.sizeof(dn),
                ctypes.byref(returned), None,
            )
            ctypes.windll.kernel32.CloseHandle(handle)
            return f"\\\\.\\PHYSICALDRIVE{dn.DeviceNumber}"
    except Exception:
        pass

    raise RuntimeError(
        f"Cannot map {mount_point} to a physical drive.\n"
        "Ensure you are running as Administrator."
    )


def raw_wipe_physical_drive(
    physical_path: str,
    algorithm: str,
    passes: int,
    progress_cb=None,
) -> dict:
   
    patterns = ALGORITHMS.get(algorithm, ["zero"])

    # ── Open the physical drive ───────────────────────────────────────────────
    handle = ctypes.windll.kernel32.CreateFileW(
        physical_path,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None, OPEN_EXISTING, 0, None,
    )
    if handle == INVALID_HANDLE_VALUE:
        err = ctypes.windll.kernel32.GetLastError()
        raise PermissionError(
            f"Cannot open {physical_path} (error {err}).\n"
            "Please run SecureWipe as Administrator for raw drive wipes."
        )

    try:
        total_bytes = _drive_size_bytes(handle)
        total_gb    = total_bytes / (1024 ** 3)

        report_every = CHUNK * 4  # report progress every 4 MB

        for pass_idx, pattern in enumerate(patterns[:passes]):
            _seek_to_start(handle)
            written = 0
            since_last_report = 0

            while written < total_bytes:
                remaining    = total_bytes - written
                current_size = min(CHUNK, remaining)

                if pattern == "random":
                    data = os.urandom(current_size)
                elif pattern == "ones":
                    data = b"\xff" * current_size
                else:  # zero
                    data = b"\x00" * current_size

                bw = _write_chunk(handle, data)
                if bw == 0:
                    break  # write error — stop pass

                written        += bw
                since_last_report += bw

                if progress_cb and since_last_report >= report_every:
                    progress_cb(pass_idx, passes, written, total_bytes)
                    since_last_report = 0

            # Final progress report for this pass
            if progress_cb:
                progress_cb(pass_idx, passes, total_bytes, total_bytes)

    finally:
        ctypes.windll.kernel32.CloseHandle(handle)

    return {
        "physical_drive": physical_path,
        "total_gb":       round(total_gb, 2),
        "algorithm":      algorithm,
        "passes":         passes,
        "method":         "Raw sector overwrite (\\.\PHYSICALDRIVEn)",
    }


def is_admin() -> bool:
    """Return True if the current process has Administrator privileges."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False
