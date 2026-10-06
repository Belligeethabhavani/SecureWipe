import json
import hashlib
from datetime import datetime

LOG_FILE = "securewipe_audit.log"


def _last_hash():
    """Read the hash of the last log entry to chain entries together."""
    try:
        with open(LOG_FILE, "r") as f:
            lines = [l.strip() for l in f.readlines() if l.strip()]
        if lines:
            return hashlib.sha256(lines[-1].encode()).hexdigest()
    except FileNotFoundError:
        pass
    return "GENESIS"


def log_event(event, detail="", level="INFO"):
    """
    Write a structured JSON log entry.

    Each entry chains to the previous one via 'prev_hash',
    making the log tamper-evident (like a mini blockchain).

    Args:
        event:  Short event name, e.g. "WIPE_STARTED"
        detail: Extra context string
        level:  "INFO", "WARNING", or "ERROR"
    """
    entry = {
        "timestamp": datetime.now().isoformat(),
        "level": level,
        "event": event,
        "detail": detail,
        "prev_hash": _last_hash(),
    }
    line = json.dumps(entry)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")