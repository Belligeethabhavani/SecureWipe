import os
import hashlib
import uuid
import shutil


# ── Wipe algorithm definitions ─────────
# Each algorithm is a list of passes.
# "random"  → overwrite with cryptographically secure random bytes
# "zero"    → overwrite with 0x00
# "ones"    → overwrite with 0xFF
# Gutmann's 35 patterns are approximated with the key random/alternating passes.

ALGORITHMS = {
    "NIST Clear (1-pass)": ["zero"],
    "DoD 5220.22-M (3-pass)": ["random", "ones", "zero"],
    "Gutmann (7-pass)": ["random", "zero", "ones", "random", "zero", "ones", "random"],
}


def sha256_of_file(path):
    """Compute SHA-256 hash of a file before wiping it."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(64 * 1024):
            h.update(chunk)
    return h.hexdigest()


def _write_pass(f, size, pattern, pass_num, total_passes, progress_cb):
    """Write a single pass over the file. pattern is 'random', 'zero', or 'ones'."""
    chunk_size = 1024 * 1024  # 1 MB chunks
    written = 0
    f.seek(0)

    while written < size:
        to_write = min(chunk_size, size - written)

        if pattern == "random":
            data = os.urandom(to_write)
        elif pattern == "ones":
            data = b"\xff" * to_write
        else:  # zero
            data = b"\x00" * to_write

        f.write(data)
        written += to_write

        # Report progress: overall percent across all passes
        pass_progress = written / size
        overall = (pass_num - 1 + pass_progress) / total_passes
        if progress_cb:
            progress_cb(pass_num, total_passes, int(overall * 100))

    # Force OS to flush to physical storage — critical for NIST compliance
    f.flush()
    os.fsync(f.fileno())


def wipe_file(path, algorithm_name="DoD 5220.22-M (3-pass)", progress_cb=None):
   
    passes = ALGORITHMS.get(algorithm_name, ALGORITHMS["DoD 5220.22-M (3-pass)"])
    total = len(passes)

    # Step 1: hash before wipe (for certificate/proof)
    original_hash = sha256_of_file(path)

    size = os.path.getsize(path)

    if size > 0:
        with open(path, "r+b") as f:
            for i, pattern in enumerate(passes, start=1):
                _write_pass(f, size, pattern, i, total, progress_cb)

            # Step 3: truncate to zero before rename/delete
            f.truncate(0)
            f.flush()
            os.fsync(f.fileno())

    # Step 4: rename to random UUID (removes original name from directory entry)
    parent = os.path.dirname(os.path.abspath(path))
    anon_path = os.path.join(parent, str(uuid.uuid4()))
    os.rename(path, anon_path)

    # Step 5: delete
    os.remove(anon_path)

    return original_hash


def wipe_files(paths, algorithm_name="DoD 5220.22-M (3-pass)", progress_cb=None):
    
    results = {}
    for path in paths:
        if os.path.isfile(path):
            h = wipe_file(path, algorithm_name, progress_cb)
            results[path] = h
    return results


def wipe_directory(dir_path, algorithm_name="DoD 5220.22-M (3-pass)", progress_cb=None):
    
    results = {}

    # Walk bottom-up so we wipe files before trying to remove their parent dirs
    for root, dirs, files in os.walk(dir_path, topdown=False):
        for fname in files:
            fpath = os.path.join(root, fname)
            h = wipe_file(fpath, algorithm_name, progress_cb)
            results[fpath] = h

        # Remove now-empty directory
        try:
            os.rmdir(root)
        except OSError:
            pass  # Not empty (unexpected), leave it

    return results