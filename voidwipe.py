#!/usr/bin/env python3
"""
voidwipe — Cross-platform secure file deletion
Features:
  - Overwrite free disk space
  - Secure deletion of specific files (multiple passes)
  - Shadow Copies / Snapshots removal (requires admin)
  - Detailed process logging

WARNING: Primarily effective on HDDs.
On SSDs, the FTL/TRIM layer limits guarantees of physical overwrite.
"""

import os
import sys
import platform
import random
import struct
import logging
import argparse
import subprocess
import shutil
import tempfile
from pathlib import Path
from datetime import datetime


# ─────────────────────────────────────────────
# LOGGING SETUP
# ─────────────────────────────────────────────

def setup_logging(log_file: str = None):
    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=handlers,
    )

log = logging.getLogger("voidwipe")


# ─────────────────────────────────────────────
# PLATFORM DETECTION
# ─────────────────────────────────────────────

SYSTEM = platform.system()  # 'Windows', 'Linux', 'Darwin'

def is_admin() -> bool:
    """Check whether the script is running with administrator/root privileges."""
    try:
        if SYSTEM == "Windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False


# ─────────────────────────────────────────────
# OVERWRITE PATTERN GENERATORS
# ─────────────────────────────────────────────

def pattern_random(size: int) -> bytes:
    """Fully random bytes (os.urandom — cryptographic quality)."""
    return os.urandom(size)

def pattern_zeros(size: int) -> bytes:
    return b'\x00' * size

def pattern_ones(size: int) -> bytes:
    return b'\xff' * size

def pattern_alternating(size: int) -> bytes:
    return bytes([0xAA, 0x55] * (size // 2 + 1))[:size]

# Pass sequence: (label, generator function)
PASS_SEQUENCE = [
    ("Random 1",      pattern_random),
    ("Ones (0xFF)",   pattern_ones),
    ("Random 2",      pattern_random),
    ("Zeros (0x00)",  pattern_zeros),
]


# ─────────────────────────────────────────────
# SECURE FILE DELETION
# ─────────────────────────────────────────────

CHUNK_SIZE = 1024 * 1024  # 1 MB per chunk

def shred_file(filepath: str, passes: int = None) -> bool:
    """
    Overwrites a file with multiple passes, then deletes it.
    Returns True on success.
    """
    path = Path(filepath)

    if not path.exists():
        log.error(f"File not found: {filepath}")
        return False

    if not path.is_file():
        log.error(f"Not a regular file: {filepath}")
        return False

    file_size = path.stat().st_size
    log.info(f"Starting secure deletion: {filepath} ({file_size / 1024:.1f} KB)")

    sequence = PASS_SEQUENCE[:passes] if passes else PASS_SEQUENCE

    try:
        with open(filepath, "r+b") as f:
            for i, (label, generator) in enumerate(sequence, 1):
                log.info(f"  Pass {i}/{len(sequence)}: {label}")
                f.seek(0)
                written = 0
                while written < file_size:
                    chunk = min(CHUNK_SIZE, file_size - written)
                    f.write(generator(chunk))
                    written += chunk
                f.flush()
                os.fsync(f.fileno())  # Force physical write to disk

        # Rename before unlinking (makes name-based recovery harder)
        random_name = path.parent / ("_" + os.urandom(8).hex())
        path.rename(random_name)
        random_name.unlink()

        log.info(f"  ✓ File securely deleted: {filepath}")
        return True

    except PermissionError:
        log.error(f"  ✗ Permission denied: {filepath}")
        return False
    except Exception as e:
        log.error(f"  ✗ Unexpected error: {e}")
        return False


# ─────────────────────────────────────────────
# FREE SPACE OVERWRITE
# ─────────────────────────────────────────────

def overwrite_free_space(directory: str, passes: int = 2) -> bool:
    """
    Fills the free space of a partition by writing temporary files
    with random data, then deletes them.
    This overwrites blocks marked as free in the filesystem.
    """
    target = Path(directory)
    if not target.exists():
        log.error(f"Invalid directory: {directory}")
        return False

    log.info(f"Overwriting free space in: {directory}")
    log.warning("NOTE: On SSDs, this operation does not guarantee physical overwrite.")

    for p in range(1, passes + 1):
        log.info(f"  Pass {p}/{passes} — filling free space...")
        tmp_path = target / f"_freespace_pass{p}_{os.urandom(4).hex()}.tmp"
        total_written = 0

        try:
            with open(tmp_path, "wb") as f:
                while True:
                    free = shutil.disk_usage(directory).free
                    if free < CHUNK_SIZE:
                        # Reserve ~50 MB to prevent system crash
                        if free < 50 * 1024 * 1024:
                            break
                    chunk = min(CHUNK_SIZE, free - 20 * 1024 * 1024)
                    if chunk <= 0:
                        break
                    f.write(os.urandom(chunk))
                    f.flush()
                    os.fsync(f.fileno())
                    total_written += chunk

            log.info(f"  Written {total_written / (1024**2):.1f} MB. Removing temp file...")
        except OSError as e:
            if e.errno == 28:  # No space left on device — expected
                log.info(f"  Disk full (expected). Removing temp file...")
            else:
                log.error(f"  Write error: {e}")
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    log.info("  ✓ Free space overwrite complete.")
    return True


# ─────────────────────────────────────────────
# SHADOW COPIES / SNAPSHOTS REMOVAL
# ─────────────────────────────────────────────

def delete_shadow_copies_windows() -> bool:
    """Delete all Volume Shadow Copies on Windows (requires admin)."""
    log.info("Deleting Volume Shadow Copies (Windows)...")
    try:
        result = subprocess.run(
            ["vssadmin", "delete", "shadows", "/all", "/quiet"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            log.info("  ✓ Shadow Copies deleted successfully.")
        else:
            log.warning(f"  vssadmin returned code {result.returncode}: {result.stderr.strip()}")
        return result.returncode == 0
    except FileNotFoundError:
        log.error("  ✗ vssadmin not found.")
        return False

def delete_snapshots_linux() -> bool:
    """Attempt to delete LVM snapshots on Linux (requires root)."""
    log.info("Looking for LVM snapshots on Linux...")
    try:
        result = subprocess.run(
            ["lvs", "--noheadings", "-o", "lv_name,lv_attr"],
            capture_output=True, text=True
        )
        snapshots = [
            line.split()[0].strip()
            for line in result.stdout.splitlines()
            if len(line.split()) >= 2 and line.split()[1].startswith("s")
        ]
        if not snapshots:
            log.info("  No LVM snapshots found.")
            return True
        for snap in snapshots:
            log.info(f"  Deleting snapshot: {snap}")
            subprocess.run(["lvremove", "-f", snap], check=True)
        log.info("  ✓ LVM snapshots deleted.")
        return True
    except FileNotFoundError:
        log.info("  LVM not available on this system.")
        return True
    except subprocess.CalledProcessError as e:
        log.error(f"  ✗ Error deleting snapshot: {e}")
        return False

def delete_snapshots_macos() -> bool:
    """Delete local APFS snapshots on macOS (requires root)."""
    log.info("Looking for local APFS snapshots (macOS)...")
    try:
        result = subprocess.run(
            ["tmutil", "listlocalsnapshots", "/"],
            capture_output=True, text=True
        )
        snapshots = [
            line.strip()
            for line in result.stdout.splitlines()
            if line.strip().startswith("com.apple")
        ]
        if not snapshots:
            log.info("  No local APFS snapshots found.")
            return True
        for snap in snapshots:
            date = snap.replace("com.apple.TimeMachine.", "").replace(".local", "")
            log.info(f"  Deleting snapshot: {snap}")
            subprocess.run(["tmutil", "deletelocalsnapshots", date], check=True)
        log.info("  ✓ APFS snapshots deleted.")
        return True
    except FileNotFoundError:
        log.error("  ✗ tmutil not found.")
        return False
    except subprocess.CalledProcessError as e:
        log.error(f"  ✗ Error: {e}")
        return False

def delete_snapshots() -> bool:
    """Cross-platform dispatcher for snapshot removal."""
    if SYSTEM == "Windows":
        return delete_shadow_copies_windows()
    elif SYSTEM == "Linux":
        return delete_snapshots_linux()
    elif SYSTEM == "Darwin":
        return delete_snapshots_macos()
    else:
        log.warning(f"Unsupported OS for snapshot removal: {SYSTEM}")
        return False


# ─────────────────────────────────────────────
# MAIN / CLI
# ─────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="voidwipe — Cross-platform secure file deletion",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Securely delete specific files
  voidwipe --files secret.txt report.pdf

  # Overwrite free space on a partition
  voidwipe --freespace /home

  # Full run with logging
  voidwipe --files secret.txt --freespace /home --snapshots --log voidwipe.log

WARNING: Physical overwrite cannot be guaranteed on SSDs.
        """
    )
    parser.add_argument(
        "--files", nargs="+", metavar="FILE",
        help="Files to securely delete"
    )
    parser.add_argument(
        "--freespace", metavar="DIRECTORY",
        help="Directory whose partition free space will be overwritten"
    )
    parser.add_argument(
        "--snapshots", action="store_true",
        help="Delete system Shadow Copies / Snapshots (requires admin)"
    )
    parser.add_argument(
        "--passes", type=int, default=None,
        help="Number of passes for file deletion (default: 4)"
    )
    parser.add_argument(
        "--freespace-passes", type=int, default=2,
        help="Number of passes for free space overwrite (default: 2)"
    )
    parser.add_argument(
        "--log", metavar="LOG_FILE",
        help="Save detailed log to a file"
    )
    return parser.parse_args()


def main():
    args = parse_args()
    setup_logging(args.log)

    log.info("=" * 60)
    log.info("voidwipe — Secure deletion session started")
    log.info(f"System: {SYSTEM} | Admin: {is_admin()}")
    log.info(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log.info("=" * 60)

    if not is_admin():
        log.warning("⚠ Not running as administrator/root.")
        log.warning("  Some features (snapshots, certain files) may fail.")

    if not any([args.files, args.freespace, args.snapshots]):
        log.error("No action specified. Use --help to see available options.")
        sys.exit(1)

    results = []

    # 1. Delete snapshots first (before touching the disk)
    if args.snapshots:
        log.info("\n── Snapshot Removal ──────────────────────────────────────")
        results.append(("Snapshots", delete_snapshots()))

    # 2. Secure file deletion
    if args.files:
        log.info("\n── Secure File Deletion ──────────────────────────────────")
        for f in args.files:
            ok = shred_file(f, passes=args.passes)
            results.append((f"File: {f}", ok))

    # 3. Free space overwrite
    if args.freespace:
        log.info("\n── Free Space Overwrite ──────────────────────────────────")
        ok = overwrite_free_space(args.freespace, passes=args.freespace_passes)
        results.append(("Free space", ok))

    # Final summary
    log.info("\n── Summary ───────────────────────────────────────────────")
    all_ok = True
    for label, ok in results:
        status = "✓ OK" if ok else "✗ FAILED"
        log.info(f"  {status}  {label}")
        if not ok:
            all_ok = False

    log.info("=" * 60)
    log.info("Session complete." + (" With errors." if not all_ok else " No errors."))
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
