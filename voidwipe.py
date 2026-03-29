#!/usr/bin/env python3
"""
voidwipe — Cross-platform secure file deletion
Features:
  - Overwrite free disk space (multiple passes, varied patterns)
  - Secure deletion of files and directories
  - Gutmann / DoD / custom pass methods
  - Shadow Copies / Snapshots removal (requires admin)
  - Dry-run mode and read-back verification
  - Detailed process logging

WARNING: Primarily effective on HDDs.
On SSDs, the FTL/TRIM layer limits guarantees of physical overwrite.
On Copy-on-Write filesystems (btrfs, ZFS, APFS), overwrite does NOT
guarantee physical data erasure regardless of storage type.
"""

import os
import sys
import platform
import logging
import argparse
import subprocess
import shutil
from pathlib import Path
from datetime import datetime

VERSION = "1.1.0"


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


def get_filesystem_type(path: str) -> str:
    """Return the filesystem type string for the given path, or '' if unknown."""
    try:
        if SYSTEM == "Linux":
            result = subprocess.run(
                ["stat", "-f", "-c", "%T", path],
                capture_output=True, text=True, timeout=5
            )
            return result.stdout.strip().lower()
        elif SYSTEM == "Darwin":
            result = subprocess.run(
                ["diskutil", "info", path],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                if "File System Personality" in line:
                    return line.split(":")[-1].strip().lower()
    except Exception:
        pass
    return ""


def warn_if_cow(path: str):
    """Warn the user if the path resides on a Copy-on-Write filesystem."""
    cow_types = {"btrfs", "zfs", "apfs", "tmpfs", "overlay"}
    fs = get_filesystem_type(path)
    for cow in cow_types:
        if cow in fs:
            log.warning(
                f"  '{path}' is on a CoW filesystem ({fs}). "
                "Physical overwrite is NOT guaranteed even on HDDs."
            )
            return


# ─────────────────────────────────────────────
# OVERWRITE PATTERN GENERATORS
# ─────────────────────────────────────────────

def pattern_random(size: int) -> bytes:
    """Fully random bytes (os.urandom — cryptographic quality)."""
    return os.urandom(size)


def _make_fixed(byte_val: int):
    """Return a generator that fills with a single repeated byte value."""
    def gen(size: int) -> bytes:
        return bytes([byte_val]) * size
    gen.__name__ = f"0x{byte_val:02X}"
    gen._deterministic = True
    gen._byte_val = byte_val
    return gen


def _make_repeat(pattern: bytes):
    """Return a generator that tiles a multi-byte pattern."""
    def gen(size: int) -> bytes:
        return (pattern * (size // len(pattern) + 1))[:size]
    gen.__name__ = ":".join(f"{b:02x}" for b in pattern)
    gen._deterministic = True
    gen._pattern = pattern
    return gen


def _gutmann_sequence():
    """Build the 35-pass Gutmann overwrite sequence."""
    f = _make_fixed
    r = _make_repeat
    return [
        ("Random 1",   pattern_random),
        ("Random 2",   pattern_random),
        ("Random 3",   pattern_random),
        ("Random 4",   pattern_random),
        ("0x55",       f(0x55)),
        ("0xAA",       f(0xAA)),
        ("92:49:24",   r(bytes([0x92, 0x49, 0x24]))),
        ("49:24:92",   r(bytes([0x49, 0x24, 0x92]))),
        ("24:92:49",   r(bytes([0x24, 0x92, 0x49]))),
        ("0x00",       f(0x00)),
        ("0x11",       f(0x11)),
        ("0x22",       f(0x22)),
        ("0x33",       f(0x33)),
        ("0x44",       f(0x44)),
        ("0x55",       f(0x55)),
        ("0x66",       f(0x66)),
        ("0x77",       f(0x77)),
        ("0x88",       f(0x88)),
        ("0x99",       f(0x99)),
        ("0xAA",       f(0xAA)),
        ("0xBB",       f(0xBB)),
        ("0xCC",       f(0xCC)),
        ("0xDD",       f(0xDD)),
        ("0xEE",       f(0xEE)),
        ("0xFF",       f(0xFF)),
        ("92:49:24",   r(bytes([0x92, 0x49, 0x24]))),
        ("49:24:92",   r(bytes([0x49, 0x24, 0x92]))),
        ("24:92:49",   r(bytes([0x24, 0x92, 0x49]))),
        ("6d:b6:db",   r(bytes([0x6D, 0xB6, 0xDB]))),
        ("b6:db:6d",   r(bytes([0xB6, 0xDB, 0x6D]))),
        ("db:6d:b6",   r(bytes([0xDB, 0x6D, 0xB6]))),
        ("Random 32",  pattern_random),
        ("Random 33",  pattern_random),
        ("Random 34",  pattern_random),
        ("Random 35",  pattern_random),
    ]


# Pass sequences: method name → list of (label, generator)
PASS_METHODS = {
    "default": [
        ("Random 1",  pattern_random),
        ("0xFF",      _make_fixed(0xFF)),
        ("Random 2",  pattern_random),
        ("0x00",      _make_fixed(0x00)),
    ],
    "dod3": [
        ("0x00",      _make_fixed(0x00)),
        ("0xFF",      _make_fixed(0xFF)),
        ("Random",    pattern_random),
    ],
    "dod7": [
        ("0x00",      _make_fixed(0x00)),
        ("0xFF",      _make_fixed(0xFF)),
        ("Random 1",  pattern_random),
        ("0x96",      _make_fixed(0x96)),
        ("0x00",      _make_fixed(0x00)),
        ("0xFF",      _make_fixed(0xFF)),
        ("Random 2",  pattern_random),
    ],
    "gutmann": _gutmann_sequence(),
}

# Patterns cycled across free-space overwrite passes (0x00 → 0xFF → random → repeat)
_FREE_SPACE_PATTERN_CYCLE = [_make_fixed(0x00), _make_fixed(0xFF), pattern_random]


# ─────────────────────────────────────────────
# SECURE FILE DELETION
# ─────────────────────────────────────────────

CHUNK_SIZE = 1024 * 1024       # 1 MB per chunk
FREE_SPACE_RESERVE = 64 * 1024 * 1024  # Keep 64 MB free to avoid system instability


def _write_passes(f, file_size: int, sequence: list, verify: bool = False):
    """
    Execute the overwrite pass sequence on an open file descriptor.
    If verify=True, the last chunk of each deterministic pass is read back
    and compared against the expected bytes.
    """
    if file_size == 0:
        return  # nothing to overwrite

    show_progress = file_size >= 4 * 1024 * 1024  # only for files >= 4 MB

    for i, (label, generator) in enumerate(sequence, 1):
        is_random = generator is pattern_random
        log.info(f"  Pass {i}/{len(sequence)}: {label}")
        f.seek(0)
        written = 0
        last_chunk = None
        last_pct_milestone = 0

        while written < file_size:
            chunk_size = min(CHUNK_SIZE, file_size - written)
            data = generator(chunk_size)
            f.write(data)
            written += chunk_size

            if show_progress:
                pct = written * 100 // file_size
                milestone = (pct // 25) * 25
                if milestone > last_pct_milestone:
                    last_pct_milestone = milestone
                    log.info(f"    {milestone}%")

            if verify and not is_random:
                last_chunk = data

        f.flush()
        os.fsync(f.fileno())  # Force physical write to disk

        if verify and not is_random and last_chunk is not None:
            # Spot-check: read back the last chunk and compare
            f.seek(file_size - len(last_chunk))
            read_back = f.read(len(last_chunk))
            if read_back == last_chunk:
                log.info(f"    Verified pass {i} OK.")
            else:
                log.warning(f"    Verification FAILED for pass {i} ({label}) — data mismatch.")


def shred_file(filepath: str, sequence: list = None, dry_run: bool = False,
               verify: bool = False) -> bool:
    """
    Overwrites a file with multiple passes, renames it, then deletes it.
    Returns True on success.
    """
    path = Path(filepath)

    # Symlink check must come first — is_symlink() does not follow the link
    if path.is_symlink():
        log.warning(f"Skipping symlink (only the link would be affected, not the target): {filepath}")
        return False

    if not path.exists():
        log.error(f"File not found: {filepath}")
        return False

    if not path.is_file():
        log.error(f"Not a regular file: {filepath}")
        return False

    if sequence is None:
        sequence = PASS_METHODS["default"]

    file_size = path.stat().st_size
    log.info(f"Secure deletion: {filepath} ({file_size / 1024:.1f} KB, {len(sequence)} passes)")
    warn_if_cow(str(path.parent))

    if dry_run:
        log.info(f"  [DRY RUN] Would overwrite and delete: {filepath}")
        return True

    try:
        with open(filepath, "r+b") as f:
            _write_passes(f, file_size, sequence, verify=verify)

        # Rename before unlinking (makes name-based recovery harder)
        random_name = path.parent / ("_" + os.urandom(8).hex())
        path.rename(random_name)
        try:
            random_name.unlink()
        except Exception as e:
            log.error(f"  Data overwritten but failed to unlink '{random_name}': {e}")
            return False

        log.info(f"  Securely deleted: {filepath}")
        return True

    except PermissionError:
        log.error(f"  Permission denied: {filepath}")
        return False
    except Exception as e:
        log.error(f"  Unexpected error: {e}")
        return False


def shred_dir(dirpath: str, sequence: list = None, dry_run: bool = False,
              verify: bool = False) -> bool:
    """
    Recursively shreds all files inside a directory, then removes the empty tree.
    Symlinks are unlinked without following them.
    Returns True if all operations succeeded.
    """
    root = Path(dirpath)
    if not root.exists():
        log.error(f"Directory not found: {dirpath}")
        return False
    if not root.is_dir():
        log.error(f"Not a directory: {dirpath}")
        return False

    files = sorted(p for p in root.rglob("*") if p.is_file() and not p.is_symlink())
    links = sorted(p for p in root.rglob("*") if p.is_symlink())
    log.info(f"Recursively shredding: {dirpath} ({len(files)} file(s), {len(links)} symlink(s))")
    warn_if_cow(dirpath)

    if dry_run:
        for f in files:
            log.info(f"  [DRY RUN] Would shred: {f}")
        for s in links:
            log.info(f"  [DRY RUN] Would unlink symlink: {s}")
        log.info(f"  [DRY RUN] Would remove directory tree: {dirpath}")
        return True

    all_ok = True
    for f in files:
        if not shred_file(str(f), sequence=sequence, verify=verify):
            all_ok = False

    for s in links:
        try:
            s.unlink()
        except Exception as e:
            log.warning(f"  Could not remove symlink {s}: {e}")

    if all_ok:
        try:
            shutil.rmtree(dirpath)
            log.info(f"  Directory removed: {dirpath}")
        except Exception as e:
            log.error(f"  Could not remove directory tree: {e}")
            all_ok = False

    return all_ok


# ─────────────────────────────────────────────
# FREE SPACE OVERWRITE
# ─────────────────────────────────────────────

def _cipher_wipe_windows(directory: str):
    """
    Use Windows' built-in 'cipher /w:' to wipe free space on NTFS.
    Returns True on success, False on failure, None if cipher is unavailable.
    """
    log.info("  Using cipher /w: (NTFS native free-space wipe)...")
    try:
        result = subprocess.run(
            ["cipher", f"/w:{directory}"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            log.info("  cipher /w: completed successfully.")
            return True
        log.warning(f"  cipher /w: returned code {result.returncode}: {result.stderr.strip()}")
        return False
    except FileNotFoundError:
        log.warning("  cipher not found; falling back to temp-file method.")
        return None


def overwrite_free_space(directory: str, passes: int = 2, dry_run: bool = False) -> bool:
    """
    Overwrites free blocks on the filesystem by filling then removing temp files.
    Each pass cycles through a different data pattern (0x00, 0xFF, random).
    On Windows NTFS, delegates to 'cipher /w:' when available.
    """
    target = Path(directory)
    if not target.exists():
        log.error(f"Invalid directory: {directory}")
        return False

    log.info(f"Overwriting free space in: {directory} ({passes} pass(es))")
    log.warning("NOTE: On SSDs, this does not guarantee physical overwrite.")
    warn_if_cow(directory)

    if dry_run:
        log.info(f"  [DRY RUN] Would overwrite free space in: {directory}")
        return True

    if SYSTEM == "Windows":
        result = _cipher_wipe_windows(directory)
        if result is True:
            return True
        # result is None (not found) or False (failed) — fall through to temp-file method

    for p in range(1, passes + 1):
        gen = _FREE_SPACE_PATTERN_CYCLE[(p - 1) % len(_FREE_SPACE_PATTERN_CYCLE)]
        label = getattr(gen, '__name__', 'Random')
        log.info(f"  Pass {p}/{passes} — pattern: {label}")
        tmp_path = target / f"_freespace_{p}_{os.urandom(4).hex()}.tmp"
        total_written = 0

        try:
            with open(tmp_path, "wb") as f:
                while True:
                    free = shutil.disk_usage(directory).free
                    if free <= FREE_SPACE_RESERVE:
                        break
                    chunk = min(CHUNK_SIZE, free - FREE_SPACE_RESERVE)
                    f.write(gen(chunk))
                    f.flush()
                    os.fsync(f.fileno())
                    total_written += chunk

            log.info(f"  Written {total_written / (1024**2):.1f} MB.")
        except OSError as e:
            if e.errno == 28:  # No space left on device — expected
                log.info(f"  Disk full (expected). Pass {p} complete.")
            else:
                log.error(f"  Write error: {e}")
        finally:
            if tmp_path.exists():
                # Zero the temp file before unlinking to limit raw block recovery
                try:
                    size = tmp_path.stat().st_size
                    with open(tmp_path, "r+b") as f:
                        f.write(b'\x00' * size)
                        f.flush()
                        os.fsync(f.fileno())
                except Exception:
                    pass
                tmp_path.unlink()

    log.info("  Free space overwrite complete.")
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
            log.info("  Shadow Copies deleted successfully.")
        else:
            log.warning(f"  vssadmin returned code {result.returncode}: {result.stderr.strip()}")
        return result.returncode == 0
    except FileNotFoundError:
        log.error("  vssadmin not found.")
        return False


def delete_snapshots_linux() -> bool:
    """Attempt to delete LVM snapshots on Linux (requires root)."""
    log.info("Looking for LVM snapshots on Linux...")
    try:
        result = subprocess.run(
            ["lvs", "--noheadings", "-o", "vg_name,lv_name,lv_attr"],
            capture_output=True, text=True
        )
        snapshots = []
        for line in result.stdout.splitlines():
            parts = line.strip().split()
            if len(parts) >= 3 and parts[2].startswith("s"):
                snapshots.append(f"{parts[0]}/{parts[1]}")

        if not snapshots:
            log.info("  No LVM snapshots found.")
            return True

        for snap in snapshots:
            log.info(f"  Deleting snapshot: {snap}")
            subprocess.run(["lvremove", "-f", snap], check=True)
        log.info("  LVM snapshots deleted.")
        return True
    except FileNotFoundError:
        log.info("  LVM not available on this system.")
        return True
    except subprocess.CalledProcessError as e:
        log.error(f"  Error deleting snapshot: {e}")
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
        log.info("  APFS snapshots deleted.")
        return True
    except FileNotFoundError:
        log.error("  tmutil not found.")
        return False
    except subprocess.CalledProcessError as e:
        log.error(f"  Error: {e}")
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
Pass methods:
  default   4 passes: random, 0xFF, random, 0x00
  dod3      DoD 5220.22-M 3-pass: 0x00, 0xFF, random
  dod7      DoD 5220.22-M 7-pass
  gutmann   Gutmann 35-pass

Examples:
  # Securely delete specific files
  voidwipe --files secret.txt report.pdf

  # Securely delete an entire directory
  voidwipe --dir /home/user/sensitive/

  # Overwrite free space on a partition
  voidwipe --freespace /home

  # Full run with DoD 7-pass, verification, and logging
  voidwipe --files secret.txt --method dod7 --verify --log voidwipe.log

  # Dry run to preview all actions without making changes
  voidwipe --files secret.txt --freespace /home --dry-run

WARNING: Physical overwrite cannot be guaranteed on SSDs or CoW filesystems (btrfs, ZFS, APFS).
        """
    )
    parser.add_argument("--version", action="version", version=f"voidwipe {VERSION}")
    parser.add_argument(
        "--files", nargs="+", metavar="FILE",
        help="Files to securely delete"
    )
    parser.add_argument(
        "--dir", metavar="DIRECTORY",
        help="Directory to recursively shred (all files inside)"
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
        "--method", choices=list(PASS_METHODS.keys()), default="default",
        help="Pass method for file deletion (default: default)"
    )
    parser.add_argument(
        "--passes", type=int, default=None,
        help="Override number of passes from the selected method (min: 1); "
             "if greater than the method's pass count, extra random passes are appended"
    )
    parser.add_argument(
        "--freespace-passes", type=int, default=2,
        help="Number of passes for free space overwrite (default: 2)"
    )
    parser.add_argument(
        "--verify", action="store_true",
        help="Read-back verify each deterministic overwrite pass"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Preview all actions without making any changes"
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
    log.info(f"System: {SYSTEM} | Admin: {is_admin()} | Version: {VERSION}")
    log.info(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    if args.dry_run:
        log.info("[DRY RUN] No changes will be made.")
    log.info("=" * 60)

    if not is_admin():
        log.warning("Not running as administrator/root. Some features may fail.")

    if not any([args.files, args.dir, args.freespace, args.snapshots]):
        log.error("No action specified. Use --help to see available options.")
        sys.exit(1)

    # Build the pass sequence
    sequence = list(PASS_METHODS[args.method])
    if args.passes is not None:
        if args.passes < 1:
            log.error("--passes must be at least 1.")
            sys.exit(1)
        if args.passes <= len(sequence):
            sequence = sequence[:args.passes]
        else:
            extra = args.passes - len(sequence)
            for n in range(1, extra + 1):
                sequence.append((f"Random (extra {n})", pattern_random))

    log.info(f"Pass method: {args.method} | Passes: {len(sequence)} | Verify: {args.verify}")

    results = []

    # 1. Delete snapshots first (before touching the disk)
    if args.snapshots:
        log.info("\n-- Snapshot Removal -----------------------------------------------")
        results.append(("Snapshots", delete_snapshots()))

    # 2. Secure file deletion
    if args.files:
        log.info("\n-- Secure File Deletion -------------------------------------------")
        for f in args.files:
            ok = shred_file(f, sequence=sequence, dry_run=args.dry_run, verify=args.verify)
            results.append((f"File: {f}", ok))

    # 3. Secure directory deletion
    if args.dir:
        log.info("\n-- Secure Directory Deletion --------------------------------------")
        ok = shred_dir(args.dir, sequence=sequence, dry_run=args.dry_run, verify=args.verify)
        results.append((f"Dir: {args.dir}", ok))

    # 4. Free space overwrite
    if args.freespace:
        log.info("\n-- Free Space Overwrite -------------------------------------------")
        ok = overwrite_free_space(args.freespace, passes=args.freespace_passes, dry_run=args.dry_run)
        results.append(("Free space", ok))

    # Final summary
    log.info("\n-- Summary --------------------------------------------------------")
    all_ok = True
    for label, ok in results:
        status = "OK  " if ok else "FAIL"
        log.info(f"  [{status}]  {label}")
        if not ok:
            all_ok = False

    log.info("=" * 60)
    log.info("Session complete." + (" With errors." if not all_ok else " No errors."))
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
