#!/usr/bin/env python3
"""
voidwipe — Cross-platform secure file deletion
Features:
  - Overwrite free disk space (multiple passes, varied patterns)
  - Secure deletion of files and directories
  - Gutmann / DoD / custom pass methods
  - Shadow Copies / Snapshots removal (requires admin)
  - SSD-aware: automatic storage detection, TRIM, ATA Secure Erase,
    NVMe Sanitize, LUKS crypto-erase
  - Dry-run mode and read-back verification
  - Detailed process logging

On SSDs, multi-pass overwrite is BEST-EFFORT only.
FTL wear-leveling and over-provisioning may retain data beyond OS reach.
On Copy-on-Write filesystems (btrfs, ZFS, APFS), overwrite does NOT
guarantee physical data erasure regardless of storage type.
"""

import os
import sys
import re
import time
import json
import fnmatch
import platform
import logging
import argparse
import subprocess
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime

VERSION = "1.2.0"


# ─────────────────────────────────────────────
# LOGGING SETUP
# ─────────────────────────────────────────────

def setup_logging(log_file: str = None, quiet: bool = False, json_mode: bool = False):
    # Suppress stdout INFO when --json is active so JSON output is not polluted.
    stream_level = logging.WARNING if (quiet or json_mode) else logging.DEBUG
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setLevel(stream_level)
    handlers = [stream_handler]
    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        handlers.append(file_handler)
    logging.basicConfig(
        level=logging.DEBUG,
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
# STORAGE DETECTION
# ─────────────────────────────────────────────

@dataclass
class StorageInfo:
    path: str
    device: str = ""         # e.g. /dev/sda1
    base_device: str = ""    # e.g. /dev/sda  (no partition suffix)
    mount_point: str = ""    # e.g. /home
    is_ssd: bool = None      # True/False/None (None = unknown)
    is_nvme: bool = False
    is_encrypted: bool = False

    def type_label(self) -> str:
        if self.is_nvme:
            return "NVMe SSD"
        if self.is_ssd is True:
            return "SSD"
        if self.is_ssd is False:
            return "HDD"
        return "unknown"


def _df_info(path: str):
    """Return (device, mount_point) via 'df -P', or ('', '') on failure."""
    try:
        result = subprocess.run(
            ["df", "-P", path], capture_output=True, text=True, timeout=5
        )
        lines = result.stdout.strip().splitlines()
        if len(lines) >= 2:
            parts = lines[1].split()
            return parts[0], parts[-1]
    except Exception:
        pass
    return "", ""


def _base_device(device: str) -> str:
    """Strip partition suffix to get the bare block device name."""
    # /dev/nvme0n1p1 → /dev/nvme0n1
    m = re.match(r"(/dev/nvme\d+n\d+)p\d+$", device)
    if m:
        return m.group(1)
    # /dev/sda1 → /dev/sda, /dev/vda2 → /dev/vda
    m = re.match(r"(/dev/[a-z]+)\d+$", device)
    if m:
        return m.group(1)
    return device


def _is_ssd_linux(base_device: str):
    """Read /sys/block/.../queue/rotational: '0' → SSD, '1' → HDD, None → unknown."""
    name = os.path.basename(base_device)
    rotational = Path(f"/sys/block/{name}/queue/rotational")
    try:
        return rotational.read_text().strip() == "0"
    except OSError:
        return None


def _is_ssd_macos(device: str):
    """Use 'diskutil info' to detect SSD on macOS."""
    try:
        result = subprocess.run(
            ["diskutil", "info", device],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            if "Solid State" in line:
                return "yes" in line.lower()
    except Exception:
        pass
    return None


def _is_ssd_windows():
    """Use PowerShell Get-PhysicalDisk to detect SSD on Windows (approximate)."""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-PhysicalDisk | Select-Object -ExpandProperty MediaType"],
            capture_output=True, text=True, timeout=10
        )
        types = result.stdout.lower()
        if "ssd" in types:
            return True
        if "hdd" in types or "unspecified" not in types:
            return False
    except Exception:
        pass
    return None


def _is_encrypted_linux(device: str) -> bool:
    """Check if the device is a LUKS container or dm-crypt device."""
    try:
        r = subprocess.run(
            ["cryptsetup", "isLuks", device],
            capture_output=True, timeout=5
        )
        if r.returncode == 0:
            return True
        # Also check if lsblk shows a 'crypt' type in the device stack
        r2 = subprocess.run(
            ["lsblk", "-sno", "TYPE", device],
            capture_output=True, text=True, timeout=5
        )
        return "crypt" in r2.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def detect_storage(path: str) -> StorageInfo:
    """
    Inspect the block device backing the given path.
    Returns a StorageInfo with device type, SSD flag, and encryption status.
    """
    info = StorageInfo(path=path)

    if SYSTEM in ("Linux", "Darwin"):
        device, mount = _df_info(path)
        info.device = device
        info.mount_point = mount
        info.base_device = _base_device(device)
        info.is_nvme = "nvme" in device.lower()

        if SYSTEM == "Linux":
            info.is_ssd = _is_ssd_linux(info.base_device)
            # NVMe is always SSD — fill in if rotational file is absent
            if info.is_ssd is None and info.is_nvme:
                info.is_ssd = True
            info.is_encrypted = _is_encrypted_linux(device)
        else:
            info.is_ssd = _is_ssd_macos(info.base_device or device)
            if info.is_ssd is None and info.is_nvme:
                info.is_ssd = True

    elif SYSTEM == "Windows":
        info.is_ssd = _is_ssd_windows()

    return info


def log_storage_info(info: StorageInfo):
    """Log storage type and targeted warnings based on detection results."""
    enc = " [ENCRYPTED]" if info.is_encrypted else ""
    log.info(f"  Storage: {info.device or 'unknown'} [{info.type_label()}]{enc}")

    if info.is_ssd:
        log.warning(
            "  SSD detected — multi-pass overwrite proceeds as BEST-EFFORT. "
            "FTL wear-leveling and over-provisioning may retain data."
        )
        if info.is_encrypted:
            log.info(
                "  Volume appears encrypted. Use --erase to destroy "
                "the key for the strongest SSD erasure guarantee (erases entire volume)."
            )
        else:
            log.warning(
                "  For stronger guarantees: use --erase (firmware-level whole-disk erase), "
                "or encrypt first and then --erase (destroys the key, strongest per-volume guarantee)."
            )
    elif info.is_ssd is None:
        log.warning("  Storage type unknown — treating overwrite as best-effort.")


# ─────────────────────────────────────────────
# SSD-SPECIFIC OPERATIONS
# ─────────────────────────────────────────────

def fstrim_mount(mount_point: str, dry_run: bool = False) -> bool:
    """
    Issue fstrim on a filesystem mount point (Linux only).
    Advisory only: signals free blocks to drive firmware; actual cell erasure
    depends on the drive and may be deferred or incomplete.
    """
    if SYSTEM != "Linux":
        log.warning("  fstrim is only supported on Linux.")
        return False

    log.info(f"  Running fstrim on {mount_point}...")
    log.warning("  fstrim is advisory — the drive may not erase cells immediately.")

    if dry_run:
        log.info(f"  [DRY RUN] Would run: fstrim -v {mount_point}")
        return True

    try:
        result = subprocess.run(
            ["fstrim", "-v", mount_point],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            log.info(f"  fstrim: {result.stdout.strip()}")
            return True
        log.warning(f"  fstrim returned code {result.returncode}: {result.stderr.strip()}")
        return False
    except FileNotFoundError:
        log.error("  fstrim not found. Install it with: apt install util-linux")
        return False


def ata_secure_erase(device: str, dry_run: bool = False) -> bool:
    """
    Perform ATA Secure Erase on a SATA drive (Linux, requires root).
    Erases all data including over-provisioned and FTL-remapped cells.
    WHOLE-DRIVE operation — requires --force.
    """
    if SYSTEM != "Linux":
        log.error("  ATA Secure Erase is only supported on Linux.")
        return False

    log.info(f"  ATA Secure Erase: {device}")
    log.warning("  This erases ALL data on the drive including hidden/over-provisioned areas.")

    if dry_run:
        log.info(f"  [DRY RUN] Would run: hdparm --security-erase on {device}")
        return True

    try:
        # Check for 'frozen' security state — cannot erase if frozen
        info_r = subprocess.run(
            ["hdparm", "-I", device], capture_output=True, text=True
        )
        if "frozen" in info_r.stdout.lower():
            log.error(
                "  Drive security state is 'frozen'. Cannot issue Secure Erase.\n"
                "  To unfreeze: suspend/resume the system (sleep+wake), then retry."
            )
            return False

        # Set a temporary password (required by ATA spec before erase)
        subprocess.run(
            ["hdparm", "--security-set-pass", "voidwipe_tmp", device],
            capture_output=True, check=True
        )
        # Issue the erase
        result = subprocess.run(
            ["hdparm", "--security-erase", "voidwipe_tmp", device],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            log.info(f"  ATA Secure Erase completed: {device}")
            return True
        log.error(f"  Secure Erase failed (code {result.returncode}): {result.stderr.strip()}")
        return False

    except FileNotFoundError:
        log.error("  hdparm not found. Install it with: apt install hdparm")
        return False
    except subprocess.CalledProcessError as e:
        log.error(f"  hdparm error: {e}")
        return False


def nvme_sanitize(device: str, dry_run: bool = False) -> bool:
    """
    Run NVMe Sanitize on an NVMe drive (Linux, requires root).
    Attempts crypto-erase first (sanact=4); falls back to block-erase (sanact=2).
    WHOLE-DRIVE operation — requires --force.
    """
    if SYSTEM != "Linux":
        log.error("  NVMe Sanitize is only supported on Linux.")
        return False

    log.info(f"  NVMe Sanitize: {device}")
    log.warning("  This erases ALL data on the NVMe drive.")

    if dry_run:
        log.info(f"  [DRY RUN] Would run: nvme sanitize {device} --sanact=4")
        return True

    try:
        # Try crypto-erase first (fastest, most thorough)
        for sanact, label in [("4", "crypto-erase"), ("2", "block-erase")]:
            result = subprocess.run(
                ["nvme", "sanitize", device, f"--sanact={sanact}"],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                log.info(
                    f"  NVMe Sanitize ({label}) initiated on {device}.\n"
                    f"  Monitor progress with: nvme sanitize-log {device}"
                )
                return True
            log.warning(f"  {label} not supported, trying next option...")

        log.error(f"  NVMe Sanitize failed: {result.stderr.strip()}")
        return False

    except FileNotFoundError:
        log.error("  nvme-cli not found. Install it with: apt install nvme-cli")
        return False


def _get_device_transport(device: str) -> str:
    """
    Return the transport string for a block device (e.g. 'usb', 'sata', 'nvme', '').
    Uses lsblk on Linux; returns '' if unavailable or not Linux.
    """
    if SYSTEM != "Linux":
        return ""
    try:
        result = subprocess.run(
            ["lsblk", "-dno", "TRAN", device],
            capture_output=True, text=True, timeout=5
        )
        return result.stdout.strip().lower()
    except Exception:
        return ""


def erase_device(device: str, dry_run: bool = False) -> bool:
    """
    Strongest available erase for DEVICE:
      1. If LUKS-encrypted: destroy all key slots (crypto-erase).
      2. Otherwise: ATA Secure Erase (SATA) or NVMe Sanitize (NVMe).
    USB devices are rejected — use --overwrite instead.
    WHOLE-DEVICE operation — requires --force.
    """
    transport = _get_device_transport(device)

    if transport == "usb":
        log.error(
            f"  {device} is connected via USB. Firmware-level erase commands are blocked "
            "by USB bridges and will silently do nothing.\n"
            f"  Use --overwrite {device} to perform a direct multi-pass overwrite instead."
        )
        return False

    # Try LUKS crypto-erase first (strongest per-volume guarantee on SSDs)
    if SYSTEM == "Linux":
        try:
            check = subprocess.run(
                ["cryptsetup", "isLuks", device],
                capture_output=True, timeout=5
            )
            if check.returncode == 0:
                log.info(f"  LUKS device detected — using crypto-erase for strongest guarantee.")
                return crypto_erase_luks(device, dry_run=dry_run)
        except FileNotFoundError:
            pass  # cryptsetup not installed; fall through to ATA/NVMe

    # Fall back to ATA Secure Erase or NVMe Sanitize
    if "nvme" in os.path.basename(device).lower():
        return nvme_sanitize(device, dry_run=dry_run)
    else:
        return ata_secure_erase(device, dry_run=dry_run)


def wipe_device(device: str, sequence: list, dry_run: bool = False,
                verify: bool = False) -> bool:
    """
    Directly overwrite a block device (e.g. /dev/sda, /dev/sdb) using the
    selected pass sequence. Works on any device the OS exposes as a block
    device, including USB drives where ATA Secure Erase is unavailable.
    WHOLE-DEVICE operation — requires --force.
    """
    dev_path = Path(device)
    if not dev_path.exists():
        log.error(f"  Device not found: {device}")
        return False

    # Determine device size via lsblk (Linux) or fallback seek
    size = None
    if SYSTEM == "Linux":
        try:
            result = subprocess.run(
                ["lsblk", "-dno", "SIZE", "--bytes", device],
                capture_output=True, text=True, timeout=5
            )
            size = int(result.stdout.strip())
        except Exception:
            pass

    if size is None:
        # Fallback: open and seek to end
        try:
            with open(device, "rb") as f:
                f.seek(0, 2)
                size = f.tell()
        except Exception as e:
            log.error(f"  Could not determine device size: {e}")
            return False

    transport = _get_device_transport(device)
    transport_note = f" [{transport.upper()}]" if transport else ""
    log.info(
        f"  Device: {device}{transport_note} | Size: {size / (1024**3):.2f} GB | "
        f"Passes: {len(sequence)}"
    )
    log.warning(
        "  WHOLE-DEVICE overwrite — all data will be permanently destroyed. "
        "On SSDs, physical erasure depends on FTL; this is best-effort."
    )

    if dry_run:
        log.info(f"  [DRY RUN] Would overwrite {size / (1024**3):.2f} GB on {device}")
        return True

    try:
        with open(device, "r+b") as f:
            _write_passes(f, size, sequence, verify=verify)
        log.info(f"  Device overwrite complete: {device}")
        return True
    except PermissionError:
        log.error(f"  Permission denied: {device}. Run with sudo.")
        return False
    except OSError as e:
        log.error(f"  Error writing to {device}: {e}")
        return False


def crypto_erase_luks(device: str, dry_run: bool = False) -> bool:
    """
    Destroy all LUKS key slots on a LUKS-encrypted device (Linux, requires root).
    Renders all ciphertext — including FTL-remapped SSD cells — computationally
    unrecoverable without key material. The strongest per-volume SSD guarantee.
    IRREVERSIBLE — requires --force.
    """
    if SYSTEM != "Linux":
        log.error("  LUKS crypto-erase is only supported on Linux.")
        return False

    log.info(f"  LUKS Crypto-Erase: {device}")
    log.warning(
        "  All LUKS key slots will be destroyed. "
        "Data will be permanently inaccessible — no recovery possible."
    )

    if dry_run:
        log.info(f"  [DRY RUN] Would run: cryptsetup erase {device}")
        return True

    try:
        # Verify it is actually a LUKS device before proceeding
        check = subprocess.run(
            ["cryptsetup", "isLuks", device],
            capture_output=True, timeout=5
        )
        if check.returncode != 0:
            log.error(f"  {device} does not appear to be a LUKS device.")
            return False

        result = subprocess.run(
            ["cryptsetup", "erase", "--batch-mode", device],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            log.info(
                f"  All LUKS key slots erased on {device}. "
                "Data is now cryptographically inaccessible."
            )
            return True
        log.error(
            f"  cryptsetup erase failed (code {result.returncode}): {result.stderr.strip()}"
        )
        return False

    except FileNotFoundError:
        log.error("  cryptsetup not found. Install it with: apt install cryptsetup")
        return False
    except subprocess.TimeoutExpired:
        log.error("  cryptsetup timed out.")
        return False


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

CHUNK_SIZE = 1024 * 1024               # 1 MB per chunk
FREE_SPACE_RESERVE = 64 * 1024 * 1024  # Keep 64 MB free to avoid system instability


def _write_passes(f, file_size: int, sequence: list, verify: bool = False):
    """
    Execute the overwrite pass sequence on an open file descriptor.
    If verify=True, the last chunk of each deterministic pass is read back
    and compared against the expected bytes.
    """
    if file_size == 0:
        return

    show_progress = file_size >= 4 * 1024 * 1024  # only for files >= 4 MB

    for i, (label, generator) in enumerate(sequence, 1):
        is_random = generator is pattern_random
        log.info(f"  Pass {i}/{len(sequence)}: {label}")
        f.seek(0)
        written = 0
        last_chunk = None
        last_pct_milestone = 0
        pass_start = time.monotonic()

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
        elapsed = time.monotonic() - pass_start
        mbps = (file_size / (1024 ** 2)) / elapsed if elapsed > 0 else 0
        log.info(f"    Done in {elapsed:.1f}s ({mbps:.1f} MB/s)")

        if verify and not is_random and last_chunk is not None:
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
    Storage detection and warnings are handled by the caller.
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
              verify: bool = False, exclude: list = None, force: bool = False) -> bool:
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

    def _is_excluded(p: Path) -> bool:
        if not exclude:
            return False
        return any(fnmatch.fnmatch(p.name, pat) for pat in exclude)

    files = sorted(p for p in root.rglob("*") if p.is_file() and not p.is_symlink() and not _is_excluded(p))
    skipped = sorted(p for p in root.rglob("*") if p.is_file() and not p.is_symlink() and _is_excluded(p))
    links = sorted(p for p in root.rglob("*") if p.is_symlink())
    skip_note = f", {len(skipped)} excluded" if skipped else ""
    log.info(f"Recursively shredding: {dirpath} ({len(files)} file(s), {len(links)} symlink(s){skip_note})")
    for p in skipped:
        log.info(f"  Excluded: {p}")
    warn_if_cow(dirpath)

    if dry_run:
        for f in files:
            log.info(f"  [DRY RUN] Would shred: {f}")
        for s in links:
            log.info(f"  [DRY RUN] Would unlink symlink: {s}")
        log.info(f"  [DRY RUN] Would remove directory tree: {dirpath}")
        return True

    if not force:
        try:
            answer = input(f"  About to shred {len(files)} file(s) in '{dirpath}'. Proceed? [y/N] ")
        except (EOFError, KeyboardInterrupt):
            log.info("  Aborted.")
            return False
        if answer.strip().lower() != "y":
            log.info("  Aborted.")
            return False

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
        raw_label = getattr(gen, '__name__', 'Random')
        label = "Random" if raw_label == "pattern_random" else raw_label
        log.info(f"  Pass {p}/{passes} — pattern: {label}")
        tmp_path = target / f"_freespace_{p}_{os.urandom(4).hex()}.tmp"
        total_written = 0
        pass_start = time.monotonic()

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

            elapsed = time.monotonic() - pass_start
            mbps = (total_written / (1024 ** 2)) / elapsed if elapsed > 0 else 0
            log.info(f"  Written {total_written / (1024**2):.1f} MB in {elapsed:.1f}s ({mbps:.1f} MB/s).")
        except OSError as e:
            if e.errno == 28:  # No space left on device — expected
                elapsed = time.monotonic() - pass_start
                mbps = (total_written / (1024 ** 2)) / elapsed if elapsed > 0 else 0
                log.info(f"  Disk full (expected). Pass {p} complete in {elapsed:.1f}s ({mbps:.1f} MB/s).")
            else:
                log.error(f"  Write error: {e}")
        finally:
            if tmp_path.exists():
                # Zero the temp file before unlinking to limit raw block recovery.
                # Written in chunks to avoid MemoryError on large files.
                try:
                    size = tmp_path.stat().st_size
                    zero_chunk = b'\x00' * CHUNK_SIZE
                    with open(tmp_path, "r+b") as f:
                        remaining = size
                        while remaining > 0:
                            n = min(CHUNK_SIZE, remaining)
                            f.write(zero_chunk[:n])
                            remaining -= n
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
        prog="voidwipe",
        description=(
            "voidwipe — Cross-platform secure file deletion\n\n"
            "Overwrites files, directories, and free space using multi-pass techniques\n"
            "before unlinking. Detects storage type (HDD/SSD/NVMe) and CoW filesystems\n"
            "automatically. On SSDs, multi-pass overwrite is best-effort only — use the\n"
            "SSD-specific options below for stronger guarantees."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
────────────────────────────────────────────────────────────────
PASS METHODS
────────────────────────────────────────────────────────────────
  default   4 passes: random → 0xFF → random → 0x00  (recommended)
  dod3      DoD 5220.22-M basic:  0x00 → 0xFF → random
  dod7      DoD 5220.22-M extended: 7 passes
  gutmann   Gutmann 35-pass (slowest, highest theoretical assurance on HDDs)

Use --passes N to override the pass count; passes beyond the method's
built-in count are filled with additional random-data passes.

────────────────────────────────────────────────────────────────
SSD ERASURE GUARANTEE TIERS  (weakest → strongest)
────────────────────────────────────────────────────────────────
  1. Multi-pass overwrite (--files, --dir, --freespace)
       Best-effort on SSDs. FTL wear-leveling may keep copies in
       over-provisioned NAND cells that the OS cannot reach.

  2. --overwrite DEVICE  (requires --force + root)
       Writes over every addressable byte of DEVICE in software.
       Works on USB drives. Still subject to FTL on SSDs.
       *** DESTROYS ALL DATA ON THE ENTIRE DEVICE ***

  3. --erase DEVICE  (requires --force + root)
       Firmware-level erase — strongest available method:
       LUKS crypto-erase if encrypted, else ATA/NVMe Secure Erase.
       Not supported on USB drives.
       *** DESTROYS ALL DATA ON THE ENTIRE DEVICE / VOLUME ***

────────────────────────────────────────────────────────────────
EXAMPLES
────────────────────────────────────────────────────────────────
  # Securely delete files (auto-detects HDD/SSD, warns if CoW filesystem)
  voidwipe --files secret.txt credentials.pdf

  # Shred an entire directory tree
  voidwipe --dir /home/user/sensitive/

  # Overwrite free space on a partition (hides previously deleted files)
  voidwipe --freespace /home

  # DoD 7-pass with read-back verification and a log file
  voidwipe --files secret.txt --method dod7 --verify --log voidwipe.log

  # Overwrite every byte of a USB drive (software, works on USB)
  sudo voidwipe --overwrite /dev/sdb --force

  # Firmware-level erase of an SSD (strongest: LUKS or ATA/NVMe Secure Erase)
  sudo voidwipe --erase /dev/sda --force

  # Remove VSS / LVM / APFS snapshots (requires root/admin)
  sudo voidwipe --snapshots

  # Preview all actions without making any changes
  voidwipe --files secret.txt --freespace /home --dry-run

────────────────────────────────────────────────────────────────
LIMITATIONS
────────────────────────────────────────────────────────────────
  SSD / NVMe    FTL and wear-leveling prevent guaranteed block overwrite.
  btrfs/ZFS/APFS  Copy-on-Write: originals may persist after overwrite.
  Encrypted volumes  Prefer cryptographic key destruction over overwriting.
  Network filesystems  Physical guarantees depend on the remote system.
        """
    )
    parser.add_argument("--version", action="version", version=f"voidwipe {VERSION}")

    # ── File / directory targets ──────────────────────────────────────────────
    targets = parser.add_argument_group("targets — what to wipe")
    targets.add_argument(
        "--files", nargs="+", metavar="FILE",
        help=(
            "One or more files to securely overwrite and delete. "
            "Each file is overwritten with the selected pass method, "
            "then renamed to a random name before unlinking."
        )
    )
    targets.add_argument(
        "--files-from", metavar="FILE",
        help=(
            "Read file paths to shred from FILE, one path per line. "
            "Use '-' to read from stdin (e.g. find . -name '*.key' | voidwipe --files-from -). "
            "Paths are processed in addition to any --files arguments."
        )
    )
    targets.add_argument(
        "--dir", metavar="DIRECTORY",
        help=(
            "Recursively shred every file inside DIRECTORY, then remove "
            "the directory tree. Equivalent to running --files on each "
            "file in the tree. Prompts for confirmation unless --force is given."
        )
    )
    targets.add_argument(
        "--exclude", nargs="+", metavar="PATTERN",
        help=(
            "Glob pattern(s) to skip when using --dir (e.g. '*.log' '*.tmp'). "
            "Matched against filename only, not the full path."
        )
    )
    targets.add_argument(
        "--freespace", metavar="DIRECTORY",
        help=(
            "Overwrite free blocks on the partition that contains DIRECTORY. "
            "Fills available space with patterned data to obscure previously "
            "deleted files, then removes the temporary fill file. "
            "Use --freespace-passes to control how many passes are written."
        )
    )
    targets.add_argument(
        "--snapshots", action="store_true",
        help=(
            "Delete system-level snapshots before wiping: "
            "VSS Shadow Copies (Windows), LVM snapshots (Linux), "
            "APFS snapshots (macOS). Requires administrator / root privileges."
        )
    )

    # ── Pass / overwrite configuration ───────────────────────────────────────
    passes = parser.add_argument_group("pass configuration")
    passes.add_argument(
        "--method", choices=list(PASS_METHODS.keys()), default="default",
        metavar="METHOD",
        help=(
            "Overwrite pattern sequence to use. "
            "Choices: default (4-pass), dod3 (3-pass), dod7 (7-pass), gutmann (35-pass). "
            "(default: default)"
        )
    )
    passes.add_argument(
        "--passes", type=int, default=None, metavar="N",
        help=(
            "Override the total number of overwrite passes (minimum: 1). "
            "If N is greater than the chosen method's built-in count, "
            "the extra passes use random data. "
            "If N is smaller, the method is truncated to N passes."
        )
    )
    passes.add_argument(
        "--freespace-passes", type=int, default=None, metavar="N",
        help=(
            "Number of overwrite passes for --freespace "
            "(default: matches --method / --passes). Each pass fills "
            "the free space with a different pattern before the fill "
            "file is removed. Set explicitly to decouple from file passes."
        )
    )
    passes.add_argument(
        "--verify", action="store_true",
        help=(
            "After each deterministic overwrite pass (fixed byte patterns), "
            "read the written data back and confirm it matches. "
            "Skipped for random-data passes. Adds time but confirms "
            "the drive accepted the writes."
        )
    )

    # ── Device operations ─────────────────────────────────────────────────────
    dev = parser.add_argument_group(
        "device operations",
        "Whole-device operations. Both require --force and root privileges."
    )
    dev.add_argument(
        "--overwrite", metavar="DEVICE",
        help=(
            "*** WHOLE-DEVICE OPERATION *** "
            "Write over every byte of DEVICE (e.g. /dev/sda) using the selected "
            "pass method. Software-level; works on all drive types including USB. "
            "On SSDs, physical erasure is best-effort due to FTL wear-leveling. "
            "Requires --force and root privileges."
        )
    )
    dev.add_argument(
        "--erase", metavar="DEVICE",
        help=(
            "*** WHOLE-DEVICE OPERATION *** "
            "Apply the strongest available firmware-level erase to DEVICE: "
            "LUKS crypto-erase if the device is encrypted (destroys key slots), "
            "otherwise ATA Secure Erase (SATA) or NVMe Sanitize (NVMe). "
            "Not supported on USB drives — use --overwrite instead. "
            "Requires --force and root privileges."
        )
    )
    dev.add_argument(
        "--force", action="store_true",
        help=(
            "Skip confirmation prompts. Required by --overwrite and --erase; "
            "also bypasses the --dir confirmation prompt."
        )
    )

    # ── General ───────────────────────────────────────────────────────────────
    general = parser.add_argument_group("general")
    general.add_argument(
        "-q", "--quiet", action="store_true",
        help=(
            "Suppress all informational output; only errors and warnings are printed. "
            "Useful for scripts and cron jobs that rely on the exit code."
        )
    )
    general.add_argument(
        "--json", action="store_true",
        help=(
            "Print the session summary as a JSON object to stdout instead of the "
            "standard log format. Useful for parsing results in scripts."
        )
    )
    general.add_argument(
        "--dry-run", action="store_true",
        help=(
            "Preview every action that would be taken without writing, "
            "deleting, or modifying anything. Useful for verifying the "
            "scope of an operation before committing."
        )
    )
    general.add_argument(
        "--log", metavar="FILE",
        help=(
            "Write a timestamped, detailed log of all operations to FILE. "
            "Log output is appended to the file if it already exists."
        )
    )
    return parser.parse_args()


def main():
    args = parse_args()
    setup_logging(args.log, quiet=args.quiet, json_mode=args.json)

    log.info("=" * 60)
    log.info("voidwipe — Secure deletion session started")
    log.info(f"System: {SYSTEM} | Admin: {is_admin()} | Version: {VERSION}")
    log.info(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    if args.dry_run:
        log.info("[DRY RUN] No changes will be made.")
    log.info("=" * 60)

    if not is_admin():
        log.warning("Not running as administrator/root. Some features may fail.")

    # Validate destructive whole-disk flags require --force
    if (args.erase or args.overwrite) and not args.force and not args.dry_run:
        log.error(
            "--erase and --overwrite are whole-device destructive operations.\n"
            "Re-run with --force to confirm, or use --dry-run to preview."
        )
        sys.exit(1)

    # Resolve --files-from
    files_from_list = []
    if args.files_from:
        src = sys.stdin if args.files_from == "-" else open(args.files_from, encoding="utf-8")
        try:
            files_from_list = [line.rstrip("\r\n") for line in src if line.strip()]
        finally:
            if src is not sys.stdin:
                src.close()

    all_files = list(args.files or []) + files_from_list

    if not any([all_files, args.dir, args.freespace, args.snapshots,
                args.erase, args.overwrite]):
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

    freespace_passes = args.freespace_passes if args.freespace_passes is not None else len(sequence)
    log.info(f"Pass method: {args.method} | File passes: {len(sequence)} | Free space passes: {freespace_passes} | Verify: {args.verify}")

    session_start = time.monotonic()
    results = []

    # 1. Delete snapshots first (before touching the disk)
    if args.snapshots:
        log.info("\n-- Snapshot Removal -----------------------------------------------")
        results.append(("Snapshots", delete_snapshots()))

    # 2. Secure file deletion
    if all_files:
        log.info("\n-- Secure File Deletion -------------------------------------------")
        for f in all_files:
            info = detect_storage(f)
            log_storage_info(info)
            ok = shred_file(f, sequence=sequence, dry_run=args.dry_run, verify=args.verify)
            results.append((f"File: {f}", ok))

    # 3. Secure directory deletion
    if args.dir:
        log.info("\n-- Secure Directory Deletion --------------------------------------")
        info = detect_storage(args.dir)
        log_storage_info(info)
        ok = shred_dir(args.dir, sequence=sequence, dry_run=args.dry_run, verify=args.verify,
                       exclude=args.exclude, force=args.force)
        results.append((f"Dir: {args.dir}", ok))

    # 4. Free space overwrite
    if args.freespace:
        log.info("\n-- Free Space Overwrite -------------------------------------------")
        info = detect_storage(args.freespace)
        log_storage_info(info)
        ok = overwrite_free_space(args.freespace, passes=freespace_passes, dry_run=args.dry_run)
        results.append(("Free space", ok))

    # 5. Direct device overwrite — software, byte-by-byte; works on USB and any block device
    if args.overwrite:
        log.info("\n-- Device Overwrite (WHOLE DEVICE) -----------------------------------")
        ok = wipe_device(args.overwrite, sequence=sequence, dry_run=args.dry_run,
                         verify=args.verify)
        results.append((f"Overwrite: {args.overwrite}", ok))

    # 6. Firmware-level erase — LUKS crypto-erase → ATA/NVMe Secure Erase (whole device)
    if args.erase:
        log.info("\n-- Device Erase (WHOLE DEVICE) ---------------------------------------")
        ok = erase_device(args.erase, dry_run=args.dry_run)
        results.append((f"Erase: {args.erase}", ok))

    # Final summary
    session_elapsed = time.monotonic() - session_start
    all_ok = all(ok for _, ok in results)

    if args.json:
        summary = {
            "status": "ok" if all_ok else "errors",
            "elapsed_s": round(session_elapsed, 1),
            "results": [{"label": label, "ok": ok} for label, ok in results],
        }
        print(json.dumps(summary))
    else:
        log.info("\n-- Summary --------------------------------------------------------")
        for label, ok in results:
            status = "OK  " if ok else "FAIL"
            log.info(f"  [{status}]  {label}")
        log.info("=" * 60)
        log.info("Session complete in {:.1f}s.".format(session_elapsed)
                 + (" With errors." if not all_ok else " No errors."))

    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
