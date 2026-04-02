# voidwipe

A cross-platform Python tool for secure file deletion, free space overwriting, and snapshot removal using multi-pass overwrite techniques.

> **Warning:** Primarily effective on HDDs. On SSDs, the FTL/TRIM layer limits physical overwrite guarantees. On Copy-on-Write filesystems (btrfs, ZFS, APFS), overwrite does **not** guarantee physical data erasure regardless of storage type.

---

## Features

- **Secure file deletion** — multi-pass overwrite before unlinking (rename randomization included)
- **Recursive directory shredding** — wipes every file inside a directory tree, then removes it
- **Free space overwriting** — fills free blocks with patterned data to overwrite unlinked file remnants; uses `cipher /w` on Windows NTFS automatically
- **Device overwrite** — overwrites an entire block device byte-by-byte in software; works on USB drives and any block device (`--overwrite`)
- **Firmware-level device erase** — auto-selects LUKS crypto-erase or ATA/NVMe Secure Erase for the strongest available guarantee (`--erase`)
- **Snapshot/shadow copy removal** — removes VSS (Windows), LVM snapshots (Linux), APFS snapshots (macOS)
- **Multiple pass methods** — Default 4-pass, DoD 3-pass, DoD 7-pass, Gutmann 35-pass
- **Read-back verification** — confirms deterministic passes were written correctly
- **Real-time progress** — live per-pass progress line with current MB/s when stderr is a TTY
- **Per-pass timing and throughput** — logs elapsed time and MB/s for each pass
- **Pre-flight validation** — checks all targets before starting; reports all errors at once
- **Parallel shredding** — shred multiple files simultaneously with `--jobs N`
- **SHA-256 audit trail** — log file hashes before deletion with `--hash`
- **Dry-run mode** — preview all actions without making any changes
- **CoW filesystem detection** — warns when overwrite cannot guarantee physical erasure
- **Detailed logging** — optional log file output
- **Quiet mode** — suppress informational output for scripting
- **JSON output** — machine-readable session summary
- **stdin / file list input** — pipe file paths directly via `--files-from`
- **Exclude patterns** — skip files matching a glob when shredding directories

---

## Requirements

- Python 3.8+
- No third-party dependencies

Platform-specific optional tools (used when available):
- **Linux:** `lvs`, `lvremove` (LVM snapshot removal), `hdparm` (ATA Secure Erase), `nvme-cli` (NVMe Sanitize), `lsblk` (transport detection), `fstrim` (TRIM)
- **macOS:** `tmutil` (APFS snapshot removal)
- **Windows:** `vssadmin` (shadow copy removal), `cipher` (NTFS free-space wipe)

---

## Installation

```bash
git clone https://github.com/youruser/voidwipe.git
cd voidwipe
pip install .
```

This registers the `voidwipe` command in your Python environment's `bin` directory (Unix) or `Scripts` directory (Windows).

For development (editable install — changes to `voidwipe.py` take effect immediately):

```bash
pip install -e .
```

**Platform notes**

| Platform | Command registered at |
|---|---|
| Linux / macOS | `~/.local/bin/voidwipe` (user) or `/usr/local/bin/voidwipe` (system with `sudo pip`) |
| Windows | `%APPDATA%\Python\Scripts\voidwipe.exe` (user) or `C:\PythonXY\Scripts\voidwipe.exe` (system) |

---

## Usage

```
voidwipe [--files FILE ...] [--files-from FILE] [--dir DIRECTORY] [--exclude PATTERN ...]
         [--freespace DIRECTORY] [--snapshots]
         [--method METHOD] [--passes N] [--freespace-passes N] [--verify] [--hash] [--jobs N]
         [--overwrite DEVICE] [--erase DEVICE]
         [--force] [-q] [--json] [--dry-run] [--log FILE]
```

### Options

#### Targets — what to wipe

| Flag | Description |
|---|---|
| `--files FILE ...` | Securely delete one or more files |
| `--files-from FILE` | Read file paths from FILE (one per line); use `-` for stdin |
| `--dir DIRECTORY` | Recursively shred all files in a directory; prompts for confirmation unless `--force` |
| `--exclude PATTERN ...` | Glob pattern(s) to skip when using `--dir` (e.g. `*.log`); matched on filename only |
| `--freespace DIRECTORY` | Overwrite free space on the partition containing this directory |
| `--snapshots` | Delete Volume Shadow Copies / LVM / APFS snapshots (requires admin) |

#### Pass options

| Flag | Description |
|---|---|
| `--method METHOD` | Pass method: `default`, `dod3`, `dod7`, `gutmann` (default: `default`) |
| `--passes N` | Override pass count; extra passes beyond the method's count use random data |
| `--freespace-passes N` | Passes for free space overwrite (default: matches `--method`/`--passes`) |
| `--verify` | Read-back verify each deterministic overwrite pass |
| `--hash` | Log SHA-256 digest of each file before overwriting (audit trail) |
| `--jobs N` | Shred files in parallel with N workers (default: 1). Applies to `--files` and `--dir` |

#### Device operations

| Flag | Description |
|---|---|
| `--overwrite DEVICE` | Write over every byte of DEVICE in software (e.g. `/dev/sda`). Works on all drive types including USB. On SSDs, best-effort due to FTL. **Whole-device, irreversible.** Requires `--force` and root |
| `--erase DEVICE` | Firmware-level erase: LUKS crypto-erase if encrypted, otherwise ATA Secure Erase (SATA) or NVMe Sanitize. Not supported on USB — use `--overwrite` instead. **Whole-device, irreversible.** Requires `--force` and root |
| `--force` | Skip confirmation prompts. Required for `--overwrite` and `--erase`; also bypasses the `--dir` prompt |

#### General

| Flag | Description |
|---|---|
| `-q`, `--quiet` | Suppress informational output; only errors and warnings are printed |
| `--json` | Print session summary as JSON to stdout |
| `--dry-run` | Preview all actions without making any changes |
| `--log FILE` | Write a detailed log to FILE (appended if it already exists) |
| `--version` | Show version and exit |

### Pass methods

| Method | Passes | Pattern |
|---|---|---|
| `default` | 4 | Random → 0xFF → Random → 0x00 |
| `dod3` | 3 | DoD 5220.22-M basic: 0x00 → 0xFF → Random |
| `dod7` | 7 | DoD 5220.22-M extended |
| `gutmann` | 35 | Gutmann method |

---

## Examples

```bash
# Securely delete files
voidwipe --files secret.txt credentials.pdf

# Shred an entire directory (prompts for confirmation)
voidwipe --dir /home/user/sensitive/

# Shred a directory, skipping log files, no prompt
voidwipe --dir /home/user/sensitive/ --exclude '*.log' --force

# Read file list from stdin
find /home/user -name '*.key' | voidwipe --files-from -

# Overwrite free space on a partition
voidwipe --freespace /home

# Full run: DoD 7-pass with verification and logging
voidwipe --files secret.txt --method dod7 --verify --log voidwipe.log

# Log SHA-256 hash before deletion (audit trail)
voidwipe --files secret.txt --hash --log audit.log

# Shred a large directory using 4 parallel workers
voidwipe --dir /home/user/sensitive/ --jobs 4 --force

# Delete snapshots + free space (requires root)
sudo voidwipe --snapshots --freespace /

# Overwrite every byte of a USB drive in software (DoD 3-pass, dry-run first)
sudo voidwipe --overwrite /dev/sdb --method dod3 --force --dry-run
sudo voidwipe --overwrite /dev/sdb --method dod3 --force

# Firmware-level erase of an SSD (auto-selects LUKS crypto-erase or ATA/NVMe Secure Erase)
sudo voidwipe --erase /dev/sda --force

# Preview all actions without making changes
voidwipe --files secret.txt --freespace /home --dry-run

# Quiet mode for scripts (only errors/warnings printed, check exit code)
voidwipe --files secret.txt -q
echo $?

# JSON output for scripting
voidwipe --files secret.txt --json
```

---

## SSD erasure tiers (weakest → strongest)

| Tier | Method | Notes |
|---|---|---|
| 1 | Multi-pass overwrite (`--files`, `--dir`, `--freespace`) | Best-effort; FTL may retain copies in over-provisioned cells |
| 2 | `--overwrite DEVICE` | Overwrites every addressable byte in software; works on USB; still subject to FTL on SSDs |
| 3 | `--erase DEVICE` (ATA/NVMe) | Drive firmware erases all cells including over-provisioned NAND; SATA/NVMe only, not USB |
| 4 | `--erase DEVICE` (LUKS) | Destroys the encryption key; ciphertext unreadable without key — strongest per-volume guarantee |

---

## Limitations

| Scenario | Limitation |
|---|---|
| SSD / NVMe | FTL wear-leveling and TRIM prevent guaranteed overwrite of specific blocks |
| USB drives | Firmware erase (`--erase`) is blocked by USB bridges — use `--overwrite` instead |
| btrfs / ZFS / APFS | Copy-on-Write writes to new blocks; original blocks may persist |
| Encrypted volumes | Rekeying the volume is more reliable than file-level overwriting |
| Network filesystems | Physical overwrite guarantees depend entirely on the remote system |
| File system journals | Journal entries may retain metadata even after deletion |

For maximum assurance on SSDs or encrypted volumes, combine voidwipe with full-disk encryption and cryptographic key destruction.

---

## License

See [LICENSE](LICENSE).
