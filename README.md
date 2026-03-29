# voidwipe

A cross-platform Python tool for secure file deletion, free space overwriting, and snapshot removal using multi-pass overwrite techniques.

> **Warning:** Primarily effective on HDDs. On SSDs, the FTL/TRIM layer limits physical overwrite guarantees. On Copy-on-Write filesystems (btrfs, ZFS, APFS), overwrite does **not** guarantee physical data erasure regardless of storage type.

---

## Features

- **Secure file deletion** — multi-pass overwrite before unlinking (rename randomization included)
- **Recursive directory shredding** — wipes every file inside a directory tree, then removes it
- **Free space overwriting** — fills free blocks with patterned data to overwrite unlinked file remnants
- **Snapshot/shadow copy removal** — removes VSS (Windows), LVM snapshots (Linux), APFS snapshots (macOS)
- **Multiple pass methods** — Default 4-pass, DoD 3-pass, DoD 7-pass, Gutmann 35-pass
- **Read-back verification** — confirms deterministic passes were written correctly
- **Dry-run mode** — preview all actions without making any changes
- **CoW filesystem detection** — warns when overwrite cannot guarantee physical erasure
- **Progress reporting** — milestone output for large files
- **Detailed logging** — optional log file output

---

## Requirements

- Python 3.8+
- No third-party dependencies

Platform-specific optional tools (used when available):
- **Linux:** `lvs`, `lvremove` (LVM snapshot removal)
- **macOS:** `tmutil` (APFS snapshot removal)
- **Windows:** `vssadmin` (shadow copy removal), `cipher` (NTFS free-space wipe)

---

## Installation

```bash
git clone https://github.com/youruser/voidwipe.git
cd voidwipe
pip install .
```

This registers the `voidwipe` command in your Python environment's `bin` directory (Unix) or `Scripts` directory (Windows), so you can run it directly without `python3 voidwipe.py`.

For development (editable install — changes to `voidwipe.py` take effect immediately):

```bash
pip install -e .
```

**Platform notes**

| Platform | Command registered at |
|---|---|
| Linux / macOS | `~/.local/bin/voidwipe` (user) or `/usr/local/bin/voidwipe` (system with `sudo pip`) |
| Windows | `%APPDATA%\Python\Scripts\voidwipe.exe` (user) or `C:\PythonXY\Scripts\voidwipe.exe` (system) |

Ensure the relevant `bin` / `Scripts` directory is in your `PATH`. Most Python installers on all platforms handle this automatically.

---

## Usage

```
voidwipe.py [--files FILE ...] [--dir DIRECTORY] [--freespace DIRECTORY]
            [--snapshots] [--method METHOD] [--passes N]
            [--freespace-passes N] [--verify] [--dry-run] [--log FILE]
```

### Options

| Flag | Description |
|---|---|
| `--files FILE ...` | Securely delete one or more files |
| `--dir DIRECTORY` | Recursively shred all files in a directory |
| `--freespace DIRECTORY` | Overwrite free space on the partition containing this directory |
| `--snapshots` | Delete Volume Shadow Copies / LVM / APFS snapshots (requires admin) |
| `--method METHOD` | Pass method: `default`, `dod3`, `dod7`, `gutmann` (default: `default`) |
| `--passes N` | Override pass count; if N > method's pass count, extra random passes are appended |
| `--freespace-passes N` | Number of passes for free space overwrite (default: 2) |
| `--verify` | Read-back verify each deterministic overwrite pass |
| `--dry-run` | Preview all actions without making any changes |
| `--log FILE` | Write a detailed log to a file |
| `--version` | Show version and exit |

### Pass methods

| Method | Passes | Description |
|---|---|---|
| `default` | 4 | Random, 0xFF, Random, 0x00 |
| `dod3` | 3 | DoD 5220.22-M (basic): 0x00, 0xFF, Random |
| `dod7` | 7 | DoD 5220.22-M (extended) |
| `gutmann` | 35 | Gutmann method |

---

## Examples

```bash
# Securely delete files
python3 voidwipe.py --files secret.txt credentials.pdf

# Shred an entire directory
python3 voidwipe.py --dir /home/user/sensitive/

# Overwrite free space on a partition
python3 voidwipe.py --freespace /home

# Full run: DoD 7-pass with verification and logging
python3 voidwipe.py --files secret.txt --method dod7 --verify --log voidwipe.log

# Delete snapshots + free space (requires root)
sudo python3 voidwipe.py --snapshots --freespace /

# Preview all actions without making changes
python3 voidwipe.py --files secret.txt --freespace /home --dry-run

# Gutmann 35-pass on a file
python3 voidwipe.py --files secret.txt --method gutmann
```

---

## Limitations

| Scenario | Limitation |
|---|---|
| SSD / NVMe | FTL wear-leveling and TRIM prevent guaranteed overwrite of specific blocks |
| btrfs / ZFS / APFS | Copy-on-Write writes to new blocks; original blocks may persist |
| Encrypted volumes | Rekeying the volume is more reliable than file-level overwriting |
| Network filesystems | Physical overwrite guarantees depend entirely on the remote system |
| File system journals | Journal entries may retain metadata even after deletion |

For maximum assurance on SSDs or encrypted volumes, combine voidwipe with full-disk encryption and cryptographic key destruction.

---

## License

See [LICENSE](LICENSE).
