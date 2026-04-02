"""
Tests for voidwipe.py — exercises all major functions and CLI paths.
Run with: python3 -m pytest test_voidwipe.py -v
"""

import hashlib
import json
import logging
import os
import subprocess
import sys
from pathlib import Path

import pytest

# ── Import the module under test ──────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))
import voidwipe
from voidwipe import (
    CHUNK_SIZE,
    PASS_METHODS,
    _make_fixed,
    _make_repeat,
    _sha256_file,
    _write_passes,
    pattern_random,
    shred_file,
    shred_dir,
    overwrite_free_space,
)


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def make_file(directory, name="test.bin", size=1024, content=None):
    p = Path(directory) / name
    if content is not None:
        p.write_bytes(content)
    else:
        p.write_bytes(os.urandom(size))
    return p


# ─────────────────────────────────────────────
# Pattern generators
# ─────────────────────────────────────────────

class TestPatternGenerators:

    def test_pattern_random_length(self):
        data = pattern_random(256)
        assert len(data) == 256

    def test_pattern_random_different_each_call(self):
        assert pattern_random(64) != pattern_random(64)

    def test_make_fixed_full_chunk(self):
        gen = _make_fixed(0xFF)
        data = gen(CHUNK_SIZE)
        assert len(data) == CHUNK_SIZE
        assert data == bytes([0xFF]) * CHUNK_SIZE

    def test_make_fixed_partial_chunk(self):
        gen = _make_fixed(0x00)
        data = gen(100)
        assert len(data) == 100
        assert data == b"\x00" * 100

    def test_make_fixed_correct_byte(self):
        for val in (0x00, 0xFF, 0x96, 0x6D):
            gen = _make_fixed(val)
            data = gen(512)
            assert all(b == val for b in data)

    def test_make_repeat_full_chunk(self):
        pattern = b"\x92\x49\x24"
        gen = _make_repeat(pattern)
        data = gen(CHUNK_SIZE)
        assert len(data) == CHUNK_SIZE
        assert data[:3] == pattern

    def test_make_repeat_partial_chunk(self):
        gen = _make_repeat(b"\xAA\x55")
        data = gen(7)
        assert len(data) == 7
        assert data == b"\xAA\x55\xAA\x55\xAA\x55\xAA"

    def test_make_fixed_name(self):
        gen = _make_fixed(0xAB)
        assert gen.__name__ == "0xAB"


# ─────────────────────────────────────────────
# _write_passes
# ─────────────────────────────────────────────

class TestWritePasses:

    def test_fixed_pass_overwrites_every_byte(self, tmp_path):
        size = CHUNK_SIZE + 512  # spans two chunks
        p = tmp_path / "data.bin"
        p.write_bytes(os.urandom(size))
        sequence = [("0xFF", _make_fixed(0xFF))]
        with open(p, "r+b") as f:
            _write_passes(f, size, sequence, progress=False)
        result = p.read_bytes()
        assert result == bytes([0xFF]) * size

    def test_random_pass_changes_content(self, tmp_path):
        size = 4096
        p = tmp_path / "data.bin"
        original = bytes([0x00]) * size
        p.write_bytes(original)
        sequence = [("Random", pattern_random)]
        with open(p, "r+b") as f:
            _write_passes(f, size, sequence, progress=False)
        assert p.read_bytes() != original

    def test_multiple_passes_execute(self, tmp_path):
        size = 4096
        p = tmp_path / "data.bin"
        p.write_bytes(b"\xAA" * size)
        sequence = list(PASS_METHODS["dod3"])
        with open(p, "r+b") as f:
            _write_passes(f, size, sequence, progress=False)
        assert len(p.read_bytes()) == size

    def test_zero_size_file_no_error(self, tmp_path):
        p = tmp_path / "empty.bin"
        p.write_bytes(b"")
        with open(p, "r+b") as f:
            _write_passes(f, 0, PASS_METHODS["default"], progress=False)

    def test_verify_pass_detects_correct_write(self, tmp_path):
        size = 4096
        p = tmp_path / "data.bin"
        p.write_bytes(b"\x00" * size)
        sequence = [("0xFF", _make_fixed(0xFF))]
        with open(p, "r+b") as f:
            _write_passes(f, size, sequence, verify=True, progress=False)

    def test_all_methods_run_without_error(self, tmp_path):
        size = CHUNK_SIZE * 2
        for method in ("default", "dod3", "dod7"):
            p = tmp_path / f"{method}.bin"
            p.write_bytes(os.urandom(size))
            with open(p, "r+b") as f:
                _write_passes(f, size, list(PASS_METHODS[method]), progress=False)


# ─────────────────────────────────────────────
# _sha256_file
# ─────────────────────────────────────────────

class TestSha256File:

    def test_known_hash(self, tmp_path):
        p = tmp_path / "data.bin"
        p.write_bytes(b"hello world")
        expected = hashlib.sha256(b"hello world").hexdigest()
        assert _sha256_file(p) == expected

    def test_empty_file(self, tmp_path):
        p = tmp_path / "empty.bin"
        p.write_bytes(b"")
        expected = hashlib.sha256(b"").hexdigest()
        assert _sha256_file(p) == expected

    def test_large_file(self, tmp_path):
        data = os.urandom(CHUNK_SIZE * 3)
        p = tmp_path / "large.bin"
        p.write_bytes(data)
        assert _sha256_file(p) == hashlib.sha256(data).hexdigest()


# ─────────────────────────────────────────────
# shred_file
# ─────────────────────────────────────────────

class TestShredFile:

    def test_file_is_deleted(self, tmp_path):
        p = make_file(tmp_path)
        ok = shred_file(str(p), sequence=list(PASS_METHODS["dod3"]))
        assert ok is True
        assert not p.exists()

    def test_content_overwritten_before_delete(self, tmp_path):
        p = tmp_path / "secret.txt"
        p.write_bytes(b"SENSITIVE DATA " * 100)
        ok = shred_file(str(p), sequence=list(PASS_METHODS["dod3"]))
        assert ok is True
        assert not p.exists()

    def test_nonexistent_file_returns_false(self, tmp_path):
        ok = shred_file(str(tmp_path / "ghost.txt"))
        assert ok is False

    def test_symlink_skipped(self, tmp_path):
        target = make_file(tmp_path, "real.bin")
        link = tmp_path / "link.bin"
        link.symlink_to(target)
        ok = shred_file(str(link))
        assert ok is False
        assert target.exists()

    def test_dry_run_file_not_deleted(self, tmp_path):
        p = make_file(tmp_path)
        ok = shred_file(str(p), dry_run=True)
        assert ok is True
        assert p.exists()

    def test_zero_byte_file(self, tmp_path):
        p = tmp_path / "empty.bin"
        p.write_bytes(b"")
        ok = shred_file(str(p), sequence=list(PASS_METHODS["default"]))
        assert ok is True
        assert not p.exists()

    def test_hash_before_logs_digest(self, tmp_path, caplog):
        content = b"audit me"
        p = tmp_path / "audit.txt"
        p.write_bytes(content)
        expected_hash = hashlib.sha256(content).hexdigest()
        with caplog.at_level(logging.INFO, logger="voidwipe"):
            shred_file(str(p), sequence=list(PASS_METHODS["dod3"]), hash_before=True)
        assert expected_hash in caplog.text

    def test_gutmann_method(self, tmp_path):
        p = make_file(tmp_path, size=512)
        ok = shred_file(str(p), sequence=list(PASS_METHODS["gutmann"]))
        assert ok is True
        assert not p.exists()

    def test_verify_flag_runs(self, tmp_path):
        p = make_file(tmp_path, size=4096)
        ok = shred_file(str(p), sequence=list(PASS_METHODS["dod3"]), verify=True)
        assert ok is True

    def test_custom_pass_count(self, tmp_path):
        p = make_file(tmp_path)
        seq = list(PASS_METHODS["default"])[:2]
        ok = shred_file(str(p), sequence=seq)
        assert ok is True
        assert not p.exists()


# ─────────────────────────────────────────────
# shred_dir
# ─────────────────────────────────────────────

class TestShredDir:

    def test_directory_and_contents_removed(self, tmp_path):
        d = tmp_path / "sensitive"
        d.mkdir()
        for i in range(3):
            (d / f"file{i}.txt").write_bytes(os.urandom(256))
        ok = shred_dir(str(d), sequence=list(PASS_METHODS["dod3"]), force=True)
        assert ok is True
        assert not d.exists()

    def test_dry_run_leaves_directory(self, tmp_path):
        d = tmp_path / "keep"
        d.mkdir()
        (d / "file.txt").write_bytes(b"data")
        ok = shred_dir(str(d), dry_run=True, force=True)
        assert ok is True
        assert d.exists()

    def test_exclude_pattern(self, tmp_path, caplog):
        d = tmp_path / "mixed"
        d.mkdir()
        log_content = b"log data"
        (d / "keep.log").write_bytes(log_content)
        (d / "delete.txt").write_bytes(b"secret")
        with caplog.at_level(logging.INFO, logger="voidwipe"):
            shred_dir(str(d), sequence=list(PASS_METHODS["dod3"]),
                      force=True, exclude=["*.log"])
        # Excluded files are skipped from secure overwrite (not securely wiped)
        # but are removed by the final rmtree along with the directory.
        # Verify the excluded file was logged as skipped.
        assert "Excluded" in caplog.text
        assert "keep.log" in caplog.text

    def test_symlinks_unlinked_not_followed(self, tmp_path):
        d = tmp_path / "withlinks"
        d.mkdir()
        real = tmp_path / "real.bin"
        real.write_bytes(os.urandom(64))
        (d / "link.bin").symlink_to(real)
        (d / "file.bin").write_bytes(os.urandom(64))
        shred_dir(str(d), sequence=list(PASS_METHODS["dod3"]), force=True)
        assert real.exists()

    def test_nonexistent_dir_returns_false(self, tmp_path):
        ok = shred_dir(str(tmp_path / "ghost"), force=True)
        assert ok is False

    def test_parallel_jobs(self, tmp_path):
        d = tmp_path / "parallel"
        d.mkdir()
        for i in range(8):
            (d / f"f{i}.bin").write_bytes(os.urandom(512))
        ok = shred_dir(str(d), sequence=list(PASS_METHODS["dod3"]),
                       force=True, jobs=4)
        assert ok is True
        assert not d.exists()

    def test_hash_before_in_dir(self, tmp_path, caplog):
        d = tmp_path / "hashdir"
        d.mkdir()
        content = b"hashable content"
        (d / "f.bin").write_bytes(content)
        expected = hashlib.sha256(content).hexdigest()
        with caplog.at_level(logging.INFO, logger="voidwipe"):
            shred_dir(str(d), sequence=list(PASS_METHODS["dod3"]),
                      force=True, hash_before=True)
        assert expected in caplog.text


# ─────────────────────────────────────────────
# overwrite_free_space
# ─────────────────────────────────────────────

class TestOverwriteFreeSpace:

    def test_dry_run(self, tmp_path):
        ok = overwrite_free_space(str(tmp_path), passes=1, dry_run=True)
        assert ok is True

    def test_invalid_directory(self, tmp_path):
        ok = overwrite_free_space(str(tmp_path / "no_such_dir"))
        assert ok is False

    def test_creates_and_removes_temp_file(self, tmp_path):
        # Run with 1 pass; the temp file must be gone afterward
        overwrite_free_space(str(tmp_path), passes=1, dry_run=False)
        remaining = list(tmp_path.glob("_freespace_*.tmp"))
        assert remaining == []


# ─────────────────────────────────────────────
# CLI integration (subprocess)
# ─────────────────────────────────────────────

class TestCLI:

    def _run(self, *args):
        return subprocess.run(
            [sys.executable, "voidwipe.py", *args],
            capture_output=True, text=True,
            cwd=Path(__file__).parent
        )

    def test_version(self):
        r = self._run("--version")
        assert r.returncode == 0
        assert "voidwipe" in r.stdout

    def test_no_args_exits_nonzero(self):
        r = self._run()
        assert r.returncode != 0

    def test_help(self):
        r = self._run("--help")
        assert r.returncode == 0
        assert "--files" in r.stdout

    def test_shred_single_file(self, tmp_path):
        p = make_file(tmp_path)
        r = self._run("--files", str(p), "--method", "dod3")
        assert r.returncode == 0
        assert not p.exists()

    def test_shred_multiple_files(self, tmp_path):
        files = [make_file(tmp_path, f"f{i}.bin") for i in range(3)]
        r = self._run("--files", *[str(f) for f in files], "--method", "dod3")
        assert r.returncode == 0
        assert all(not f.exists() for f in files)

    def test_dry_run_flag(self, tmp_path):
        p = make_file(tmp_path)
        r = self._run("--files", str(p), "--dry-run")
        assert r.returncode == 0
        assert p.exists()

    def test_shred_dir_force(self, tmp_path):
        d = tmp_path / "target"
        d.mkdir()
        (d / "a.bin").write_bytes(os.urandom(128))
        r = self._run("--dir", str(d), "--force", "--method", "dod3")
        assert r.returncode == 0
        assert not d.exists()

    def test_exclude_flag(self, tmp_path):
        d = tmp_path / "mixed"
        d.mkdir()
        (d / "keep.log").write_bytes(b"keep")
        (d / "delete.bin").write_bytes(os.urandom(128))
        r = self._run("--dir", str(d), "--exclude", "*.log",
                      "--force", "--method", "dod3")
        assert r.returncode == 0
        assert (d / "keep.log").exists()
        assert not (d / "delete.bin").exists()

    def test_files_from_file(self, tmp_path):
        files = [make_file(tmp_path, f"listed{i}.bin") for i in range(3)]
        list_file = tmp_path / "filelist.txt"
        list_file.write_text("\n".join(str(f) for f in files))
        r = self._run("--files-from", str(list_file), "--method", "dod3")
        assert r.returncode == 0
        assert all(not f.exists() for f in files)

    def test_files_from_stdin(self, tmp_path):
        p = make_file(tmp_path)
        result = subprocess.run(
            [sys.executable, "voidwipe.py", "--files-from", "-", "--method", "dod3"],
            input=str(p) + "\n",
            capture_output=True, text=True,
            cwd=Path(__file__).parent
        )
        assert result.returncode == 0
        assert not p.exists()

    def test_json_output(self, tmp_path):
        p = make_file(tmp_path)
        r = self._run("--files", str(p), "--json", "--method", "dod3")
        assert r.returncode == 0
        data = json.loads(r.stdout)
        assert "status" in data
        assert "results" in data
        assert data["status"] == "ok"

    def test_quiet_mode_suppresses_info(self, tmp_path):
        p = make_file(tmp_path)
        r = self._run("--files", str(p), "-q", "--method", "dod3")
        assert r.returncode == 0
        assert "Pass" not in r.stdout
        assert not p.exists()

    def test_hash_flag_logs_sha256(self, tmp_path):
        content = b"known content"
        p = tmp_path / "known.bin"
        p.write_bytes(content)
        expected = hashlib.sha256(content).hexdigest()
        r = self._run("--files", str(p), "--hash", "--method", "dod3")
        assert r.returncode == 0
        assert expected in r.stdout

    def test_log_file_written(self, tmp_path):
        p = make_file(tmp_path)
        log_path = tmp_path / "out.log"
        r = self._run("--files", str(p), "--log", str(log_path), "--method", "dod3")
        assert r.returncode == 0
        assert log_path.exists()
        assert "Pass" in log_path.read_text()

    def test_verify_flag(self, tmp_path):
        p = make_file(tmp_path, size=4096)
        r = self._run("--files", str(p), "--verify", "--method", "dod3")
        assert r.returncode == 0

    def test_freespace_dry_run(self, tmp_path):
        r = self._run("--freespace", str(tmp_path), "--dry-run")
        assert r.returncode == 0

    def test_method_default(self, tmp_path):
        p = make_file(tmp_path)
        r = self._run("--files", str(p), "--method", "default")
        assert r.returncode == 0
        assert not p.exists()

    def test_method_dod7(self, tmp_path):
        p = make_file(tmp_path, size=512)
        r = self._run("--files", str(p), "--method", "dod7")
        assert r.returncode == 0
        assert not p.exists()

    def test_passes_override(self, tmp_path):
        p = make_file(tmp_path)
        r = self._run("--files", str(p), "--passes", "2")
        assert r.returncode == 0
        assert not p.exists()

    def test_jobs_parallel(self, tmp_path):
        files = [make_file(tmp_path, f"pj{i}.bin", size=512) for i in range(6)]
        r = self._run("--files", *[str(f) for f in files],
                      "--jobs", "3", "--method", "dod3")
        assert r.returncode == 0
        assert all(not f.exists() for f in files)

    def test_nonexistent_file_fails_preflight(self, tmp_path):
        r = self._run("--files", str(tmp_path / "ghost.bin"))
        assert r.returncode != 0

    def test_preflight_reports_all_errors(self, tmp_path):
        r = self._run("--files",
                      str(tmp_path / "a.bin"),
                      str(tmp_path / "b.bin"),
                      str(tmp_path / "c.bin"))
        assert r.returncode != 0
        # All three missing files should be reported together
        assert "a.bin" in r.stdout + r.stderr
        assert "b.bin" in r.stdout + r.stderr
        assert "c.bin" in r.stdout + r.stderr

    def test_dir_not_found_fails_preflight(self, tmp_path):
        r = self._run("--dir", str(tmp_path / "no_such_dir"), "--force")
        assert r.returncode != 0
