"""Subprocess tests for the password_checker CLI (``python -m password_checker``)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "password_checker", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


def test_cli_help_exits_zero() -> None:
    proc = _run_cli("--help")
    assert proc.returncode == 0
    assert "password" in proc.stdout.lower() or "password" in proc.stderr.lower()


def test_cli_weak_password_exits_one() -> None:
    proc = _run_cli("-p", "password")
    assert proc.returncode == 1
    assert "Weak" in proc.stdout or "Terrible" in proc.stdout


def test_cli_strong_password_exits_zero() -> None:
    # Avoid ``$`` in the literal so PowerShell-friendly invocation matches bash.
    secret = "xK9#mQ2+vL5nR8wP1zT7jH4sD6fG0aB"
    proc = _run_cli("-p", secret)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_cli_missing_file_exits_two() -> None:
    missing = ROOT / "nonexistent_passwords_file_xyz.txt"
    proc = _run_cli("-f", str(missing))
    assert proc.returncode == 2
    assert "cannot read" in proc.stderr.lower() or "password_checker:" in proc.stderr


def test_cli_min_length_zero_exits_two() -> None:
    proc = _run_cli("-p", "x", "--min-length", "0")
    assert proc.returncode == 2
    assert "min-length" in proc.stderr.lower()


def test_cli_export_json(tmp_path: Path) -> None:
    out_path = tmp_path / "report.json"
    proc = _run_cli("-p", "a", "--export", str(out_path))
    assert proc.returncode in (0, 1)
    assert out_path.is_file()
    data = json.loads(out_path.read_text(encoding="utf-8"))
    assert "analyses" in data
    assert data["module_name"] == "audit"
