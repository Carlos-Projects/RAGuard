"""Tests for RAGuard __main__ entry point."""

import subprocess
import sys
from pathlib import Path


def test_main_module_execution() -> None:
    """Test that the module can be executed with python -m raguard."""
    result = subprocess.run(
        [sys.executable, "-m", "raguard", "--help"],
        capture_output=True,
        text=True,
        cwd=str(Path(__file__).parent.parent),
    )
    assert result.returncode == 0
    assert "RAGuard" in result.stdout


def test_main_module_scan_help() -> None:
    """Test that scan help works via module execution."""
    result = subprocess.run(
        [sys.executable, "-m", "raguard", "scan", "--help"],
        capture_output=True,
        text=True,
        cwd=str(Path(__file__).parent.parent),
    )
    assert result.returncode == 0
    assert "Scan a RAG system" in result.stdout
