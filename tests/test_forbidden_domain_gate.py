"""Execute the forbidden-domain CI step against controlled trees.

The gate is release-blocking, so it must fail closed: a missing scanner or an
unreadable tree is an error, never an empty (passing) scan.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
# Assembled at runtime so this test file is not itself a scan hit.
DOMAIN = "a11oy" + ".com"


def scan_step() -> str:
    workflow = yaml.safe_load((ROOT / ".github/workflows/forbidden-domain.yml").read_text())
    return next(step for step in workflow["jobs"]["scan"]["steps"]
                if step.get("name", "").startswith("Scan for forbidden"))["run"]


def run_gate(cwd: Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    # The same shell flags GitHub uses for `shell: bash`.
    return subprocess.run(["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", scan_step()],
                          cwd=cwd, env=env or dict(os.environ), text=True, capture_output=True, check=False)


def tracked_tree(root: Path, files: dict[str, str | bytes]) -> Path:
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
    return root


def stub_path(tmp_path: Path, name: str, status: int) -> dict[str, str]:
    bin_dir = tmp_path / "stub-bin"
    bin_dir.mkdir()
    stub = bin_dir / name
    stub.write_text(f"#!/bin/bash\nexit {status}\n")
    stub.chmod(0o700)
    return {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}"}


def test_canonical_domains_pass(tmp_path):
    tree = tracked_tree(tmp_path / "repo", {"README.md": "Product a-11-oy.com; proof a11oy.net.\n"})
    result = run_gate(tree)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "OK: scanned 1 tracked text files; 0 reference(s)" in result.stdout


def test_violation_fails_and_names_the_line(tmp_path):
    tree = tracked_tree(tmp_path / "repo", {"docs/page.md": f"intro\nSee {DOMAIN} for details\n"})
    result = run_gate(tree)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "::error::Forbidden domain references found" in result.stdout
    assert f"docs/page.md:2:See {DOMAIN} for details" in result.stdout


def test_guard_context_on_the_same_line_passes(tmp_path):
    tree = tracked_tree(tmp_path / "repo", {"docs/page.md": f"**Never:** {DOMAIN}.\n"})
    result = run_gate(tree)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "1 reference(s), all in guard contexts" in result.stdout


def test_guard_word_in_the_file_path_does_not_exempt_the_line(tmp_path):
    tree = tracked_tree(tmp_path / "repo", {"docs/forbidden-blocklist-notes.md": f"Visit {DOMAIN}\n"})
    result = run_gate(tree)
    assert result.returncode == 1, result.stdout + result.stderr


def test_only_unguarded_lines_are_reported(tmp_path):
    tree = tracked_tree(tmp_path / "repo", {
        "a.md": f"Never use {DOMAIN}.\n",
        "b.md": f"Contact us at {DOMAIN}\n",
    })
    result = run_gate(tree)
    assert result.returncode == 1
    assert f"b.md:1:Contact us at {DOMAIN}" in result.stdout
    assert "a.md:1" not in result.stdout


def test_hyphenated_lookalike_is_not_a_hit(tmp_path):
    tree = tracked_tree(tmp_path / "repo", {"a.md": "mirror at x-" + DOMAIN + "\n"})
    result = run_gate(tree)
    assert result.returncode == 0, result.stdout + result.stderr


def test_binary_files_are_skipped(tmp_path):
    tree = tracked_tree(tmp_path / "repo", {"blob.bin": b"\x00\x01" + DOMAIN.encode(), "a.md": "clean\n"})
    result = run_gate(tree)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "scanned 1 tracked text files" in result.stdout


def test_empty_tree_fails_closed(tmp_path):
    tree = tracked_tree(tmp_path / "repo", {})
    result = run_gate(tree)
    assert result.returncode == 1
    assert "refusing to pass an empty scan" in result.stdout


@pytest.mark.parametrize("tool,status", [("git", 2), ("git", 128), ("python3", 127)])
def test_scanner_failure_fails_closed(tmp_path, tool, status):
    # The previous `rg ... || true` scan printed OK when rg was missing.
    tree = tracked_tree(tmp_path / "repo", {"a.md": f"See {DOMAIN}\n"})
    result = run_gate(tree, env=stub_path(tmp_path, tool, status))
    assert result.returncode != 0, result.stdout + result.stderr
    assert "OK:" not in result.stdout


def test_this_repository_passes_its_own_gate():
    result = run_gate(ROOT)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.startswith("OK: scanned ")
