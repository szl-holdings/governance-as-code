"""CI installs only hash-locked closures that pin what users are told to install.

requirements.txt (and pyproject.toml) declare the runtime pins; the CI
workflows install requirements/ci/*.txt with --require-hashes. These checks keep
the declared pins, the .in sources and the compiled locks in step, so CI never
silently tests different versions than the ones the README installs.
"""
from __future__ import annotations

from pathlib import Path
import re
import tomllib

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / "requirements" / "ci"
PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;\\]+)")


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def pins(path: Path) -> dict[str, str]:
    out = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = PIN.match(line.strip())
        if match:
            out[norm(match.group(1))] = match.group(2)
    return out


def declared() -> dict[str, str]:
    return pins(ROOT / "requirements.txt")


def test_pyproject_dependencies_match_requirements_txt():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    from_pyproject = {}
    for requirement in project["dependencies"]:
        match = PIN.match(requirement)
        assert match, f"pyproject dependency is not an exact pin: {requirement}"
        from_pyproject[norm(match.group(1))] = match.group(2)
    assert from_pyproject == declared()


@pytest.mark.parametrize("lock,runtime", [
    ("base-python-ci", None),  # the base gate installs every runtime dependency
    ("gates", {"cryptography", "jsonschema", "pyyaml"}),
])
def test_in_files_pin_the_declared_runtime_versions(lock, runtime):
    source = pins(CI / f"{lock}.in")
    expected = declared() if runtime is None else {k: v for k, v in declared().items() if k in runtime}
    assert {k: source.get(k) for k in expected} == expected


@pytest.mark.parametrize("lock", ["base-python-ci", "gates"])
def test_compiled_lock_is_hashed_and_matches_its_source(lock):
    text = (CI / f"{lock}.txt").read_text(encoding="utf-8")
    locked = pins(CI / f"{lock}.txt")
    for name, version in pins(CI / f"{lock}.in").items():
        assert locked.get(name) == version, f"{lock}.txt is stale for {name}; recompile it from {lock}.in"
    for line in text.splitlines():
        if PIN.match(line.strip()):
            assert line.rstrip().endswith("\\"), f"unhashed requirement in {lock}.txt: {line}"
    assert text.count("--hash=sha256:") >= len(locked)
    unpinned = [line for line in (CI / f"{lock}.in").read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.startswith("#")]
    for line in unpinned:
        name = norm(re.split(r"[<>=!~;\s\[]", line.strip(), maxsplit=1)[0])
        assert name in locked, f"{name} from {lock}.in is missing from {lock}.txt"


@pytest.mark.parametrize("workflow,lock", [
    ("base-python-ci.yml", "base-python-ci"),
    ("gates.yml", "gates"),
])
def test_workflows_install_only_from_their_hashed_lock(workflow, lock):
    data = yaml.safe_load((ROOT / ".github" / "workflows" / workflow).read_text(encoding="utf-8"))
    runs = "\n".join(step.get("run", "") for job in data["jobs"].values() for step in job["steps"])
    installs = [line.strip() for line in runs.splitlines() if re.search(r"\bpip\s+install\b", line)]
    assert installs, f"{workflow} installs nothing"
    for line in installs:
        hashed = "--require-hashes" in line and f"requirements/ci/{lock}.txt" in line
        local_only = "--no-deps" in line and line.rstrip().endswith("-e .")
        assert hashed or local_only, f"{workflow} has an unhashed install: {line}"
