"""Execute the CI report wrapper with controlled gate exit statuses."""
import os
from pathlib import Path
import subprocess

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]


def raise_step():
    workflow = yaml.safe_load((ROOT / ".github/workflows/gates.yml").read_text())
    return next(step for step in workflow["jobs"]["gates"]["steps"]
                if step.get("name", "").startswith("Raise gate"))


@pytest.mark.parametrize("gate_status,expected", [(0, 0), (2, 0), (1, 1), (3, 3), (127, 127)])
def test_report_only_handles_only_the_documented_commercial_block(tmp_path, gate_status, expected):
    executable = tmp_path / "python3"
    executable.write_text("#!/bin/bash\nexit \"$GATE_TEST_STATUS\"\n")
    executable.chmod(0o700)
    env = {**os.environ, "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"],
           "GATE_TEST_STATUS": str(gate_status)}
    result = subprocess.run(["bash", "-e", "-o", "pipefail", "-c", raise_step()["run"]],
                            env=env, cwd=ROOT, text=True, capture_output=True, check=False)
    assert result.returncode == expected, result.stdout + result.stderr
    if gate_status == 2:
        assert "report-only" in result.stdout
