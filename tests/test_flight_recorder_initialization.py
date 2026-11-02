"""Initialization must preserve records committed by another creator."""
import builtins
import pathlib
import sys
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from receipt_lib import FlightRecorder  # noqa: E402


def test_interleaved_creator_cannot_truncate_committed_record(tmp_path):
    path = tmp_path / "flight.bin"
    receipt = {"action_id": "other-creator", "evidence": "synthetic"}
    real_open = builtins.open
    interleaved = False
    committed = None

    def open_after_other_creator(file, *args, **kwargs):
        nonlocal interleaved, committed
        if pathlib.Path(file) == path and not interleaved:
            # Pause the first constructor immediately before its open. A second
            # creator completes initialization and a locally ACKed append.
            interleaved = True
            recorder = FlightRecorder(path)
            ack = recorder.append(receipt)
            assert ack["durability"] == "LOCAL_ACK"
            committed = path.read_bytes()
        return real_open(file, *args, **kwargs)

    with mock.patch("builtins.open", side_effect=open_after_other_creator):
        recorder = FlightRecorder(path)

    assert interleaved
    assert path.read_bytes() == committed
    assert recorder.read_all() == [receipt]


def test_existing_empty_file_is_initialized_before_append(tmp_path):
    path = tmp_path / "flight.bin"
    path.touch()
    recorder = FlightRecorder(path)
    receipt = {"action_id": "empty-control"}
    ack = recorder.append(receipt)
    assert ack["durability"] == "LOCAL_ACK"
    assert recorder.read_all() == [receipt]


def test_reopening_preserves_header_and_existing_bytes(tmp_path):
    path = tmp_path / "flight.bin"
    first = {"action_id": "first"}
    second = {"action_id": "second"}
    recorder = FlightRecorder(path)
    recorder.append(first)
    before = path.read_bytes()
    reopened = FlightRecorder(path)
    assert path.read_bytes() == before
    reopened.append(second)
    assert reopened.read_all() == [first, second]
    assert path.read_bytes().count(FlightRecorder.MAGIC) == 1
