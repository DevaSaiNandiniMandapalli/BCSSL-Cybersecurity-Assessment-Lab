"""Shared pytest fixtures.

Tests never contact any network target other than the loopback interface, and
never run a real security scan. Parser tests consume fixture files; runner tests
use a stub executable created in a temporary directory.
"""

from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bcssl.config import DEFAULT_CONFIG, LabConfig  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture()
def config(tmp_path: Path) -> LabConfig:
    """A lab configuration whose authorized target is loopback only.

    ``$BCSSL_OUTPUT_ROOT`` points at a temporary directory so tests never write
    into the real reports/, evidence/ or state/ directories. Lab content
    (configuration, exercises) still resolves from the project itself.
    """
    import os

    previous = os.environ.get("BCSSL_OUTPUT_ROOT")
    os.environ["BCSSL_OUTPUT_ROOT"] = str(tmp_path)
    try:
        yield LabConfig(data=copy.deepcopy(DEFAULT_CONFIG), source=None)
    finally:
        if previous is None:
            os.environ.pop("BCSSL_OUTPUT_ROOT", None)
        else:
            os.environ["BCSSL_OUTPUT_ROOT"] = previous


@pytest.fixture(autouse=True)
def isolated_output(tmp_path_factory):
    """Redirect writable output for every test.

    Without this, a test that runs the CLI would read or write the real
    reports/, evidence/ and state/ directories of the lab project.
    """
    import os

    directory = tmp_path_factory.mktemp("bcssl-output")
    previous = os.environ.get("BCSSL_OUTPUT_ROOT")
    os.environ["BCSSL_OUTPUT_ROOT"] = str(directory)
    try:
        yield directory
    finally:
        if previous is None:
            os.environ.pop("BCSSL_OUTPUT_ROOT", None)
        else:
            os.environ["BCSSL_OUTPUT_ROOT"] = previous


@pytest.fixture()
def fixture_text():
    def _read(name: str) -> str:
        return (FIXTURES / name).read_text(encoding="utf-8")

    return _read
