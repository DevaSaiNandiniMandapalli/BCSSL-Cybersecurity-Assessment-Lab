"""Artifact cleanup: only generated output is removed, never source."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bcssl import clean, paths


@pytest.fixture()
def populated(config):
    """Create the artifact layout the lab produces after a run."""
    run_dir = paths.raw_dir() / "nmap" / "nmap-20260101T000000Z"
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "stdout.txt").write_text("scan output", encoding="utf-8")
    (run_dir / "nmap.xml").write_text("<nmaprun/>", encoding="utf-8")

    paths.normalized_dir().mkdir(parents=True, exist_ok=True)
    (paths.normalized_dir() / "findings-nmap-1.json").write_text("{}", encoding="utf-8")

    paths.final_dir().mkdir(parents=True, exist_ok=True)
    (paths.final_dir() / "assessment-1.html").write_text("<html></html>", encoding="utf-8")

    evidence = paths.evidence_dir("nmap")
    evidence.mkdir(parents=True, exist_ok=True)
    (evidence / "finding-1.json").write_text(
        json.dumps({"raw_sha256": "abc"}), encoding="utf-8"
    )

    paths.state_dir().mkdir(parents=True, exist_ok=True)
    (paths.state_dir() / "run-index.json").write_text('{"runs":{}}', encoding="utf-8")

    # Seed the placeholders the shipped skeleton carries, so the test can prove
    # cleanup preserves them.
    for directory in (paths.raw_dir(), paths.normalized_dir(), paths.final_dir(), paths.state_dir()):
        Path(directory).mkdir(parents=True, exist_ok=True)
        (Path(directory) / ".gitkeep").touch()
    return config


# ---------------------------------------------------------------------------
def test_clean_removes_generated_artifacts(populated):
    result = clean.clean()
    assert result.removed_files >= 5
    assert result.areas


def test_clean_empties_the_artifact_directories(populated):
    clean.clean()
    for directory in (
        paths.raw_dir(),
        paths.normalized_dir(),
        paths.final_dir(),
        paths.state_dir(),
    ):
        leftovers = [
            item
            for item in Path(directory).rglob("*")
            if item.is_file() and item.name != ".gitkeep"
        ]
        assert not leftovers, f"{directory} still holds {leftovers}"


def test_clean_preserves_gitkeep(populated):
    clean.clean()
    for directory in (paths.raw_dir(), paths.state_dir()):
        keeps = list(Path(directory).rglob(".gitkeep"))
        assert keeps, f"{directory} lost its .gitkeep placeholder"


def test_clean_never_touches_source(populated):
    """The engine, configuration and exercises must survive untouched."""
    protected = [
        paths.project_root() / "bcssl" / "target.py",
        paths.project_root() / "config" / "lab-config.json",
        paths.project_root() / "lab" / "beginner" / "ex01" / "exercise.json",
        paths.project_root() / "README.md",
    ]
    before = {path: (path.exists(), path.stat().st_mtime if path.exists() else 0) for path in protected}
    clean.clean()
    for path, (existed, mtime) in before.items():
        assert path.exists() == existed
        if existed:
            assert path.stat().st_mtime == mtime, f"{path} was modified by clean"


def test_clean_can_keep_evidence(populated):
    clean.clean(keep_evidence=True)
    records = list(paths.evidence_dir("nmap").rglob("*.json"))
    assert records, "evidence must survive when keep_evidence is set"


def test_clean_can_keep_progress(populated):
    clean.clean(keep_progress=True)
    assert (paths.state_dir() / "run-index.json").exists()


def test_clean_dry_run_removes_nothing(populated):
    before = sorted(str(p) for p in paths.raw_dir().rglob("*"))
    result = clean.clean(dry_run=True)
    after = sorted(str(p) for p in paths.raw_dir().rglob("*"))
    assert before == after, "a dry run must not delete anything"
    assert result.removed_files > 0, "a dry run should still report the count"
    assert result.dry_run is True
    assert (paths.raw_dir() / "nmap" / "nmap-20260101T000000Z" / "stdout.txt").exists()


def test_clean_is_safe_to_repeat(populated):
    clean.clean()
    second = clean.clean()
    assert second.removed_files == 0


def test_clean_reports_freed_bytes(populated):
    result = clean.clean()
    assert result.freed_bytes > 0


def test_clean_output_is_json_serialisable(populated):
    payload = clean.clean(dry_run=True).to_dict()
    assert json.loads(json.dumps(payload))
