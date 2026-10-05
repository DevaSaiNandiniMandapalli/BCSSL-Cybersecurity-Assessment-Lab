"""Exercise registry.

Exercises are content, not code: each one lives in
``lab/<level>/<id>/exercise.json`` with a human-readable ``exercise.md`` beside
it. This module loads and validates them so the CLI and the web dashboard can
render the same material without duplicating it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .. import paths
from ..models import read_json

LEVELS: tuple[str, ...] = ("beginner", "intermediate", "advanced")

REQUIRED_KEYS: tuple[str, ...] = (
    "id",
    "level",
    "title",
    "tool",
    "objective",
    "authorized_target",
    "prerequisites",
    "command",
    "expected_observation",
    "student_task",
    "evidence_requirement",
    "questions",
    "safety_note",
    "checklist",
)


class ExerciseError(RuntimeError):
    """Raised when exercise content is missing or malformed."""


@dataclass
class Exercise:
    """A single lab exercise."""

    id: str
    level: str
    title: str
    tool: str
    objective: str
    authorized_target: str
    prerequisites: list[str]
    command: str
    expected_observation: str
    student_task: list[str]
    evidence_requirement: list[str]
    questions: list[dict[str, str]]
    safety_note: str
    checklist: list[dict[str, str]]
    path: Path
    markdown_path: Path | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def question_ids(self) -> list[str]:
        return [str(item.get("id", "")) for item in self.questions if item.get("id")]

    @property
    def checklist_ids(self) -> list[str]:
        return [str(item.get("id", "")) for item in self.checklist if item.get("id")]

    @property
    def step(self) -> int:
        """Numeric step derived from the exercise id (``ex07`` -> 7)."""
        digits = "".join(char for char in self.id if char.isdigit())
        return int(digits) if digits else 0

    @property
    def markdown(self) -> str:
        if self.markdown_path and self.markdown_path.is_file():
            return self.markdown_path.read_text(encoding="utf-8")
        return ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "level": self.level,
            "title": self.title,
            "tool": self.tool,
            "objective": self.objective,
            "authorized_target": self.authorized_target,
            "prerequisites": self.prerequisites,
            "command": self.command,
            "expected_observation": self.expected_observation,
            "student_task": self.student_task,
            "evidence_requirement": self.evidence_requirement,
            "questions": self.questions,
            "safety_note": self.safety_note,
            "checklist": self.checklist,
            "markdown_path": (
                paths.relative_to_root(self.markdown_path) if self.markdown_path else ""
            ),
            "json_path": paths.relative_to_root(self.path),
        }


def _validate(data: dict[str, Any], path: Path) -> None:
    missing = [key for key in REQUIRED_KEYS if key not in data]
    if missing:
        raise ExerciseError(
            f"{path} is missing required key(s): {', '.join(missing)}"
        )
    for key in ("prerequisites", "student_task", "evidence_requirement"):
        if not isinstance(data[key], list):
            raise ExerciseError(f"{path}: '{key}' must be a list")
    for key in ("questions", "checklist"):
        if not isinstance(data[key], list) or not data[key]:
            raise ExerciseError(f"{path}: '{key}' must be a non-empty list")
        for item in data[key]:
            if not isinstance(item, dict) or "id" not in item:
                raise ExerciseError(f"{path}: every '{key}' entry needs an 'id'")


def load_exercise(level: str, exercise_id: str) -> Exercise:
    """Load a single exercise by level and id."""
    directory = paths.exercise_dir(level, exercise_id)
    json_path = directory / "exercise.json"
    if not json_path.is_file():
        raise ExerciseError(f"exercise not found: {paths.relative_to_root(json_path)}")
    data = read_json(json_path)
    if not isinstance(data, dict):
        raise ExerciseError(f"{json_path} is not valid JSON")
    _validate(data, json_path)
    return _to_exercise(data, json_path)


def _to_exercise(data: dict[str, Any], json_path: Path) -> Exercise:
    markdown_path = json_path.with_name("exercise.md")
    return Exercise(
        id=str(data["id"]),
        level=str(data["level"]),
        title=str(data["title"]),
        tool=str(data["tool"]),
        objective=str(data["objective"]),
        authorized_target=str(data["authorized_target"]),
        prerequisites=[str(item) for item in data["prerequisites"]],
        command=str(data["command"]),
        expected_observation=str(data["expected_observation"]),
        student_task=[str(item) for item in data["student_task"]],
        evidence_requirement=[str(item) for item in data["evidence_requirement"]],
        questions=[dict(item) for item in data["questions"]],
        safety_note=str(data["safety_note"]),
        checklist=[dict(item) for item in data["checklist"]],
        path=json_path,
        markdown_path=markdown_path if markdown_path.is_file() else None,
        raw=data,
    )


def load_all(levels: tuple[str, ...] = LEVELS) -> list[Exercise]:
    """Load every exercise, ordered by level then step.

    Malformed exercise files raise :class:`ExerciseError` rather than being
    silently skipped: a broken exercise should be visible, not invisible.
    """
    exercises: list[Exercise] = []
    for level in levels:
        base = paths.lab_dir(level)
        if not base.is_dir():
            continue
        for directory in sorted(base.iterdir()):
            json_path = directory / "exercise.json"
            if not json_path.is_file():
                continue
            data = read_json(json_path)
            if not isinstance(data, dict):
                raise ExerciseError(f"{json_path} is not valid JSON")
            _validate(data, json_path)
            exercises.append(_to_exercise(data, json_path))
    order = {level: index for index, level in enumerate(levels)}
    exercises.sort(key=lambda ex: (order.get(ex.level, 99), ex.step))
    return exercises


def exercises_by_level(
    exercises: list[Exercise],
) -> dict[str, list[Exercise]]:
    grouped: dict[str, list[Exercise]] = {level: [] for level in LEVELS}
    for exercise in exercises:
        grouped.setdefault(exercise.level, []).append(exercise)
    return grouped
