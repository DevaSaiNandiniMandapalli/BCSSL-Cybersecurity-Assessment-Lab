"""Student lab: exercise registry and progress tracking."""

from __future__ import annotations

from .exercises import Exercise, ExerciseError, LEVELS, load_all, load_exercise
from .progress import (
    Progress,
    ack_exercise,
    load_progress,
    overall_progress,
    reset_exercise,
    reset_progress,
)

__all__ = [
    "Exercise",
    "ExerciseError",
    "LEVELS",
    "Progress",
    "ack_exercise",
    "load_all",
    "load_exercise",
    "load_progress",
    "overall_progress",
    "reset_exercise",
    "reset_progress",
]
