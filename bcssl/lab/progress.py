"""Student progress tracking.

An exercise is complete only when the student has, themselves:

* ticked every checklist item,
* answered every question, and
* recorded at least one evidence reference.

Running a tool never advances progress. ``acknowledge`` is the only function
that writes completion state, and it can only record work the student asserts -
it cannot infer that a scan happened or that the student read the output.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

from .. import paths
from ..models import read_json, utc_now_iso, write_json
from . import quiz
from .exercises import Exercise, load_all, load_exercise

VERSION = 1


@dataclass
class ExerciseProgress:
    """Acknowledgements recorded for one exercise."""

    exercise_id: str
    checks: list[str] = field(default_factory=list)
    answers: dict[str, str] = field(default_factory=dict)
    evidence: list[str] = field(default_factory=list)
    started_at: str = ""
    completed_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "exercise_id": self.exercise_id,
            "checks": list(self.checks),
            "answers": dict(self.answers),
            "evidence": list(self.evidence),
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }


@dataclass
class Progress:
    """All recorded progress plus derived completion state."""

    entries: dict[str, ExerciseProgress] = field(default_factory=dict)

    # -- persistence -------------------------------------------------------
    @classmethod
    def load(cls) -> "Progress":
        data = read_json(paths.progress_file(), default={}) or {}
        entries: dict[str, ExerciseProgress] = {}
        raw_entries = data.get("exercises", {}) if isinstance(data, dict) else {}
        if isinstance(raw_entries, dict):
            for exercise_id, value in raw_entries.items():
                if not isinstance(value, dict):
                    continue
                entries[exercise_id] = ExerciseProgress(
                    exercise_id=exercise_id,
                    checks=[str(item) for item in value.get("checks", [])],
                    answers={
                        str(k): str(v) for k, v in (value.get("answers") or {}).items()
                    },
                    evidence=[str(item) for item in value.get("evidence", [])],
                    started_at=str(value.get("started_at", "")),
                    completed_at=str(value.get("completed_at", "")),
                )
        return cls(entries=entries)

    def save(self) -> None:
        payload = {
            "version": VERSION,
            "updated_at": utc_now_iso(),
            "exercises": {
                key: value.to_dict() for key, value in self.entries.items()
            },
        }
        write_json(paths.progress_file(), payload)

    # -- state -------------------------------------------------------------
    def entry(self, exercise_id: str) -> ExerciseProgress:
        if exercise_id not in self.entries:
            self.entries[exercise_id] = ExerciseProgress(exercise_id=exercise_id)
        return self.entries[exercise_id]

    def status_for(self, exercise: Exercise) -> dict[str, Any]:
        """Derive completion for *exercise* without mutating stored state.

        Completion requires every checklist item ticked, every gradable question
        answered *correctly*, and at least one evidence reference. A tool run on
        its own never contributes to progress.
        """
        entry = self.entries.get(exercise.id)
        checks = set(entry.checks) if entry else set()
        answers = entry.answers if entry else {}
        evidence = entry.evidence if entry else []

        missing_checks = [cid for cid in exercise.checklist_ids if cid not in checks]

        missing_answers: list[str] = []
        unanswered: list[str] = []
        needs_review: list[str] = []
        graded_questions = [q for q in exercise.questions if quiz.is_gradable(q)]
        passed_count = 0
        for question in exercise.questions:
            qid = str(question.get("id", ""))
            answer = answers.get(qid, "")
            if not str(answer).strip():
                # Every question blocks completion, gradable or not: a student
                # must actually answer all of them.
                unanswered.append(qid)
                missing_answers.append(qid)
                continue
            result = quiz.grade(question, answer)
            if result.needs_review:
                needs_review.append(qid)
                passed_count += 1
            elif result.passed:
                passed_count += 1
            else:
                missing_answers.append(qid)

        missing_evidence = not [item for item in evidence if str(item).strip()]

        complete = not missing_checks and not missing_answers and not missing_evidence
        total_items = len(exercise.checklist_ids) + len(exercise.question_ids) + 1
        done_items = (
            (len(exercise.checklist_ids) - len(missing_checks))
            + passed_count
            + (0 if missing_evidence else 1)
        )

        return {
            "id": exercise.id,
            "level": exercise.level,
            "title": exercise.title,
            "tool": exercise.tool,
            "command": exercise.command,
            "started": bool(entry and (entry.checks or entry.answers or entry.evidence)),
            "complete": complete,
            "checks_total": len(exercise.checklist_ids),
            "checks_done": len(exercise.checklist_ids) - len(missing_checks),
            "missing_checks": missing_checks,
            "questions_total": len(exercise.question_ids),
            "questions_answered": len(exercise.question_ids) - len(unanswered),
            "questions_passed": passed_count,
            "gradable_questions": len(graded_questions),
            "missing_answers": missing_answers,
            "unanswered_questions": unanswered,
            "needs_instructor_review": needs_review,
            "evidence_recorded": not missing_evidence,
            "evidence": list(evidence),
            "percent": round(done_items / total_items * 100, 1) if total_items else 0.0,
            "completed_at": entry.completed_at if entry else "",
        }

    def badges(self, exercises: Iterable[Exercise]) -> list[dict[str, Any]]:
        """Achievement badges earned from the recorded progress."""
        items = list(exercises)
        statuses = [self.status_for(exercise) for exercise in items]
        by_level = {status["level"]: status for status in statuses}
        levels = {
            level: [s for s in statuses if s["level"] == level] for level in
            ("beginner", "intermediate", "advanced")
        }
        complete_levels = [
            level for level, group in levels.items()
            if group and all(s["complete"] for s in group)
        ]
        total_complete = sum(1 for s in statuses if s["complete"])
        evidenced = sum(1 for s in statuses if s["evidence_recorded"])
        questioned = sum(s["questions_answered"] for s in statuses)

        earned: list[dict[str, Any]] = []
        if evidenced:
            earned.append({
                "id": "first-evidence",
                "name": "Evidence Keeper",
                "detail": f"Recorded evidence for {evidenced} exercise(s).",
            })
        if questioned:
            earned.append({
                "id": "first-answer",
                "name": "Analyst",
                "detail": f"Answered {questioned} question(s).",
            })
        for level in complete_levels:
            earned.append({
                "id": f"level-{level}",
                "name": f"{level.title()} Complete",
                "detail": f"All four {level} exercises completed.",
            })
        if total_complete == len(items) and items:
            earned.append({
                "id": "lab-complete",
                "name": "Lab Graduate",
                "detail": "All twelve exercises completed with evidence and passing answers.",
            })
        return earned

    def summary(self, exercises: Iterable[Exercise]) -> dict[str, Any]:
        items = list(exercises)
        statuses = [self.status_for(exercise) for exercise in items]
        by_level: dict[str, dict[str, Any]] = {}
        for status in statuses:
            level = by_level.setdefault(
                status["level"], {"total": 0, "complete": 0, "in_progress": 0}
            )
            level["total"] += 1
            if status["complete"]:
                level["complete"] += 1
            elif status["started"]:
                level["in_progress"] += 1
        for level in by_level.values():
            level["percent"] = (
                round(level["complete"] / level["total"] * 100, 1)
                if level["total"]
                else 0.0
            )
        total = len(statuses)
        complete = sum(1 for status in statuses if status["complete"])
        return {
            "total": total,
            "complete": complete,
            "in_progress": sum(1 for status in statuses if status["started"] and not status["complete"]),
            "percent": round(complete / total * 100, 1) if total else 0.0,
            "by_level": by_level,
        }


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------
def load_progress() -> Progress:
    return Progress.load()


def ack_exercise(
    progress: Progress,
    exercise_id: str,
    *,
    checks: Iterable[str] = (),
    answers: dict[str, str] | None = None,
    evidence: Iterable[str] = (),
    level: str | None = None,
) -> dict[str, Any]:
    """Record student acknowledgements for one exercise.

    Raises:
        ExerciseError: when the exercise does not exist.
        ValueError: when an unknown checklist id, question id or level is given.
    """
    from .exercises import LEVELS, ExerciseError

    resolved_level = level
    if resolved_level is None:
        for candidate in LEVELS:
            try:
                load_exercise(candidate, exercise_id)
            except ExerciseError:
                continue
            resolved_level = candidate
            break
    if resolved_level is None:
        raise ExerciseError(f"exercise '{exercise_id}' was not found in the lab")

    exercise = load_exercise(resolved_level, exercise_id)
    entry = progress.entry(exercise_id)
    if not entry.started_at:
        entry.started_at = utc_now_iso()

    valid_checks = set(exercise.checklist_ids)
    for check in checks:
        check = str(check).strip()
        if not check:
            continue
        if check not in valid_checks:
            raise ValueError(
                f"unknown checklist item '{check}' for {exercise_id}; "
                f"valid items: {', '.join(sorted(valid_checks))}"
            )
        if check not in entry.checks:
            entry.checks.append(check)

    valid_questions = set(exercise.question_ids)
    for question_id, text in (answers or {}).items():
        question_id = str(question_id).strip()
        if question_id not in valid_questions:
            raise ValueError(
                f"unknown question '{question_id}' for {exercise_id}; "
                f"valid questions: {', '.join(sorted(valid_questions))}"
            )
        cleaned = str(text).strip()
        if not cleaned:
            raise ValueError(
                f"answer for {question_id} is empty; write your answer in your "
                "own words"
            )
        entry.answers[question_id] = cleaned

    for item in evidence:
        cleaned = str(item).strip()
        if cleaned and cleaned not in entry.evidence:
            entry.evidence.append(cleaned)

    status = progress.status_for(exercise)
    if status["complete"] and not entry.completed_at:
        entry.completed_at = utc_now_iso()

    progress.save()
    return status


def reset_exercise(progress: Progress, exercise_id: str) -> bool:
    """Clear acknowledgements for one exercise."""
    if exercise_id not in progress.entries:
        return False
    del progress.entries[exercise_id]
    progress.save()
    return True


def reset_progress() -> None:
    """Remove all recorded progress."""
    path = paths.progress_file()
    if path.is_file():
        path.unlink()


def overall_progress() -> dict[str, Any]:
    """Convenience helper returning the full progress summary."""
    progress = load_progress()
    return progress.summary(load_all())
