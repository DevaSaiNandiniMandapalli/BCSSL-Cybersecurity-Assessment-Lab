"""Exercise content integrity and student progress semantics.

The key rule: running a tool must never complete an exercise.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bcssl import paths
from bcssl.lab import exercises as exercise_module
from bcssl.lab import progress as progress_module

AUTHORIZED_TARGET = "http://localhost:3001"


# ---------------------------------------------------------------------------
# Exercise content
# ---------------------------------------------------------------------------

def passing_answers(exercise) -> dict:
    """One grading-satisfying answer per question (completion tests only)."""
    from bcssl.lab import quiz

    answers = {}
    for question in exercise.questions:
        kind = quiz.question_type(question)
        qid = str(question.get("id"))
        if kind == quiz.YES_NO:
            answers[qid] = "Yes, because the configuration authorises it."
        elif kind == quiz.NUMBER:
            exact = question.get("exact")
            if exact is None:
                answers[qid] = str(int(question.get("min_number", 0)) + 1)
            else:
                answers[qid] = str(exact)
        elif kind == quiz.LIST:
            answers[qid] = "\n".join("item %d" % i for i in range(1, 5))
        else:
            keywords = [str(k) for k in question.get("expected_keywords", [])] or ["answer"]
            answers[qid] = "My answer covers: " + ", ".join(keywords) + "."
    return answers

def test_twelve_exercises_load():
    exercises = exercise_module.load_all()
    assert len(exercises) == 12


def test_all_three_levels_present():
    exercises = exercise_module.load_all()
    grouped = exercise_module.exercises_by_level(exercises)
    assert len(grouped["beginner"]) == 4
    assert len(grouped["intermediate"]) == 4
    assert len(grouped["advanced"]) == 4


def test_exercises_are_ordered_by_level_then_step():
    exercises = exercise_module.load_all()
    levels = [ex.level for ex in exercises]
    assert levels == (
        ["beginner"] * 4 + ["intermediate"] * 4 + ["advanced"] * 4
    )
    steps = [ex.step for ex in exercises]
    assert steps == sorted(steps)


def test_every_exercise_has_required_content():
    for exercise in exercise_module.load_all():
        assert exercise.objective.strip()
        assert exercise.command.strip()
        assert exercise.expected_observation.strip()
        assert exercise.safety_note.strip()
        assert len(exercise.prerequisites) >= 1
        assert len(exercise.student_task) >= 1
        assert len(exercise.evidence_requirement) >= 1
        assert len(exercise.questions) >= 1
        assert len(exercise.checklist) >= 1


def test_every_exercise_targets_only_the_authorized_host():
    for exercise in exercise_module.load_all():
        assert exercise.authorized_target == AUTHORIZED_TARGET


def test_every_exercise_has_a_markdown_mirror():
    for exercise in exercise_module.load_all():
        assert exercise.markdown_path is not None, f"{exercise.id} has no exercise.md"
        text = exercise.markdown
        for heading in (
            "## Objective",
            "## Authorized Target",
            "## Prerequisites",
            "## Tool Used",
            "## Exact Command",
            "## Expected Observation",
            "## Student Task",
            "## Evidence Requirement",
            "## Questions",
            "## Safety Note",
            "## Completion Checklist",
        ):
            assert heading in text, f"{exercise.id} missing {heading}"


def test_no_exercise_mentions_a_non_loopback_target():
    """Safety regression guard for student-facing content."""
    import re

    pattern = re.compile(r"https?://(?!localhost|127\.0\.0\.1|\[::1\])[A-Za-z0-9.-]+")
    for exercise in exercise_module.load_all():
        assert not pattern.search(exercise.markdown), (
            f"{exercise.id} references a non-loopback host"
        )
        assert not pattern.search(exercise.command)


def test_exercise_commands_use_the_documented_cli():
    for exercise in exercise_module.load_all():
        assert exercise.command.startswith("python -m bcssl "), exercise.command


def test_question_and_checklist_ids_are_unique():
    for exercise in exercise_module.load_all():
        assert len(exercise.question_ids) == len(set(exercise.question_ids))
        assert len(exercise.checklist_ids) == len(set(exercise.checklist_ids))
        assert not set(exercise.question_ids) & set(exercise.checklist_ids)


def test_load_exercise_rejects_unknown_id():
    with pytest.raises(exercise_module.ExerciseError):
        exercise_module.load_exercise("beginner", "ex99")


def test_malformed_exercise_is_reported_not_skipped(tmp_path, monkeypatch):
    """A broken exercise file must be visible rather than silently ignored."""
    broken = tmp_path / "lab" / "beginner" / "ex01" / "exercise.json"
    broken.parent.mkdir(parents=True)
    broken.write_text(json.dumps({"id": "ex01", "title": "Incomplete"}), encoding="utf-8")
    monkeypatch.setattr(paths, "project_root", lambda: tmp_path)

    with pytest.raises(exercise_module.ExerciseError) as excinfo:
        exercise_module.load_all()
    assert "missing required key" in str(excinfo.value)


# ---------------------------------------------------------------------------
# Progress semantics
# ---------------------------------------------------------------------------
@pytest.fixture()
def exercise():
    return exercise_module.load_exercise("beginner", "ex01")


def test_new_progress_is_empty(config):
    progress = progress_module.load_progress()
    summary = progress.summary(exercise_module.load_all())
    assert summary["complete"] == 0
    assert summary["total"] == 12


def test_running_a_tool_does_not_complete_an_exercise(config):
    """The central rule: completion comes only from acknowledgement."""
    progress = progress_module.load_progress()
    exercise = exercise_module.load_exercise("beginner", "ex01")
    before = progress.status_for(exercise)
    assert before["complete"] is False
    assert before["started"] is False

    # Simulate a tool having run: no acknowledgement state is written.
    from bcssl.pipeline import results_from_index

    results_from_index()
    after = progress.status_for(exercise)
    assert after["complete"] is False
    assert after["started"] is False


def test_partial_acknowledgement_is_incomplete(config, exercise):
    progress = progress_module.load_progress()
    status = progress_module.ack_exercise(
        progress, "ex01", checks=[exercise.checklist_ids[0]]
    )
    assert status["complete"] is False
    assert status["started"] is True
    assert status["checks_done"] == 1


def test_full_acknowledgement_completes(config, exercise):
    progress = progress_module.load_progress()
    status = progress_module.ack_exercise(
        progress,
        "ex01",
        checks=exercise.checklist_ids,
        answers=passing_answers(exercise),
        evidence=["reports/raw/lab-cli/preflight.txt"],
    )
    assert status["complete"] is True
    assert status["checks_done"] == status["checks_total"]
    assert status["questions_answered"] == status["questions_total"]
    assert status["evidence_recorded"] is True


def test_all_questions_but_no_evidence_stays_incomplete(config, exercise):
    progress = progress_module.load_progress()
    status = progress_module.ack_exercise(
        progress,
        "ex01",
        checks=exercise.checklist_ids,
        answers={qid: "Answer." for qid in exercise.question_ids},
    )
    assert status["complete"] is False
    assert status["evidence_recorded"] is False


def test_all_checks_but_unanswered_questions_stays_incomplete(config, exercise):
    progress = progress_module.load_progress()
    status = progress_module.ack_exercise(
        progress,
        "ex01",
        checks=exercise.checklist_ids,
        evidence=["evidence/x.txt"],
    )
    assert status["complete"] is False
    assert status["questions_answered"] == 0


def test_gradable_question_must_be_answered_correctly(config):
    """Answering a gradable question wrongly must not complete the exercise."""
    from bcssl.lab import quiz

    exercise = exercise_module.load_exercise("beginner", "ex01")
    progress = progress_module.load_progress()

    question = next(
        q for q in exercise.questions if quiz.is_gradable(q)
    ) if any(quiz.is_gradable(q) for q in exercise.questions) else None
    if question is None:
        pytest.skip("exercise 1 has no gradable questions")

    wrong = "banana"
    assert quiz.grade(question, wrong).passed is False

    answers = passing_answers(exercise)
    answers[question["id"]] = wrong
    status = progress_module.ack_exercise(
        progress,
        "ex01",
        checks=exercise.checklist_ids,
        answers=answers,
        evidence=["evidence/x.txt"],
    )
    assert status["complete"] is False
    assert question["id"] in status["missing_answers"]


def test_empty_answer_is_refused(config, exercise):
    progress = progress_module.load_progress()
    with pytest.raises(ValueError):
        progress_module.ack_exercise(
            progress, "ex01", answers={exercise.question_ids[0]: "   "}
        )


def test_unknown_checklist_id_is_refused(config):
    progress = progress_module.load_progress()
    with pytest.raises(ValueError) as excinfo:
        progress_module.ack_exercise(progress, "ex01", checks=["c99"])
    assert "unknown checklist item" in str(excinfo.value)


def test_unknown_question_id_is_refused(config):
    progress = progress_module.load_progress()
    with pytest.raises(ValueError):
        progress_module.ack_exercise(progress, "ex01", answers={"q99": "hi"})


def test_unknown_exercise_is_refused(config):
    progress = progress_module.load_progress()
    with pytest.raises(exercise_module.ExerciseError):
        progress_module.ack_exercise(progress, "ex99", checks=["c1"])


def test_progress_persists_across_loads(config, exercise):
    progress = progress_module.load_progress()
    progress_module.ack_exercise(progress, "ex01", checks=[exercise.checklist_ids[0]])

    reloaded = progress_module.load_progress()
    assert reloaded.entries["ex01"].checks == [exercise.checklist_ids[0]]


def test_duplicate_acknowledgement_is_idempotent(config, exercise):
    progress = progress_module.load_progress()
    cid = exercise.checklist_ids[0]
    progress_module.ack_exercise(progress, "ex01", checks=[cid])
    status = progress_module.ack_exercise(progress, "ex01", checks=[cid])
    assert status["checks_done"] == 1


def test_reset_exercise_clears_only_that_exercise(config, exercise):
    progress = progress_module.load_progress()
    ex02 = exercise_module.load_exercise("beginner", "ex02")
    progress_module.ack_exercise(progress, "ex01", checks=[exercise.checklist_ids[0]])
    progress_module.ack_exercise(progress, "ex02", checks=[ex02.checklist_ids[0]])

    assert progress_module.reset_exercise(progress, "ex01") is True
    reloaded = progress_module.load_progress()
    assert "ex01" not in reloaded.entries
    assert "ex02" in reloaded.entries


def test_summary_percentages(config):
    progress = progress_module.load_progress()
    exercises = exercise_module.load_all()
    summary = progress.summary(exercises)
    assert summary["percent"] == 0.0
    assert set(summary["by_level"]) == {"beginner", "intermediate", "advanced"}
    for stats in summary["by_level"].values():
        assert stats["total"] == 4
