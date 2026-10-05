"""Question grading and answer-key protection."""

from __future__ import annotations

import pytest

from bcssl.lab import quiz


# ---------------------------------------------------------------------------
# Answer keys must never leak
# ---------------------------------------------------------------------------
def test_student_view_removes_every_answer_key_field():
    question = {
        "id": "q1",
        "question": "Which header is missing?",
        "guidance": "Name the header",
        "type": "keyword",
        "expected_keywords": ["content-security-policy"],
        "any_keywords": ["csp"],
        "min_keywords": 1,
        "min_items": 3,
        "min_number": 1,
        "max_number": 2,
        "exact": 3001,
        "accepted_answers": ["yes"],
    }
    view = quiz.student_view(question)
    for hidden in quiz._KEY_FIELDS:
        assert hidden not in view, f"{hidden} must not be shown to a student"
    assert view["id"] == "q1"
    assert view["question"] == question["question"]
    assert view["gradable"] is True
    assert "guidance" not in view


def test_student_view_marks_freeform_as_not_gradable():
    view = quiz.student_view({"id": "q2", "question": "Explain.", "type": "freeform"})
    assert view["gradable"] is False


# ---------------------------------------------------------------------------
# Type detection
# ---------------------------------------------------------------------------
def test_question_type_defaults_to_freeform():
    assert quiz.question_type({"id": "q1"}) == quiz.FREEFORM


def test_keywords_imply_keyword_type():
    assert quiz.question_type({"expected_keywords": ["x"]}) == quiz.KEYWORD


def test_is_gradable():
    assert quiz.is_gradable({"type": "yes_no"})
    assert not quiz.is_gradable({"type": "freeform"})
    assert not quiz.is_gradable({"question": "no spec"})


# ---------------------------------------------------------------------------
# yes/no
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("answer", ["yes", "Y", "true", "Yes, because it is absent."])
def test_yes_no_accepts_affirmative(answer):
    result = quiz.grade({"id": "q1", "type": "yes_no"}, answer)
    assert result.passed is True


@pytest.mark.parametrize("answer", ["no", "N", "false", "No, it is present."])
def test_yes_no_accepts_negative(answer):
    assert quiz.grade({"id": "q1", "type": "yes_no"}, answer).passed is True


def test_yes_no_rejects_non_answer():
    result = quiz.grade({"id": "q1", "type": "yes_no"}, "banana")
    assert result.passed is False


# ---------------------------------------------------------------------------
# keyword / keywords
# ---------------------------------------------------------------------------
def test_keyword_match_is_case_insensitive_substring():
    question = {"id": "q1", "type": "keyword", "expected_keywords": ["content-security-policy"]}
    assert quiz.grade(question, "The Content-Security-Policy header is missing.").passed


def test_keyword_accepts_alternatives():
    question = {"id": "q1", "type": "keyword", "expected_keywords": ["content-security-policy", "csp"]}
    assert quiz.grade(question, "CSP is absent.").passed


def test_keyword_rejects_wrong_answer():
    question = {"id": "q1", "type": "keyword", "expected_keywords": ["content-security-policy"]}
    result = quiz.grade(question, "banana")
    assert result.passed is False
    assert "technical term" in result.feedback


def test_keywords_requires_the_minimum():
    question = {
        "id": "q1",
        "type": "keywords",
        "expected_keywords": ["csp", "hsts", "nosniff", "x-frame-options"],
        "min_keywords": 3,
    }
    assert quiz.grade(question, "csp hsts nosniff are all missing").passed
    partial = quiz.grade(question, "only csp is missing")
    assert partial.passed is False
    assert len(partial.matched) == 1


# ---------------------------------------------------------------------------
# number
# ---------------------------------------------------------------------------
def test_number_exact_match():
    assert quiz.grade({"id": "q1", "type": "number", "exact": 3001}, "3001").passed
    assert not quiz.grade({"id": "q1", "type": "number", "exact": 3001}, "8080").passed


def test_number_range():
    question = {"id": "q1", "type": "number", "min_number": 1, "max_number": 65535}
    assert quiz.grade(question, "443").passed
    assert not quiz.grade(question, "70000").passed


def test_number_requires_a_number():
    assert not quiz.grade({"id": "q1", "type": "number", "exact": 3001}, "no idea").passed


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------
def test_list_requires_enough_items():
    question = {"id": "q1", "type": "list", "min_items": 3}
    assert quiz.grade(question, "a\nb\nc").passed
    assert not quiz.grade(question, "a, b").passed


def test_list_accepts_separators():
    assert quiz.grade({"id": "q1", "type": "list", "min_items": 3}, "a; b, c").passed


# ---------------------------------------------------------------------------
# freeform + empty
# ---------------------------------------------------------------------------
def test_freeform_is_recorded_for_review():
    result = quiz.grade({"id": "q1", "type": "freeform"}, "My own explanation.")
    assert result.passed is True
    assert result.needs_review is True


def test_empty_answer_never_passes():
    for kind in (quiz.YES_NO, quiz.KEYWORD, quiz.NUMBER, quiz.LIST, quiz.FREEFORM):
        result = quiz.grade({"id": "q1", "type": kind, "expected_keywords": ["x"]}, "   ")
        assert result.passed is False, kind


def test_grade_all_returns_one_result_per_question():
    questions = [
        {"id": "q1", "type": "yes_no"},
        {"id": "q2", "type": "keyword", "expected_keywords": ["csp"]},
    ]
    results = quiz.grade_all(questions, {"q1": "yes", "q2": "csp is missing"})
    assert len(results) == 2
    assert all(item.passed for item in results)
    assert {item.question_id for item in results} == {"q1", "q2"}


# ---------------------------------------------------------------------------
# Shipped exercise content
# ---------------------------------------------------------------------------
def test_shipped_questions_are_gradable_enough_to_be_useful(config):
    """A lab where nothing can be graded defeats the requirement."""
    from bcssl.lab.exercises import load_all

    graded = 0
    total = 0
    for exercise in load_all():
        for question in exercise.questions:
            total += 1
            if quiz.is_gradable(question):
                graded += 1
    assert total == 36
    assert graded >= 30, f"only {graded}/{total} questions are gradable"


def test_every_shipped_gradable_question_has_a_key(config):
    from bcssl.lab.exercises import load_all

    for exercise in load_all():
        for question in exercise.questions:
            kind = quiz.question_type(question)
            if kind in (quiz.KEYWORD, quiz.KEYWORDS):
                assert question.get("expected_keywords"), f"{exercise.id}/{question.get('id')}"
            if kind == quiz.NUMBER:
                has_bound = any(
                    question.get(key) is not None
                    for key in ("exact", "min_number", "max_number")
                )
                assert has_bound, f"{exercise.id}/{question.get('id')}"
            if kind == quiz.LIST:
                assert question.get("min_items")
