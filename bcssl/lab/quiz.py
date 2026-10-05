"""Structured questions and answer validation.

Questions may declare how they are graded:

``yes_no``      answer must be yes/no (or true/false)
``keyword``     answer must contain one of the accepted keywords
``keywords``    answer must contain at least ``min_keywords`` of them
``number``      answer must parse as a number inside an optional range
``list``        answer must contain at least ``min_items`` items
``freeform``    recorded for instructor review, no automatic grading

**Answer keys are never shown to a student.** :func:`student_view` strips every
validation field, and the CLI, dashboard API and reports all use it. Keys stay
inside the lab for grading only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# Question types.
YES_NO = "yes_no"
KEYWORD = "keyword"
KEYWORDS = "keywords"
NUMBER = "number"
LIST = "list"
FREEFORM = "freeform"

QUESTION_TYPES = (YES_NO, KEYWORD, KEYWORDS, NUMBER, LIST, FREEFORM)

#: Fields that reveal the answer key and must never reach a student.
_KEY_FIELDS = (
    "expected_keywords",
    "any_keywords",
    "accepted_answers",
    "min_keywords",
    "min_items",
    "min_number",
    "max_number",
    "exact",
    "guidance",
)

_YES = {"yes", "y", "true", "correct", "affirmative"}
_NO = {"no", "n", "false", "incorrect", "negative"}


@dataclass
class GradeResult:
    """Outcome of grading one answer."""

    question_id: str
    passed: bool
    needs_review: bool = False
    feedback: str = ""
    matched: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "question_id": self.question_id,
            "passed": self.passed,
            "needs_review": self.needs_review,
            "feedback": self.feedback,
            "matched": self.matched,
        }


def question_type(question: dict[str, Any]) -> str:
    declared = str(question.get("type") or "").strip().lower()
    if declared in QUESTION_TYPES:
        return declared
    if question.get("expected_keywords") or question.get("any_keywords"):
        return KEYWORD
    return FREEFORM


def is_gradable(question: dict[str, Any]) -> bool:
    """True when the lab can decide correctness without an instructor."""
    return question_type(question) != FREEFORM


def student_view(question: dict[str, Any]) -> dict[str, Any]:
    """Return the question with every answer-key field removed."""
    view = {key: value for key, value in question.items() if key not in _KEY_FIELDS}
    view["type"] = question_type(question)
    view["gradable"] = is_gradable(question)
    return view


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", str(text or "")).strip().lower()


def grade(question: dict[str, Any], answer: str | None) -> GradeResult:
    """Grade *answer* against *question*'s declared specification."""
    qid = str(question.get("id", ""))
    kind = question_type(question)
    text = _normalize(answer)

    if not text:
        return GradeResult(qid, False, feedback="No answer recorded.")

    if kind == YES_NO:
        accepted = {str(value).strip().lower() for value in question.get("accepted_answers", [])}
        accepted |= set(question.get("any_keywords", [])) or _YES | _NO
        if text in accepted:
            return GradeResult(qid, True, feedback="Recorded.")
        # Allow a short justification around a yes/no token.
        tokens = set(re.findall(r"[a-z]+", text))
        if tokens & (_YES | _NO):
            return GradeResult(
                qid, True, feedback="Recorded (yes/no detected in your answer)."
            )
        return GradeResult(
            qid, False, feedback="Answer with yes or no, plus a short reason."
        )

    if kind == KEYWORD:
        keywords = [str(value).lower() for value in question.get("expected_keywords", [])]
        if not keywords:
            keywords = [str(value).lower() for value in question.get("any_keywords", [])]
        matched = [value for value in keywords if value in text]
        if matched:
            return GradeResult(
                qid, True, feedback="Correct key point present.", matched=matched
            )
        return GradeResult(
            qid,
            False,
            feedback=(
                "Your answer does not mention the expected technical term. "
                "Name the specific header, tool, port or option."
            ),
        )

    if kind == KEYWORDS:
        keywords = [str(value).lower() for value in question.get("expected_keywords", [])]
        minimum = int(question.get("min_keywords", max(1, len(keywords) // 2)))
        matched = [value for value in keywords if value in text]
        if len(matched) >= minimum:
            return GradeResult(
                qid,
                True,
                feedback=f"{len(matched)} of the expected points were covered.",
                matched=matched,
            )
        return GradeResult(
            qid,
            False,
            feedback=(
                f"Cover more of the expected points; at least {minimum} "
                "distinct key terms were required."
            ),
            matched=matched,
        )

    if kind == NUMBER:
        numbers = re.findall(r"-?\d+(?:\.\d+)?", text)
        if not numbers:
            return GradeResult(qid, False, feedback="Your answer must contain a number.")
        value = float(numbers[0])
        low = question.get("min_number")
        high = question.get("max_number")
        if low is not None and value < float(low):
            return GradeResult(qid, False, feedback="That value is below the expected range.")
        if high is not None and value > float(high):
            return GradeResult(qid, False, feedback="That value is above the expected range.")
        exact = question.get("exact")
        if exact is not None and abs(value - float(exact)) > 1e-9:
            return GradeResult(qid, False, feedback="That number is not the expected value.")
        return GradeResult(qid, True, feedback="Value recorded and within range.")

    if kind == LIST:
        items = [
            item.strip()
            for item in re.split(r"[\n;,]+", str(answer or ""))
            if item.strip()
        ]
        minimum = int(question.get("min_items", 3))
        if len(items) >= minimum:
            return GradeResult(
                qid, True, feedback=f"{len(items)} item(s) listed."
            )
        return GradeResult(
            qid,
            False,
            feedback=f"List at least {minimum} items; you listed {len(items)}.",
        )

    # freeform: recorded, instructor decides.
    return GradeResult(
        qid, True, needs_review=True, feedback="Recorded for instructor review."
    )


def grade_all(
    questions: list[dict[str, Any]], answers: dict[str, str]
) -> list[GradeResult]:
    """Grade every question, returning one result per question."""
    return [grade(question, answers.get(str(question.get("id", "")))) for question in questions]
