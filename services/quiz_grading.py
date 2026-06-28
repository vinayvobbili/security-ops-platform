"""Adapter over the model-agnostic ``quizforge`` grading kernel.

The grading logic — deterministic fill-blank / match, plus LLM-scored open
answers — lives in the standalone ``quizforge`` package. This module is a thin
seam that wires that kernel to the local LLM and a SOC-coach grading tone.

Multiple-choice is still graded deterministically in the route (a trivial index
compare). Fill-blank and match are deterministic here (no LLM). Open questions
("explain how you'd triage X") are scored 0..1 with feedback by the LLM against a
per-question model answer + rubric.
"""

import logging
from typing import Optional

from quizforge import QuizGrade, grade_fill_blank, grade_match
from quizforge import grade_open_answer as _grade_open_answer
from quizforge.text import normalize as _normalize  # re-exported for back-compat

from my_bot.utils.llm_factory import create_llm

logger = logging.getLogger(__name__)

# Re-exports so existing imports keep working unchanged.
__all__ = ["grade_fill_blank", "grade_match", "grade_open_answer", "QuizGrade", "_normalize"]

# SOC-flavored override of quizforge's domain-neutral assessor prompt — keeps the
# "security analyst, attacker tradecraft / detection signals / analyst actions"
# framing and coaching tone the lessons feature was tuned around.
_SOC_GRADE_SYSTEM = (
    "You are a SOC training assessor grading a security analyst's open-ended quiz "
    "answer. Grade on CONCEPTS, not phrasing or grammar — credit the analyst when "
    "they demonstrate the right understanding in their own words. Be fair but "
    "rigorous: award partial credit when an answer is on the right track but misses "
    "a key point, and award 0 when it is wrong, empty, evasive ('I don't know'), or "
    "merely restates the question. Do not be fooled by confident-sounding but "
    "incorrect answers. Return strict JSON for the QuizGrade schema."
)


def grade_open_answer(question: dict, user_answer: str) -> Optional[QuizGrade]:
    """Score an open-ended answer 0..1 with feedback via the local LLM.

    Returns a :class:`quizforge.QuizGrade`, or ``None`` if automated grading was
    unavailable — callers exclude the question from the attempt's max score
    rather than penalize the learner for our outage.
    """
    return _grade_open_answer(
        question, user_answer,
        create_llm(temperature=0),
        system=_SOC_GRADE_SYSTEM,
    )
