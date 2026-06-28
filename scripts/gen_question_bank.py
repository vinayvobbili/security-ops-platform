#!/usr/bin/env python3
"""Grow a lesson's quiz question bank with the LLM, grounded in the lesson content.

The /lessons feature draws a fresh, shuffled, mixed-format test from each topic's
question bank (see web/routes/lessons.py TEST_BLUEPRINT). A deep bank — many more
questions than any single test shows — is what makes two analysts rarely see the
same test, which defeats answer-sharing. Hand-authoring 100 good questions is a
slog, so this tool drafts them with the local LLM strictly from
the topic's own material, validates each one, dedupes against what's already
there, and appends to the topic YAML.

The generation engine itself lives in the model-agnostic ``quizforge`` package;
this script is the application seam — it builds the lesson material, injects the
local LLM, and steers the prompt toward SOC attack-scenario coverage.

Usage:
    python scripts/gen_question_bank.py citrix                 # top up to defaults
    python scripts/gen_question_bank.py citrix --dry-run       # print, don't write
    python scripts/gen_question_bank.py citrix --mc 40 --fill 20 --match 12 \
        --short 16 --freetext 12                               # explicit targets

Targets are TOTAL bank size per format (existing counted); the tool only generates
the shortfall. Re-run anytime to top up — it never duplicates existing prompts.
"""

import argparse
import logging
import sys
from collections import Counter
from pathlib import Path

import yaml
from quizforge import DEFAULT_TARGETS, Bank, generate_bank

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from my_bot.utils.llm_factory import create_llm  # noqa: E402

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger("gen_question_bank")
logger.setLevel(logging.INFO)
# Surface quizforge's per-format progress at INFO too.
logging.getLogger("quizforge").setLevel(logging.INFO)

TOPICS_DIR = Path(__file__).resolve().parent.parent / "data" / "training" / "topics"

# Override quizforge's domain-neutral prompts with SOC-content framing.
_SOC_SYSTEM = (
    "You are a senior SOC training content author writing quiz questions for security "
    "analysts. Write questions STRICTLY grounded in the provided lesson material — do not "
    "invent facts beyond it. Questions must be accurate, unambiguous, and test real "
    "understanding (attacker tradecraft, detection signals, analyst actions), not trivia. "
    "For multiple choice, exactly one option is correct and the distractors are plausible. "
    "Vary difficulty as requested. Return strict JSON for the requested schema."
)
_SOC_COVERAGE = (
    "at least HALF of these must be attack-scenario questions about how a real adversary "
    "attacks THIS platform end-to-end — the edge->domain kill chain, the specific CVEs/TTPs "
    "named above, post-exploitation, and (critically) the detection signals and the concrete "
    "triage/containment actions a SOC analyst takes at each stage. The rest can cover core "
    "platform knowledge. Frame scenarios as a real incident an analyst is working, not "
    "abstract trivia. Do not invent CVEs or behaviors."
)


def _lesson_material(meta: dict) -> str:
    """Flatten a topic's content into grounding text for the generator."""
    lines = [f"TOPIC: {meta.get('title', '')}", ""]
    if meta.get("summary"):
        lines += [meta["summary"], ""]
    if meta.get("why_risky"):
        lines += ["WHY IT'S RISKY:", meta["why_risky"].strip(), ""]
    if meta.get("key_concepts"):
        lines.append("KEY CONCEPTS:")
        for c in meta["key_concepts"]:
            lines.append(f"- {c.get('title','')}: {c.get('body','')}")
            # Per-concept bullets carry the attack kill-chain + detection signals;
            # feed them in so generated questions can ground attack-scenario items.
            for b in c.get("bullets", []) or []:
                lines.append(f"    • {b}")
        lines.append("")
    return "\n".join(lines)


def _append_questions(path: Path, questions: list) -> None:
    """Append already-id'd question dicts under the topic's ``questions:`` list.

    Append-only — never re-dumps the file — so the hand-authored lesson content
    above (block-scalar summary/why_risky, emoji bullets, comments) survives
    byte-for-byte. quizforge's Bank.save() does a clean full re-dump, which we
    deliberately avoid for these hand-maintained topic files.
    """
    blocks = []
    for q in questions:
        dumped = yaml.dump([q], default_flow_style=False, sort_keys=False,
                           allow_unicode=True, width=100)
        # yaml.dump emits top-level list items at column 0; indent 2 to sit under `questions:`.
        blocks.append("\n".join("  " + ln if ln else ln for ln in dumped.splitlines()))
    with open(path, "a") as f:
        f.write("\n" + "\n".join(blocks) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser(description="Grow a lesson's quiz question bank with the LLM.")
    ap.add_argument("topic", help="Topic ID, e.g. 'citrix'")
    ap.add_argument("--dry-run", action="store_true", help="Generate and print a summary, but don't write")
    for fmt in DEFAULT_TARGETS:
        ap.add_argument(f"--{fmt.replace('_', '-')}", type=int, default=None,
                        help=f"Target TOTAL {fmt} questions (default {DEFAULT_TARGETS[fmt]})")
    args = ap.parse_args()

    path = TOPICS_DIR / f"{args.topic}.yaml"
    if not path.is_file():
        logger.error("No such topic: %s", path)
        return 1

    bank = Bank.load(path)
    targets = {f: (getattr(args, f) if getattr(args, f) is not None else DEFAULT_TARGETS[f])
               for f in DEFAULT_TARGETS}
    material = _lesson_material(bank.meta)
    llm = create_llm(temperature=0.4)  # a little warmth for question variety

    new = generate_bank(material, llm, targets=targets, existing=bank.questions,
                        system=_SOC_SYSTEM, coverage=_SOC_COVERAGE)

    if not new:
        logger.info("Nothing to add — bank already meets targets.")
        return 0

    by_type = Counter(q["type"] for q in new)
    by_diff = Counter(q["difficulty"] for q in new)
    logger.info("Generated %d new questions: %s | difficulty %s",
                len(new), dict(by_type), dict(by_diff))

    if args.dry_run:
        logger.info("--dry-run: not writing. New bank total would be %d.", len(bank) + len(new))
        for q in new[:3]:
            logger.info("  sample[%s/%s]: %s", q["type"], q["difficulty"], q["prompt"][:90])
        return 0

    _append_questions(path, new)
    # Re-parse to prove the file is still valid YAML after the append.
    reparsed = Bank.load(path)
    logger.info("Wrote %d questions. Bank now %d total (was %d). YAML re-parsed OK.",
                len(new), len(reparsed), len(bank))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
