"""Meeting Minutes QA — compare human notes with Copilot notes and produce
consolidated executive-ready minutes with quality scores.

Uses the M1 Analysis LLM (GLM-4.7-Flash-8bit) via the OpenAI SDK with
extra_body to disable thinking mode — matching how the security assistant bot calls the model.
"""

import logging
import os
import re

from openai import OpenAI

logger = logging.getLogger(__name__)

# Lazy-loaded at request time (after Flask loads .env)
_client = None
_model_id = None


def _get_client() -> OpenAI:
    """Get OpenAI client lazily — .env is loaded by Flask before first request."""
    global _client
    if _client:
        return _client
    # m1 analysis (GLM-4.7-Flash)
    base_url = os.environ.get('SLEUTH_LLM_BASE_URL') or os.environ.get('LLM_BASE_URL', 'http://localhost:8015/v1')
    logger.info(f"Meeting QA LLM base URL: {base_url}")
    _client = OpenAI(base_url=base_url, api_key="not-needed")
    return _client


def _get_model_id() -> str:
    """Auto-discover the model ID from the /models endpoint (cached)."""
    global _model_id
    if _model_id:
        return _model_id
    try:
        models = _get_client().models.list()
        if models.data:
            _model_id = models.data[0].id
            logger.info(f"Meeting QA using model: {_model_id}")
            return _model_id
    except Exception as e:
        logger.warning(f"Could not discover model ID: {e}")
    return "default"


SYSTEM_PROMPT = "You are a meeting-notes QA coach. Respond ONLY with the requested markdown. No thinking, no preamble."

USER_PROMPT = """\
You are reviewing a human's meeting notes against Copilot's AI-generated transcript. \
Your job is to coach the human on what they captured well, what they missed, and where \
their notes contradict the transcript. Then produce a single consolidated set of \
executive-ready minutes.

HUMAN NOTES:
{human_notes}

COPILOT NOTES:
{copilot_notes}

Respond using EXACTLY this structure:

## Comparison Analysis

### What You Captured Well
- (specific items the human got right — quote both sources briefly)

### What You Missed
- (important details from Copilot that the human left out — be specific: "Copilot recorded X but your notes don't mention it")

### Contradictions
- (where the human wrote one thing but Copilot recorded something different — e.g. "You wrote 'Q2 deadline' but Copilot has 'April 5'", or "None found")

### What Copilot Missed
- (anything the human captured that Copilot did not — or "None")

## Consolidated Meeting Minutes

### Meeting Overview
(date, attendees, purpose — merged from both sources)

### Key Discussion Points
(organized by topic, concise, combining details from both)

### Decisions Made
1. (numbered list)

### Action Items
| Who | What | Deadline |
|-----|------|----------|
| ... | ...  | ...      |

### Open Questions
- (unresolved items, or "None")

## Quality Scores

### Coverage Score: X/10
(how much of the meeting content the human captured compared to Copilot)

### Accuracy Score: X/10
(whether the human's facts align with or contradict Copilot's record)

### Executive Readiness Score: X/10
(could the human's notes alone serve as executive meeting minutes — clarity, structure, completeness)"""


def _clean_llm_response(raw: str) -> str:
    """Strip any reasoning preamble — real output starts at first '## ' heading."""
    if '</think>' in raw:
        raw = raw.split('</think>')[-1].strip()
    elif '<think>' in raw:
        raw = raw.split('<think>')[0].strip()
    m = re.search(r'^## ', raw, re.MULTILINE)
    if m:
        raw = raw[m.start():]
    return raw.strip()


def analyze_meeting_notes(human_notes: str, copilot_notes: str) -> dict:
    """Send both note sets to LLM for comparison, consolidation, and scoring."""
    if not human_notes.strip() or not copilot_notes.strip():
        return {"success": False, "error": "Both human notes and Copilot notes are required."}

    try:
        # Assistant prefix-filling: start the response with the first heading
        # so GLM skips its reasoning phase and produces markdown directly.
        # Without this, GLM spends ~2 min on thinking before any real output.
        ASSISTANT_PREFIX = "## Comparison Analysis"
        resp = _get_client().chat.completions.create(
            model=_get_model_id(),
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": USER_PROMPT.format(
                    human_notes=human_notes.strip(),
                    copilot_notes=copilot_notes.strip(),
                )},
                {"role": "assistant", "content": ASSISTANT_PREFIX},
            ],
            temperature=0,
            max_tokens=4096,
            timeout=180,
        )
        content = _clean_llm_response(resp.choices[0].message.content)
        if not content:
            logger.error("Meeting QA: LLM returned no usable markdown sections")
            return {"success": False, "error": "The model did not produce a valid analysis. Please try again."}
        return {"success": True, "result": content}

    except Exception as e:
        msg = str(e)
        if 'timed out' in msg.lower() or 'timeout' in msg.lower():
            logger.error("Meeting QA LLM request timed out")
            return {"success": False, "error": "The analysis request timed out. Please try again."}
        if 'connection' in msg.lower() or 'refused' in msg.lower():
            logger.error("Meeting QA LLM connection refused")
            return {"success": False, "error": "Could not connect to the analysis model. Is the M1 server running?"}
        logger.error(f"Meeting QA analysis failed: {e}")
        return {"success": False, "error": f"Analysis failed: {e}"}
