#!/usr/bin/env python3
"""Generate the Customer Assurance "How does this work?" explainer video.

Renders one branded slide per step via headless Chromium, narrates each with a
local Kokoro neural TTS voice (an OpenAI-compatible /v1/audio/speech endpoint —
the same natural voice used by the Vulnerability Deep Dive demo, NOT the robotic
browser speechSynthesis), and stitches everything into a single MP4 with ffmpeg.

The render/narrate/stitch mechanics live in the model-agnostic ``slidecast``
package; this script is the application seam — it owns the branded slide HTML, the
step script (SCENES), and the local Kokoro voice, and hands them to a ``slidecast.Reel``.

Output: web/static/video/customer_assurance_demo.mp4  (embedded via <video controls>
in the how-to modal, exactly like vuln_deep_dive_demo.mp4).

Re-running overwrites the existing mp4.

    python scripts/gen_ca_howto_video.py
"""
from __future__ import annotations

import html
import sys
from pathlib import Path

from slidecast import KokoroTTS, PlaywrightRenderer, Reel
from slidecast.ffmpeg import FFmpegNotFound, find_ffmpeg

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = PROJECT_ROOT / "web" / "static" / "video"
OUT_PATH = OUT_DIR / "customer_assurance_demo.mp4"

KOKORO_URL = "http://localhost:8021/v1/audio/speech"
KOKORO_VOICE = "af_heart"

W, H = 1280, 720
TAIL_PAD = 0.8   # seconds of silence after each narration so nothing is clipped

# --- the reel. One dict per slide; `art` is an HTML fragment dropped into the
#     right-hand art panel. `narration` is what the voice says (and the subtitle).
SCENES = [
    {
        "step": "Behind the scenes · Knowledge library",
        "title": "📚 Indexing the policy library",
        "blurb": "Your approved security documents become a searchable library that "
                 "grounds every answer.",
        "art": """
            <div class="bigemoji">📚</div>
            <div class="chips">
              <span class="chip">📄 policies</span>
              <span class="chip">🛡️ SOC 2 evidence</span>
              <span class="chip accent">✅ past answers</span>
            </div>""",
        "narration": "Before any questionnaire arrives, your approved security "
                     "documents — policies, S O C 2 evidence, and past approved "
                     "answers — are indexed into a searchable knowledge library. "
                     "That library is what every draft is grounded in, so answers "
                     "always reflect your real, current documentation.",
    },
    {
        "step": "Step 1 · Intake",
        "title": "📥 Intake",
        "blurb": "Paste the questions, or upload the customer's spreadsheet — the "
                 "tool takes it from there.",
        "art": """
            <div class="bigemoji">📥</div>
            <div class="chips">
              <span class="chip">📎 .xlsx</span>
              <span class="chip">📄 .docx</span>
              <span class="chip accent">✍️ paste</span>
            </div>""",
        "narration": "An account team member submits a customer's security "
                     "questionnaire — they paste the questions, or drop in an Excel "
                     "or Word file. No special format required.",
    },
    {
        "step": "Step 2 · Auto-split",
        "title": "✂️ Auto-split",
        "blurb": "One messy file becomes clean, individually-tracked questions — "
                 "organized by section.",
        "art": """
            <div class="card">
              <div class="row l"></div><div class="row m"></div>
              <div class="row l brand"></div><div class="row s"></div>
              <div class="row m accent"></div>
            </div>""",
        "narration": "The tool reads the document and automatically splits it into "
                     "individual questions, grouped by section — no manual copy and "
                     "paste.",
    },
    {
        "step": "Step 3 · Grounded retrieval",
        "title": "🔎 Grounded retrieval",
        "blurb": "Every draft is anchored to your real policy library and prior "
                 "approved answers — never to guesswork.",
        "art": """
            <div class="card">
              <div class="row l"></div><div class="row m"></div>
              <div class="row l brand"></div><div class="row s"></div>
            </div>
            <div class="chips">
              <span class="chip">📚 policy</span>
              <span class="chip">🛡️ evidence</span>
              <span class="chip accent">✅ past answers</span>
            </div>""",
        "narration": "For each question, the assistant searches your approved policy "
                     "library, security evidence, and past approved answers — pulling "
                     "only the most relevant, re-ranked passages as grounding.",
    },
    {
        "step": "Step 4 · AI drafting",
        "title": "🤖 AI drafting",
        "blurb": "Direct, cited, and honest. Yes or No when policy backs it; flagged "
                 "for an expert only when it truly must be.",
        "art": """
            <div class="card">
              <span class="yesno">✓ Yes</span>
              <div class="row l"></div><div class="row m"></div><div class="row s"></div>
              <div class="chips" style="margin-top:14px;">
                <span class="chip">[Source: InfoSec Std]</span>
                <span class="chip accent">[Source: SOC 2]</span>
              </div>
            </div>""",
        "narration": "The assistant writes a direct, policy-grounded answer with "
                     "citations — a clear Yes or No when the evidence supports it, and "
                     "an honest, confirm with an expert, only when the library is "
                     "genuinely silent. It never invents a specific date, name, or "
                     "number.",
    },
    {
        "step": "Step 5 · Review & approve",
        "title": "👤 Review & approve",
        "blurb": "A human owns every answer — edit, approve, or route to Legal. The "
                 "AI drafts; the analyst decides.",
        "art": """
            <div class="bigemoji">✅</div>
            <div class="chips">
              <span class="chip">✏️ edit</span>
              <span class="chip accent">👍 approve</span>
              <span class="chip">⚖️ route to Legal</span>
            </div>""",
        "narration": "An analyst reviews every draft — edits freely, approves, or "
                     "flags for Legal. Nothing reaches a customer without a human "
                     "sign-off.",
    },
    {
        "step": "Step 6 · Reuse & deliver",
        "title": "🚀 Reuse & deliver",
        "blurb": "Approved answers feed the next questionnaire automatically. Export "
                 "to Word and you're done.",
        "art": """
            <div class="bigemoji">📄</div>
            <div class="chips">
              <span class="chip accent">♻️ auto-reuse</span>
              <span class="chip">📄 .docx export</span>
            </div>""",
        "narration": "Approved answers are remembered, so the next questionnaire "
                     "reuses them automatically. Export the finished response as a "
                     "Word document and hand it back — minutes instead of days.",
    },
]

SLIDE_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
html, body { width: 1280px; height: 720px; overflow: hidden;
  font-family: 'Segoe UI', 'Noto Sans', system-ui, sans-serif; }
body {
  background:
    radial-gradient(900px 500px at 12% -10%, rgba(0,70,173,.16), transparent 60%),
    radial-gradient(900px 520px at 110% 120%, rgba(0,166,81,.18), transparent 60%),
    linear-gradient(135deg, #eef4ff 0%, #eafaf1 100%);
  display: flex; align-items: center; justify-content: center;
}
.card-frame {
  width: 1140px; height: 600px; background: #ffffff;
  border-radius: 28px; position: relative; overflow: hidden;
  box-shadow: 0 30px 80px rgba(8,17,35,.20), 0 2px 0 rgba(255,255,255,.6) inset;
  display: flex; flex-direction: column;
}
.accent-bar { height: 10px; background: linear-gradient(135deg,#0046AD,#00A651); }
.frame-inner { flex: 1; padding: 44px 56px 30px; display: flex; flex-direction: column; }
.head { display: flex; align-items: center; justify-content: space-between; }
.wordmark { font-size: 26px; font-weight: 800; letter-spacing: .2px;
  background: linear-gradient(135deg,#0046AD,#00A651);
  -webkit-background-clip: text; background-clip: text; color: transparent; }
.step-chip { font-size: 18px; font-weight: 700; color: #0046AD;
  background: linear-gradient(135deg, rgba(0,70,173,.10), rgba(0,166,81,.12));
  padding: 9px 18px; border-radius: 999px; border: 1px solid rgba(0,70,173,.18); }
.body { flex: 1; display: flex; align-items: center; gap: 48px; margin-top: 8px; }
.text { flex: 1.05; }
.title { font-size: 60px; font-weight: 800; color: #0d1b34; line-height: 1.05; }
.blurb { font-size: 27px; line-height: 1.45; color: #44506a; margin-top: 22px; max-width: 520px; }
.art { flex: .95; display: flex; flex-direction: column; align-items: center;
  justify-content: center; gap: 22px; min-height: 320px; }
.bigemoji { font-size: 150px; line-height: 1;
  filter: drop-shadow(0 14px 26px rgba(8,17,35,.22)); }
.chips { display: flex; flex-wrap: wrap; gap: 12px; justify-content: center; max-width: 440px; }
.chip { font-size: 20px; font-weight: 600; color: #2a3753;
  background: #eef2fb; border: 1px solid #dde6f6; padding: 9px 16px; border-radius: 12px; }
.chip.accent { color: #0a7d44; background: #e7f8ef; border-color: #c7eed8; }
.card { width: 380px; background: #f7f9ff; border: 1px solid #e4ebf8;
  border-radius: 18px; padding: 26px; box-shadow: 0 12px 30px rgba(8,17,35,.10); }
.row { height: 18px; border-radius: 9px; margin: 12px 0; background: #dde5f3; }
.row.l { width: 100%; } .row.m { width: 72%; } .row.s { width: 48%; }
.row.brand { background: linear-gradient(90deg,#0046AD,#3f7fe0); }
.row.accent { background: linear-gradient(90deg,#00A651,#4cc98a); }
.yesno { display: inline-block; font-size: 26px; font-weight: 800; color: #0a7d44;
  background: #e7f8ef; border: 1px solid #c7eed8; padding: 8px 20px;
  border-radius: 12px; margin-bottom: 14px; }
.caption { background: rgba(13,27,52,.92); color: #fff; font-size: 23px; line-height: 1.4;
  padding: 16px 26px; border-radius: 14px; margin-top: 8px; text-align: center; }
"""


def build_slide_html(scene: dict) -> str:
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<style>{SLIDE_CSS}</style></head><body>
<div class="card-frame">
  <div class="accent-bar"></div>
  <div class="frame-inner">
    <div class="head">
      <div class="wordmark">Customer Assurance</div>
      <div class="step-chip">{html.escape(scene['step'])}</div>
    </div>
    <div class="body">
      <div class="text">
        <div class="title">{html.escape(scene['title'])}</div>
        <div class="blurb">{html.escape(scene['blurb'])}</div>
      </div>
      <div class="art">{scene['art']}</div>
    </div>
    <div class="caption">{html.escape(scene['narration'])}</div>
  </div>
</div></body></html>"""


def main() -> int:
    try:
        find_ffmpeg()
    except FFmpegNotFound as exc:
        print(f"ffmpeg not found: {exc}", file=sys.stderr)
        return 1
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    # slidecast does the render/narrate/stitch. We keep the branded slide HTML,
    # the step script (SCENES), the local Kokoro voice (WAV so each segment pads
    # to fit the speech), and the 2x screenshot for crispness at 1280x720.
    reel = Reel(
        width=W, height=H, fps=25,
        tts=KokoroTTS(url=KOKORO_URL, voice=KOKORO_VOICE, response_format="wav"),
        renderer=PlaywrightRenderer(device_scale_factor=2),
    )
    titles = [s["title"] for s in SCENES]
    for scene in SCENES:
        reel.add(build_slide_html(scene), scene["narration"], tail_pad=TAIL_PAD)

    def _progress(i, total, _slide):
        print(f"  [{i}/{total}] {titles[i - 1]}")

    print(f"Generating {len(SCENES)} scenes -> {OUT_PATH}")
    reel.render(OUT_PATH, make_poster=True, on_progress=_progress)

    poster = OUT_PATH.with_name(OUT_PATH.stem + "_poster.jpg")
    size = OUT_PATH.stat().st_size / 1e6
    print(f"\n✓ Wrote {OUT_PATH}  ({size:.1f} MB)")
    print(f"✓ Wrote {poster}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
