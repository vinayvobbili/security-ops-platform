#!/usr/bin/env python3
"""Generate a training video for a lesson topic.

Reads data/training/topics/<topic>.yaml and builds one slide per concept. Each
slide is a lively, on-brand HTML card (gradient backdrop, big emoji, short
bullets, accents) screenshotted at 1080p via headless Chromium — so the screen
stays scannable while the full prose is narrated underneath by the local Kokoro
TTS service (natural voice; gTTS fallback). Slides + audio are stitched into
web/static/videos/<topic>.mp4 with ffmpeg.

Slides show short `bullets` (authored in the topic YAML); the narration always
reads the full `summary` / `why_risky` / concept `body` prose, so nothing is
lost from the audio track.

Usage:
    python scripts/gen_training_video.py citrix

Environment:
    TTS_PROVIDER   "kokoro" (default) or "gtts"
    KOKORO_URL     default http://127.0.0.1:8021
    KOKORO_VOICE   default af_heart

Re-running overwrites the existing mp4. Runs on Linux or macOS.
"""

import argparse
import html
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import requests
import yaml

PROJECT_ROOT = Path(__file__).parent.parent
TOPICS_DIR = PROJECT_ROOT / "data" / "training" / "topics"
VIDEOS_DIR = PROJECT_ROOT / "web" / "static" / "videos"

WIDTH, HEIGHT = 1920, 1080

TTS_PROVIDER = os.environ.get("TTS_PROVIDER", "kokoro")
KOKORO_URL = os.environ.get("KOKORO_URL", "http://127.0.0.1:8021")
KOKORO_VOICE = os.environ.get("KOKORO_VOICE", "af_heart")

# Per-slide palettes: (background gradient, headline accent gradient, two blob
# colors). Concept slides rotate through PALETTES; title/risk use fixed ones.
TITLE_PAL = {"bg": "linear-gradient(135deg,#1a0b3e 0%,#0046ad 55%,#00a651 120%)",
             "accent": "linear-gradient(90deg,#8fd3ff,#46e08a)",
             "blob1": "rgba(141,211,255,.40)", "blob2": "rgba(70,224,138,.36)"}
RISK_PAL = {"bg": "linear-gradient(135deg,#3a0610 0%,#a40e26 52%,#fc6767 122%)",
            "accent": "linear-gradient(90deg,#ffd6a5,#ff8f8f)",
            "blob1": "rgba(255,180,120,.36)", "blob2": "rgba(255,90,90,.34)"}
PALETTES = [
    {"bg": "linear-gradient(135deg,#0b1f3a 0%,#0a4d8c 60%,#0a8fd6 125%)",
     "accent": "linear-gradient(90deg,#8fd3ff,#cfe7ff)", "blob1": "rgba(120,180,255,.34)", "blob2": "rgba(10,143,214,.30)"},
    {"bg": "linear-gradient(135deg,#06291f 0%,#0a6b4a 60%,#11998e 125%)",
     "accent": "linear-gradient(90deg,#7af0c8,#d6fff0)", "blob1": "rgba(70,224,138,.34)", "blob2": "rgba(17,153,142,.30)"},
    {"bg": "linear-gradient(135deg,#2a0a45 0%,#5b1f8f 60%,#8f5cff 125%)",
     "accent": "linear-gradient(90deg,#e0c3ff,#f3e8ff)", "blob1": "rgba(180,130,255,.34)", "blob2": "rgba(143,92,255,.30)"},
    {"bg": "linear-gradient(135deg,#3a1602 0%,#a85a07 58%,#f7971e 125%)",
     "accent": "linear-gradient(90deg,#ffe6a5,#fff4d6)", "blob1": "rgba(255,200,110,.34)", "blob2": "rgba(247,151,30,.30)"},
    {"bg": "linear-gradient(135deg,#3a0620 0%,#a4185c 58%,#ec4899 125%)",
     "accent": "linear-gradient(90deg,#ffc3e0,#ffe8f3)", "blob1": "rgba(255,150,200,.34)", "blob2": "rgba(236,72,153,.30)"},
]

FONT_STACK = "'Arial Black','Liberation Sans','DejaVu Sans',Arial,sans-serif"
BODY_STACK = "'Liberation Sans','DejaVu Sans',Arial,sans-serif"


def _slide_html(slide: dict) -> str:
    """Build a full HTML document for one 1920x1080 slide."""
    pal = slide["pal"]
    idx, total = slide["idx"], slide["total"]
    bullets_html = "\n".join(
        f'<li style="animation-delay:{0.08 * i:.2f}s">{html.escape(b)}</li>'
        for i, b in enumerate(slide["bullets"])
    )
    dots = "".join(
        f'<span class="dot{" on" if (i + 1) == idx else ""}"></span>' for i in range(total)
    )
    sub = f'<div class="sub">{html.escape(slide["sub"])}</div>' if slide.get("sub") else ""
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><style>
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  html,body {{ width:{WIDTH}px; height:{HEIGHT}px; overflow:hidden; }}
  body {{ font-family:{BODY_STACK}; background:{pal['bg']}; color:#fff; position:relative; }}
  .blob {{ position:absolute; border-radius:50%; filter:blur(60px); }}
  .b1 {{ width:760px; height:760px; right:-180px; top:-260px; background:{pal['blob1']}; }}
  .b2 {{ width:620px; height:620px; left:-200px; bottom:-240px; background:{pal['blob2']}; }}
  .frame {{ position:absolute; inset:0; padding:70px 100px 64px; display:flex; flex-direction:column; }}
  .topbar {{ display:flex; justify-content:space-between; align-items:center; }}
  .kicker {{ font-family:{BODY_STACK}; font-weight:800; font-size:25px; letter-spacing:6px; text-transform:uppercase;
             color:rgba(255,255,255,.82); background:rgba(255,255,255,.10); border:1px solid rgba(255,255,255,.22);
             padding:10px 22px; border-radius:999px; }}
  .counter {{ font-weight:800; font-size:29px; color:rgba(255,255,255,.6); letter-spacing:2px; }}
  .head {{ display:flex; align-items:center; gap:30px; margin-top:40px; }}
  .emoji {{ font-size:104px; line-height:1; width:164px; height:164px; flex:none; display:flex; align-items:center;
            justify-content:center; background:rgba(255,255,255,.12); border:2px solid rgba(255,255,255,.22);
            border-radius:34px; box-shadow:0 24px 60px rgba(0,0,0,.32); }}
  h1 {{ font-family:{FONT_STACK}; font-size:96px; line-height:1.03; letter-spacing:-2px;
        background:{pal['accent']}; -webkit-background-clip:text; background-clip:text; color:transparent; }}
  h1.small {{ font-size:70px; }}
  .sub {{ font-family:{BODY_STACK}; font-weight:700; font-size:33px; color:rgba(255,255,255,.86); margin-top:12px; letter-spacing:.5px; }}
  ul {{ list-style:none; margin:38px 0 0; display:flex; flex-direction:column; gap:18px; }}
  li {{ font-family:{BODY_STACK}; font-weight:600; font-size:46px; line-height:1.25; color:#fff;
        background:rgba(255,255,255,.08); border-left:8px solid rgba(255,255,255,.55); border-radius:16px;
        padding:20px 30px; box-shadow:0 10px 30px rgba(0,0,0,.18); }}
  .footer {{ margin-top:auto; display:flex; justify-content:space-between; align-items:center; }}
  .brand {{ font-family:{BODY_STACK}; font-weight:800; font-size:24px; letter-spacing:5px; text-transform:uppercase;
            color:rgba(255,255,255,.62); }}
  .dots {{ display:flex; gap:12px; }}
  .dot {{ width:14px; height:14px; border-radius:50%; background:rgba(255,255,255,.26); }}
  .dot.on {{ background:#fff; box-shadow:0 0 0 6px rgba(255,255,255,.18); }}
</style></head><body>
  <div class="blob b1"></div><div class="blob b2"></div>
  <div class="frame">
    <div class="topbar">
      <div class="kicker">{html.escape(slide['kicker'])}</div>
      <div class="counter">{idx:02d} / {total:02d}</div>
    </div>
    <div class="head">
      <div class="emoji">{html.escape(slide['emoji'])}</div>
      <div><h1 class="{slide.get('h1cls', '')}">{html.escape(slide['headline'])}</h1>{sub}</div>
    </div>
    <ul>{bullets_html}</ul>
    <div class="footer">
      <div class="brand">Mythos Readiness · SOC Analyst Prep</div>
      <div class="dots">{dots}</div>
    </div>
  </div>
</body></html>"""


# Acronyms the TTS engine spells out letter-by-letter or otherwise mangles.
# These rewrites apply to the spoken narration ONLY — the on-screen slide text
# keeps the real spelling. "SOC" is said as a word ("sock"), not "S-O-C".
_TTS_PHONETIC = {
    r"\bSOCs\b": "socks",
    r"\bSOC\b": "sock",
}


def _phonetic_for_tts(text: str) -> str:
    """Rewrite known mispronounced acronyms phonetically for narration audio."""
    for pattern, repl in _TTS_PHONETIC.items():
        text = re.sub(pattern, repl, text)
    return text


def _generate_narration(text: str, out_path: Path) -> None:
    """Write an mp3 narration to out_path via Kokoro (gTTS fallback)."""
    text = _phonetic_for_tts(text)
    if TTS_PROVIDER == "kokoro":
        try:
            resp = requests.post(
                f"{KOKORO_URL}/v1/audio/speech",
                json={"input": text, "voice": KOKORO_VOICE, "response_format": "mp3"},
                timeout=180,
            )
            resp.raise_for_status()
            out_path.write_bytes(resp.content)
            return
        except Exception as exc:  # noqa: BLE001 — fall back to gTTS on any Kokoro failure
            print(f"    Kokoro unavailable ({exc}); falling back to gTTS", file=sys.stderr)
    from gtts import gTTS
    gTTS(text=text, lang="en", tld="co.uk", slow=False).save(str(out_path))


def _build_segment(slide_png: Path, narration_audio: Path, out_mp4: Path) -> None:
    subprocess.run(
        [
            "ffmpeg", "-y", "-loglevel", "error",
            "-loop", "1", "-i", str(slide_png),
            "-i", str(narration_audio),
            "-c:v", "libx264", "-tune", "stillimage", "-pix_fmt", "yuv420p",
            "-c:a", "aac", "-b:a", "192k",
            "-shortest",
            str(out_mp4),
        ],
        check=True,
    )


def _concat_segments(segments: list[Path], out_mp4: Path) -> None:
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        for seg in segments:
            f.write(f"file '{seg.absolute()}'\n")
        list_path = f.name
    try:
        subprocess.run(
            [
                "ffmpeg", "-y", "-loglevel", "error",
                "-f", "concat", "-safe", "0",
                "-i", list_path,
                "-c", "copy",
                str(out_mp4),
            ],
            check=True,
        )
    finally:
        Path(list_path).unlink(missing_ok=True)


def _fallback_bullets(text: str, n: int = 3) -> list[str]:
    """If a slide has no authored bullets, derive short ones from the prose so
    the screen still stays scannable rather than dumping the paragraph."""
    sentences = [s.strip() for s in text.replace("\n", " ").split(". ") if s.strip()]
    out = []
    for s in sentences[:n]:
        words = s.split()
        out.append(" ".join(words[:11]) + ("…" if len(words) > 11 else ""))
    return out or [text[:80]]


def _build_slides(topic: dict) -> list[dict]:
    title = topic["title"]
    concepts = topic.get("key_concepts", [])
    total = 2 + len(concepts)
    slides: list[dict] = []

    # Title slide
    slides.append({
        "kind": "title", "pal": TITLE_PAL, "kicker": "Mythos Prep",
        "emoji": topic.get("icon", "🎓"), "headline": title,
        "sub": f"Tier {topic['tier']} · SOC analyst readiness" if topic.get("tier") else "SOC analyst readiness",
        "bullets": topic.get("intro_bullets") or _fallback_bullets(topic.get("summary", "")),
        "narration": f"{title}. {topic.get('summary', '').strip()}",
    })
    # Why-risky slide
    slides.append({
        "kind": "risk", "pal": RISK_PAL, "kicker": "Why it matters",
        "emoji": "⚠️", "headline": f"Why {title} is risky", "h1cls": "small",
        "bullets": topic.get("risk_bullets") or _fallback_bullets(topic.get("why_risky", "")),
        "narration": f"Why {title} is risky. {topic.get('why_risky', '').strip()}",
    })
    # Concept slides
    for i, c in enumerate(concepts):
        slides.append({
            "kind": "concept", "pal": PALETTES[i % len(PALETTES)],
            "kicker": f"Key concept {i + 1}", "emoji": c.get("icon", "📌"),
            "headline": c["title"], "h1cls": "small",
            "bullets": c.get("bullets") or _fallback_bullets(c.get("body", "")),
            "narration": f"{c['title']}. {c.get('body', '').strip()}",
        })

    for n, s in enumerate(slides, start=1):
        s["idx"], s["total"] = n, total
    return slides


def generate_video(topic_id: str) -> Path:
    from playwright.sync_api import sync_playwright

    topic_path = TOPICS_DIR / f"{topic_id}.yaml"
    if not topic_path.is_file():
        raise SystemExit(f"Topic not found: {topic_path}")
    with open(topic_path) as f:
        topic = yaml.safe_load(f)

    VIDEOS_DIR.mkdir(parents=True, exist_ok=True)
    workdir = Path(tempfile.mkdtemp(prefix=f"lesson_{topic_id}_"))

    slides = _build_slides(topic)
    total = len(slides)
    print(f"Generating {total} slides for {topic_id}...")

    segments: list[Path] = []
    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--force-color-profile=srgb"])
        page = browser.new_context(viewport={"width": WIDTH, "height": HEIGHT},
                                   device_scale_factor=1).new_page()
        for s in slides:
            i = s["idx"]
            slide_png = workdir / f"slide_{i:02d}.png"
            narration_mp3 = workdir / f"slide_{i:02d}.mp3"
            segment_mp4 = workdir / f"slide_{i:02d}.mp4"

            page.set_content(_slide_html(s), wait_until="networkidle")
            page.wait_for_timeout(250)
            page.screenshot(path=str(slide_png))
            _generate_narration(s["narration"], narration_mp3)
            _build_segment(slide_png, narration_mp3, segment_mp4)
            segments.append(segment_mp4)
            print(f"  [{i}/{total}] {s['headline']}")
        browser.close()

    out_path = VIDEOS_DIR / f"{topic_id}.mp4"
    _concat_segments(segments, out_path)
    shutil.rmtree(workdir, ignore_errors=True)
    print(f"\n✓ Wrote {out_path}")
    return out_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a training video for a lesson topic.")
    parser.add_argument("topic", help="Topic ID, e.g. 'citrix'")
    args = parser.parse_args()
    if not shutil.which("ffmpeg"):
        print("ERROR: ffmpeg not found in PATH.", file=sys.stderr)
        return 1
    generate_video(args.topic)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
