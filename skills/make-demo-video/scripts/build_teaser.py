"""Build a real 30-second teaser: problem → curiosity gap → CTA.

- Visuals: pull short clips from the raw recording that *establish the problem*
  (cluttered dashboard) and *hint at the solution* (quick flash of the AI panel),
  then end on a static call-to-action card.
- Narration: separate teaser script, NOT the full video's opening.
"""
import subprocess
from pathlib import Path

import imageio_ffmpeg
import os
import requests

TTS_PROVIDER = os.environ.get("TTS_PROVIDER", "kokoro")
KOKORO_URL = os.environ.get("KOKORO_URL", "http://127.0.0.1:8021")
KOKORO_VOICE = os.environ.get("KOKORO_VOICE", "af_heart")

FFMPEG = imageio_ffmpeg.get_ffmpeg_exe()
HERE = Path(__file__).parent
WORK = HERE / "work_teaser"
WORK.mkdir(exist_ok=True)
OUT = HERE / "output" / "ruai_demo_teaser_30s.mp4"
RAW = HERE / "video" / "ruai_demo_raw.webm"

# Three narration beats, generated separately for tighter timing control
BEATS = [
    {
        "id": "01_problem",
        "text": (
            "As an R.U.A.I. reviewer, every new A.I. use case used to mean "
            "forty pages of reading, hunting for the risky bits. "
            "And the queue never stopped growing."
        ),
        "video_src_start": 14.0,
        "video_src_end": 28.0,
    },
    {
        "id": "02_tease",
        "text": (
            "That's gone now. And not because we hired more people. "
            "The dashboard does the heavy lifting, and I want to show you how."
        ),
        "video_src_start": 78.0,
        "video_src_end": 92.0,
    },
    {
        "id": "03_cta",
        "text": (
            "I'm running a short walkthrough next week. "
            "If you're curious, message me for the meeting invite."
        ),
        "video_src_start": None,
        "video_src_end": None,
    },
]


def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print("STDERR:", r.stderr[-1500:])
        raise SystemExit(f"ffmpeg failed: {cmd[:4]}")
    return r


def probe_duration(path: Path) -> float:
    r = subprocess.run([FFMPEG, "-i", str(path), "-f", "null", "-"],
                       capture_output=True, text=True)
    for line in r.stderr.splitlines():
        if "Duration:" in line:
            t = line.split("Duration:")[1].split(",")[0].strip()
            h, m, s = t.split(":")
            return int(h) * 3600 + int(m) * 60 + float(s)
    return 0.0


def gen_audio(beat):
    out = WORK / f"{beat['id']}.mp3"
    if TTS_PROVIDER == "kokoro":
        r = requests.post(
            f"{KOKORO_URL}/v1/audio/speech",
            json={"input": beat["text"], "voice": KOKORO_VOICE, "response_format": "mp3"},
            timeout=120,
        )
        r.raise_for_status()
        out.write_bytes(r.content)
    else:
        from gtts import gTTS
        gTTS(text=beat["text"], lang="en", tld="co.uk", slow=False).save(str(out))
    beat["audio_path"] = out
    beat["audio_dur"] = probe_duration(out)
    print(f"  audio {beat['id']}: {beat['audio_dur']:.2f}s")


def make_end_card(target_dur: float) -> Path:
    """Static end card: PIL-rendered PNG looped as a video."""
    from PIL import Image, ImageDraw, ImageFont
    png = WORK / "endcard.png"
    img = Image.new("RGB", (1920, 1080), (15, 23, 42))  # slate-900
    draw = ImageDraw.Draw(img)
    bold = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 80)
    reg  = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 56)
    accent = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 56)

    line1 = "Want to see how it all works?"
    line2 = "Reach out for the demo invite."

    def center(text, font, y, fill):
        bbox = draw.textbbox((0, 0), text, font=font)
        w = bbox[2] - bbox[0]
        draw.text(((1920 - w) // 2, y), text, fill=fill, font=font)

    center(line1, bold, 420, (255, 255, 255))
    center(line2, accent, 580, (96, 165, 250))  # blue-400
    # Subtle bottom-right watermark
    foot = "RUAI Reviewer Workflow Demo"
    bbox = draw.textbbox((0, 0), foot, font=reg)
    draw.text((1920 - (bbox[2] - bbox[0]) - 60, 1080 - 80), foot,
              fill=(100, 116, 139), font=reg)
    img.save(png)

    out = WORK / "endcard.mp4"
    run([
        FFMPEG, "-y",
        "-loop", "1", "-framerate", "30", "-t", f"{target_dur:.3f}",
        "-i", str(png),
        "-vf", "fps=30,format=yuv420p",
        "-c:v", "libx264", "-preset", "veryfast", "-crf", "20",
        str(out),
    ])
    return out


def slice_video(beat, idx):
    """Extract a clip from raw recording, rescale to match the beat's audio duration."""
    src_dur = beat["video_src_end"] - beat["video_src_start"]
    factor = beat["audio_dur"] / src_dur
    out = WORK / f"clip_{idx:02d}.mp4"
    run([
        FFMPEG, "-y",
        "-ss", f"{beat['video_src_start']:.3f}",
        "-to", f"{beat['video_src_end']:.3f}",
        "-i", str(RAW),
        "-vf", f"setpts={factor:.6f}*PTS,scale=1920:1080,fps=30",
        "-an",
        "-c:v", "libx264", "-preset", "veryfast", "-crf", "22", "-pix_fmt", "yuv420p",
        str(out),
    ])
    return out


def main():
    # 1) Generate narration for each beat
    print("Generating teaser narration...")
    for beat in BEATS:
        gen_audio(beat)

    # 2) Build per-beat video clips
    print("\nBuilding per-beat video clips...")
    clips = []
    for i, beat in enumerate(BEATS):
        if beat["video_src_start"] is None:
            # End card for the CTA beat
            clip = make_end_card(beat["audio_dur"])
        else:
            clip = slice_video(beat, i)
        clips.append(clip)

    # 3) Concat video clips
    print("\nConcatenating video...")
    vlist = WORK / "vlist.txt"
    vlist.write_text("\n".join(f"file '{c}'" for c in clips))
    vcat = WORK / "video_concat.mp4"
    run([FFMPEG, "-y", "-f", "concat", "-safe", "0", "-i", str(vlist),
         "-c", "copy", str(vcat)])

    # 4) Concat audio
    alist = WORK / "alist.txt"
    alist.write_text("\n".join(f"file '{b['audio_path']}'" for b in BEATS))
    acat = WORK / "audio_concat.m4a"
    run([FFMPEG, "-y", "-f", "concat", "-safe", "0", "-i", str(alist),
         "-c:a", "aac", "-b:a", "192k", str(acat)])

    # 5) Mux
    print("\nMuxing final teaser...")
    run([FFMPEG, "-y", "-i", str(vcat), "-i", str(acat),
         "-c:v", "copy", "-c:a", "copy",
         "-map", "0:v:0", "-map", "1:a:0", "-shortest",
         str(OUT)])

    dur = probe_duration(OUT)
    size_mb = OUT.stat().st_size / 1024 / 1024
    print(f"\n✓ Teaser: {OUT}")
    print(f"  Duration: {dur:.2f}s")
    print(f"  Size: {size_mb:.1f} MB")


if __name__ == "__main__":
    main()
