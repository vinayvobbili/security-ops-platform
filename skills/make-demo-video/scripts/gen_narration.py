"""Generate per-scene TTS narration MP3s and report durations.

Default provider is Kokoro (mac-m3, lab-vm:8021). Set TTS_PROVIDER=gtts to
fall back to gTTS. Kokoro produces much more natural voices.
"""
import os
import subprocess
from pathlib import Path

import imageio_ffmpeg
import requests

from scenes import SCENES

OUT_DIR = Path(__file__).parent / "audio"
OUT_DIR.mkdir(exist_ok=True)
FFMPEG = imageio_ffmpeg.get_ffmpeg_exe()

TTS_PROVIDER = os.environ.get("TTS_PROVIDER", "kokoro")
KOKORO_URL = os.environ.get("KOKORO_URL", "http://127.0.0.1:8021")
KOKORO_VOICE = os.environ.get("KOKORO_VOICE", "af_heart")


def probe_duration(path: Path) -> float:
    r = subprocess.run(
        [FFMPEG, "-i", str(path), "-f", "null", "-"],
        capture_output=True, text=True,
    )
    for line in r.stderr.splitlines():
        if "Duration:" in line:
            t = line.split("Duration:")[1].split(",")[0].strip()
            h, m, s = t.split(":")
            return int(h) * 3600 + int(m) * 60 + float(s)
    return 0.0


def gen_kokoro(text: str, out: Path, voice: str = KOKORO_VOICE):
    r = requests.post(
        f"{KOKORO_URL}/v1/audio/speech",
        json={"input": text, "voice": voice, "response_format": "mp3"},
        timeout=120,
    )
    r.raise_for_status()
    out.write_bytes(r.content)


def gen_gtts(text: str, out: Path):
    from gtts import gTTS
    gTTS(text=text, lang="en", tld="co.uk", slow=False).save(str(out))


def main():
    print(f"TTS provider: {TTS_PROVIDER}  voice: {KOKORO_VOICE if TTS_PROVIDER == 'kokoro' else 'gtts'}")
    durations = {}
    for scene in SCENES:
        sid = scene["id"]
        out = OUT_DIR / f"{sid}.mp3"
        print(f"[{sid}] generating...")
        if TTS_PROVIDER == "kokoro":
            gen_kokoro(scene["narration"], out)
        else:
            gen_gtts(scene["narration"], out)
        dur = probe_duration(out)
        durations[sid] = dur
        print(f"   → {out.name}  {dur:.2f}s  ({len(scene['narration'])} chars)")

    total = sum(durations.values())
    print(f"\nTotal narration: {total:.2f}s  (~{total/60:.2f} min)")

    durfile = OUT_DIR / "durations.txt"
    with open(durfile, "w") as f:
        for sid, d in durations.items():
            f.write(f"{sid}\t{d:.3f}\n")
    print(f"Durations written to {durfile}")


if __name__ == "__main__":
    main()
