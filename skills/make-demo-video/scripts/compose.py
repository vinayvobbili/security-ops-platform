"""Stitch recorded webm + per-scene narration MP3s into final MP4.

For each scene: take the video segment, adjust its playback speed (setpts)
so its duration matches the scene's narration MP3 exactly, then concat all
scenes, mux with concatenated audio, burn in captions, export 1080p MP4.
"""
import subprocess
import sys
from pathlib import Path

import imageio_ffmpeg

FFMPEG = imageio_ffmpeg.get_ffmpeg_exe()
HERE = Path(__file__).parent
VIDEO_DIR = HERE / "video"
AUDIO_DIR = HERE / "audio"
WORK_DIR = HERE / "work"
WORK_DIR.mkdir(exist_ok=True)
OUT_DIR = HERE / "output"
OUT_DIR.mkdir(exist_ok=True)

RAW_VIDEO = VIDEO_DIR / "<feature>_demo_raw.webm"  # rename per video
TIMINGS = VIDEO_DIR / "scene_timings.txt"
FINAL_MP4 = OUT_DIR / "<feature>_demo_final.mp4"   # rename per video

# Optional bed music. Tracks live in <repo>/web/static/audio/ (Pixabay royalty-free).
# PICK A DIFFERENT TRACK PER VIDEO so demos don't all sound the same. Set MUSIC = None
# to skip, or point at any mp3 in that dir. MUSIC_VOLUME is a fraction (1.0 = full).
MUSIC = HERE.parents[2] / "web" / "static" / "audio" / "kornevmusic-upbeat-happy-corporate-487426.mp3"
MUSIC_VOLUME = 0.12  # 12% — present under narration without fighting the voice

# Title slide + outro freeze bookend the video so it doesn't start/end abruptly.
# LEAD_IN: music-only intro with a branded title card.
# OUTRO:   hold the last frame while music fades out.
LEAD_IN_SECONDS = 2.0
OUTRO_SECONDS = 2.0
TITLE_TEXT = "<Feature Name>"        # rename per video
SUBTITLE_TEXT = "<one-line subtitle>" # rename per video


def run(cmd, log=True):
    if log:
        print(f"$ {' '.join(cmd)[:200]}")
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print("STDERR:", r.stderr[-2000:])
        raise SystemExit(f"ffmpeg failed: {cmd[:3]}")
    return r


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


def load_scene_plan():
    """Returns list of dicts: {id, video_start, video_end, audio_dur}."""
    audio_durs = {}
    for line in (AUDIO_DIR / "durations.txt").read_text().splitlines():
        sid, d = line.split("\t")
        audio_durs[sid] = float(d)

    scenes = []
    lines = TIMINGS.read_text().splitlines()[1:]  # skip header
    prev_end = 0.0
    for line in lines:
        sid, start, end, dur = line.split("\t")
        start = float(start)
        end = float(end)
        scenes.append({
            "id": sid,
            "video_start": prev_end,      # start from prev end so we don't lose pre-roll
            "video_end": end,
            "audio_dur": audio_durs[sid],
            "audio_file": AUDIO_DIR / f"{sid}.mp3",
        })
        prev_end = end
    return scenes


def build_video_clips(scenes):
    """Extract each scene's video slice, rescale duration to match audio."""
    clip_paths = []
    for i, sc in enumerate(scenes):
        sid = sc["id"]
        video_dur = sc["video_end"] - sc["video_start"]
        audio_dur = sc["audio_dur"]
        # setpts factor: output_dur = input_dur * factor
        # target output_dur = audio_dur, so factor = audio_dur / video_dur
        factor = audio_dur / video_dur
        out = WORK_DIR / f"{i:02d}_{sid}.mp4"
        print(f"[{sid}] video_dur={video_dur:.2f}s  audio_dur={audio_dur:.2f}s  factor={factor:.3f}x")
        # Use setpts to adjust speed (we can slow down or speed up)
        # -vf "setpts=FACTOR*PTS"  where FACTOR = audio_dur/video_dur
        run([
            FFMPEG, "-y",
            "-ss", f"{sc['video_start']:.3f}",
            "-to", f"{sc['video_end']:.3f}",
            "-i", str(RAW_VIDEO),
            "-vf", f"setpts={factor:.6f}*PTS,scale=1920:1080,fps=30",
            "-an",
            "-c:v", "libx264", "-preset", "veryfast", "-crf", "22",
            "-pix_fmt", "yuv420p",
            str(out),
        ])
        clip_paths.append(out)
    return clip_paths


def concat_audio(scenes):
    """Concat per-scene MP3s into a single AAC track."""
    list_file = WORK_DIR / "audio_list.txt"
    list_file.write_text("\n".join(f"file '{sc['audio_file']}'" for sc in scenes))
    out = WORK_DIR / "narration.m4a"
    run([
        FFMPEG, "-y", "-f", "concat", "-safe", "0", "-i", str(list_file),
        "-c:a", "aac", "-b:a", "192k",
        str(out),
    ])
    return out


def concat_video_clips(clip_paths):
    list_file = WORK_DIR / "video_list.txt"
    list_file.write_text("\n".join(f"file '{p}'" for p in clip_paths))
    out = WORK_DIR / "video_concat.mp4"
    run([
        FFMPEG, "-y", "-f", "concat", "-safe", "0", "-i", str(list_file),
        "-c", "copy",
        str(out),
    ])
    return out


def mix_with_music(narration: Path, music: Path, total_dur: float) -> Path:
    """Mix narration with a ducked music bed. Narration is delayed by LEAD_IN_SECONDS so
    the music plays alone under the title slide; music then fades out during the outro."""
    out = WORK_DIR / "mixed_audio.m4a"
    fade = 1.5
    lead_ms = int(LEAD_IN_SECONDS * 1000)
    fc = (
        f"[0:a]adelay={lead_ms}|{lead_ms}[narr];"
        f"[1:a]volume={MUSIC_VOLUME},"
        f"afade=t=in:st=0:d={fade},"
        f"afade=t=out:st={max(0.0, total_dur - fade):.3f}:d={fade}"
        f"[bed];"
        f"[narr][bed]amix=inputs=2:duration=longest:dropout_transition=0[a]"
    )
    run([
        FFMPEG, "-y",
        "-i", str(narration),
        "-stream_loop", "-1", "-i", str(music),
        "-filter_complex", fc,
        "-map", "[a]",
        "-t", f"{total_dur:.3f}",
        "-c:a", "aac", "-b:a", "192k",
        str(out),
    ])
    return out


def make_title_slide(title: str, subtitle: str) -> Path:
    """Render a 1920x1080 title card PNG — navy-to-brand-blue gradient, centered title + subtitle."""
    from PIL import Image, ImageDraw, ImageFont
    W, H = 1920, 1080
    img = Image.new("RGB", (W, H), "#0b1e3a")
    top = (11, 30, 58)
    bot = (27, 63, 126)
    px = img.load()
    for y in range(H):
        t = y / (H - 1)
        r = int(top[0] + (bot[0] - top[0]) * t)
        g = int(top[1] + (bot[1] - top[1]) * t)
        b = int(top[2] + (bot[2] - top[2]) * t)
        for x in range(W):
            px[x, y] = (r, g, b)
    draw = ImageDraw.Draw(img)
    title_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 140)
    sub_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 56)
    tb = draw.textbbox((0, 0), title, font=title_font)
    tw, th = tb[2] - tb[0], tb[3] - tb[1]
    draw.text(((W - tw) / 2, H / 2 - th - 20), title, font=title_font, fill="#ffffff")
    sb = draw.textbbox((0, 0), subtitle, font=sub_font)
    sw = sb[2] - sb[0]
    draw.text(((W - sw) / 2, H / 2 + 40), subtitle, font=sub_font, fill="#cbd8ea")
    bar_w, bar_h = 180, 6
    draw.rectangle(
        [((W - bar_w) / 2, H / 2 + 150), ((W + bar_w) / 2, H / 2 + 150 + bar_h)],
        fill="#60a5fa",
    )
    out = WORK_DIR / "title_slide.png"
    img.save(out)
    return out


def append_outro_freeze(video: Path, seconds: float) -> Path:
    """Hold the last frame for `seconds` so the closer doesn't end abruptly."""
    out = WORK_DIR / "video_with_outro.mp4"
    run([
        FFMPEG, "-y", "-i", str(video),
        "-vf", f"tpad=stop_duration={seconds}:stop_mode=clone",
        "-c:v", "libx264", "-preset", "veryfast", "-crf", "22",
        "-pix_fmt", "yuv420p",
        "-an",
        str(out),
    ])
    return out


def prepend_title_slide(video: Path, title: str, subtitle: str, seconds: float) -> Path:
    """Generate a title slide PNG, turn it into a `seconds`-long clip, concat before main video."""
    slide_png = make_title_slide(title, subtitle)
    slide_mp4 = WORK_DIR / "title_slide.mp4"
    run([
        FFMPEG, "-y",
        "-loop", "1", "-t", f"{seconds}", "-i", str(slide_png),
        "-vf", "scale=1920:1080,fps=30",
        "-c:v", "libx264", "-preset", "veryfast", "-crf", "22",
        "-pix_fmt", "yuv420p",
        "-an",
        str(slide_mp4),
    ])
    list_file = WORK_DIR / "intro_list.txt"
    list_file.write_text(f"file '{slide_mp4}'\nfile '{video}'\n")
    out = WORK_DIR / "video_with_intro.mp4"
    run([
        FFMPEG, "-y", "-f", "concat", "-safe", "0", "-i", str(list_file),
        "-c", "copy",
        str(out),
    ])
    return out


def mux_final(video: Path, audio: Path, out: Path):
    run([
        FFMPEG, "-y", "-i", str(video), "-i", str(audio),
        "-c:v", "copy", "-c:a", "copy",
        "-map", "0:v:0", "-map", "1:a:0",
        "-shortest",
        str(out),
    ])


def main():
    scenes = load_scene_plan()
    print(f"Loaded {len(scenes)} scenes")
    clips = build_video_clips(scenes)
    video = concat_video_clips(clips)
    narration = concat_audio(scenes)
    narration_dur = probe_duration(narration)
    if MUSIC and MUSIC.exists():
        print(f"\nMixing in bed music: {MUSIC.name} (volume={MUSIC_VOLUME}), lead-in={LEAD_IN_SECONDS}s, outro={OUTRO_SECONDS}s")
        total_dur = narration_dur + LEAD_IN_SECONDS + OUTRO_SECONDS
        audio = mix_with_music(narration, MUSIC, total_dur)
        video = append_outro_freeze(video, OUTRO_SECONDS)
        video = prepend_title_slide(video, TITLE_TEXT, SUBTITLE_TEXT, LEAD_IN_SECONDS)
    else:
        audio = narration
    mux_final(video, audio, FINAL_MP4)
    dur = probe_duration(FINAL_MP4)
    size_mb = FINAL_MP4.stat().st_size / 1024 / 1024
    print(f"\n✓ Final: {FINAL_MP4}")
    print(f"  Duration: {dur:.2f}s ({dur/60:.2f} min)")
    print(f"  Size: {size_mb:.1f} MB")


if __name__ == "__main__":
    main()
