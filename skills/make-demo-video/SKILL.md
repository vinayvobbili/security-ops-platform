---
name: make-demo-video
description: Produce a narrated screencast video of a web UI feature — drive headless Chrome through a scripted walkthrough, generate TTS narration, composite per-scene-synced MP4 plus a short Webex/Slack teaser. Use when the user asks to "make a demo video", "record a walkthrough", "produce a teaser", or similar for any web feature they own.
---

# Demo Video Production

Build a narrated 1080p screencast of a web UI feature. Output: a full-length MP4 (typically 2-4 min) plus a short teaser cut with a call-to-action end card.

## When to use this skill

- User wants a polished video walking through a feature of a web app they own and can reach from the machine
- They want a teaser cut for chat/email distribution
- They're OK with a TTS narrator or plan to swap in a human voice later

**Don't** use this for:
- Videos that need a human avatar (HeyGen, Synthesia territory — needs their account/face)
- Recording someone else's live session (requires screen capture of a real display, not possible headlessly)
- Videos requiring tight lip-sync to a specific speaker

## Workflow (stick to this order)

### 1. Align on the story, not the tech

A demo video sells a **value proposition**, not a feature tour. If a viewer finishes and can only say "cool UI," the video failed. They should be able to say "this saves us N hours a week" or "this closes a gap that was costing us X."

Before any code, pin down:

- **Audience**: who's watching? Team demo, stakeholder pitch, onboarding? Exec pitches need dollars and hours; team demos can lean on workflow pain.
- **Perspective**: first-person user ("I'm an analyst and I..."), narrator, marketing?
- **Problem statement**: what was broken/slow/risky *before* this existed? Be concrete — "analysts spent 20 min per ticket chasing context across 4 tools" beats "hard to investigate."
- **Value proposition (quantified)**: what does this feature change, in numbers? Ask the user for real figures — don't invent them. Examples:
  - Time: "15 min → 2 min per case" / "saves ~6 hrs/week per analyst"
  - Dollars: "~$Xk/yr at N analysts × loaded rate" / "avoided headcount of 0.5 FTE"
  - Risk/coverage: "caught X% more detections" / "closed a blind spot in Y"
  - Volume: "handles 200 cases/day vs. 30 manually"
  If the user doesn't have numbers yet, help them derive a defensible estimate (frequency × time-per-use × people-affected × loaded hourly rate) and call it out as an estimate in the narration.
- **Hero case**: pick ONE specific record/case the video orbits around. Real data always beats staged — ask if real data is OK (privacy), and pick a row with enough richness to populate every feature you'll show *and* make the pain tangible.
- **Length**: default to ~3 minutes. Any longer loses attention; shorter undersells.
- **Script beats**: 6–9 scenes. Structure them around the value arc, not the feature list:
  1. **Hook / problem** — the pain, stated in the viewer's language. ("Every time a tipper lands, an analyst burns 20 minutes stitching context from 4 tools.")
  2. **Stakes** — why this matters in time/$/risk terms. Drop the headline number here.
  3. **Before state (optional)** — show the old workflow briefly if it makes the contrast land. Skip if it pads the runtime.
  4. **Solution walkthrough** — 3–5 scenes on the actual feature, each tied back to a pain point from beat 1.
  5. **Payoff** — restate the quantified win with the feature now visible behind it. ("That 20 minutes is now 90 seconds.")
  6. **Close / CTA** — takeaway + one-line call to action (try it, request access, ping #channel).
  Each scene gets one or two sentences of conversational narration. Every feature beat should implicitly answer "so what?"

**Ask the user to confirm** audience, problem statement, quantified value prop, hero case, and draft scene list before recording anything. Getting the story right here — especially the numbers — saves a full re-record later.

### 2. Set up the per-video project directory

Each video gets its own directory — never edit the skill's `scripts/` in place.

```bash
mkdir -p <repo>/demos/videos/<feature>
cp ~/.claude/skills/make-demo-video/scripts/*.py <repo>/demos/videos/<feature>/
cd <repo>/demos/videos/<feature>
```

Then edit:
- **`scenes.py`** — replace `SCENES` with the per-video narration (one entry per scene, with a stable `id` like `"01_hook"`)
- **`record.py`** — replace the Playwright flow with the UI walk-through for THIS feature (see "Playwright recording gotchas" below)
- **`compose.py`** — update `RAW_VIDEO` / `FINAL_MP4` filenames to match `<feature>`, set `TITLE_TEXT` / `SUBTITLE_TEXT` for the opening slide (see "Intro and outro" below), and pick a **bed music track** from `web/static/audio/` for `MUSIC` (see "Music" below — use a different track per video)
- **`build_teaser.py`** — only if making a teaser: update `BEATS` with teaser narration (problem → curiosity gap → CTA) and source timestamps from your raw recording

### 3. Prerequisite check

Run from the project dir:

```bash
.venv/bin/python -c "import playwright, imageio_ffmpeg, gtts; from PIL import Image; print('OK')"
.venv/bin/playwright install chromium
```

Confirm the web app is reachable: `curl -I http://localhost:<port>/<path>`.

### 4. Run the pipeline

```bash
# 1. Generate per-scene narration MP3s (writes audio/<scene_id>.mp3 + durations.txt)
.venv/bin/python gen_narration.py

# 2. Drive the UI and record  (writes video/<feature>_demo_raw.webm + scene_timings.txt)
.venv/bin/python record.py

# 3. Compose: split recording into scenes, speed-match each to its narration,
#    concat, mux audio  (writes output/*_final.mp4)
.venv/bin/python compose.py
```

**Teasers are opt-in, not part of the default pipeline.** Full videos are usually hosted on the web app directly, so a short teaser cut isn't needed. `build_teaser.py` is still in `scripts/` if you want one (edit its `BEATS` and run `.venv/bin/python build_teaser.py`), but only copy it into a per-video dir when you actually plan to use it.

## Intro and outro

Every video gets:

- **Title slide** at the front (2 s, brand-blue gradient, centered title + subtitle)
- **Closing scene** as the last narrated scene — verbal conclusion that reframes what was shown ("from X to Y", takeaway, one-line CTA). Don't end on the last feature beat; audiences need a proper wrap-up line.
- **Outro card** after the closing narration (2 s hold, same brand-blue style as the title slide but with a "takeaway → built with X" framing, e.g. title `"From war room to platform"` / subtitle `"Built with Claude Code"`). Add this as a final scene (id `NN_outro`) pointing at a generated `slide_outro.png`, not a frozen last frame of content.
- **Music bed fade-out over the outro card.** No separate sting — earlier demos mixed in a descending piano sting (G4 → E4 → C4) but it reads as sad/funereal against upbeat corporate beds. Letting the bed music fade out over `OUTRO_SECONDS` using `afade=t=out` feels cleaner and more natural. `mix_with_music` takes two inputs (narration, bed); no third sting track.

Set these in `compose.py` / `build.py`:

- `TITLE_TEXT` — the feature name (e.g. `"Meeting Recap"`, `"RUAI Reviewer"`). Keep it short — a full 1920px wide row in 140pt bold.
- `SUBTITLE_TEXT` — one-line description (e.g. `"AI-assisted security review"`). Smaller, lighter weight.
- `LEAD_IN_SECONDS` / `OUTRO_SECONDS` — both default to 2.0 s. Don't change unless you have a reason.

The title + outro cards are generated by PIL (`make_title_slide`, `_render_outro_slide.py`) so there's nothing to design externally. Fonts are DejaVu Sans Bold / Regular from the system.

**Poster / thumbnail**: use the title slide (not the first content frame) as the `<video poster>` JPG. A branded title card reads cleanly at thumbnail scale and sets expectations; a random first frame (half-rendered UI, mid-transition) looks accidental. In `compose.py` / `build.py`: `make_poster(WORK_DIR / "title_slide.png", poster)`.

## Music

Royalty-free (Pixabay license) tracks are pre-downloaded to `<repo>/web/static/audio/`. They have no vocals and fit 2–3 min demos:

- `kornevmusic-upbeat-happy-corporate-487426.mp3` — upbeat, happy
- `hitslab-corporate-corporate-music-481124.mp3` — standard corporate
- `nastelbom-corporate-440511.mp3` / `nastelbom-corporate-corporate-background-488317.mp3` — neutral background
- `paulyudin-corporate-corporate-music-478177.mp3` — energetic
- `the_mountain-corporate-corporate-music-483810.mp3` — driving
- `watermello-corporate-corporate-music-477144.mp3` — bright
- `inspirational-uplifting-calm-piano-254764.mp3` — calm, reflective (good for thoughtful/story-driven cuts)

**Pick a different track per video** so consecutive demos don't sound identical. Set `MUSIC` in `compose.py`; `MUSIC_VOLUME = 0.12` (12%) is usually right — present under the narration without fighting the voice. `compose.py` loops the track to cover the full runtime and fades it in/out over 1.5 s at the edges. Set `MUSIC = None` to skip.

To add a new track: download from pixabay.com/music into `web/static/audio/` using the pattern `<uploader>-<genre>-<slug>.mp3` so the source is obvious later.

### 5. Review, iterate, ship

- Watch the full video after compose. Common fixes: narration word choice, scenes over/undershooting, missed clicks, modal didn't open.
- For minor narration tweaks, edit `scenes.py` and re-run only `gen_narration.py` + `compose.py` (skip `record.py`).
- For UI flow changes, re-run `record.py` (which re-captures `scene_timings.txt`), then `compose.py`.
- Confirm distribution plan with the user before sending anything. Posting videos to shared channels is visible-to-others and can't be unposted.

## Playwright recording gotchas (learned the hard way)

These are load-bearing defaults. Don't change without reason.

1. **Never use `wait_until="networkidle"`** for page navigations — if the UI holds an open stream (chat widget, polling), networkidle never fires. Use `wait_until="domcontentloaded"` followed by a fixed `page.wait_for_timeout(1500)`.
2. **Close stateful widgets before navigating** — chat widgets, live tail panels, WebSocket connections. Pending requests can block the next `goto`.
3. **Smooth mouse moves are slow in headless** — `page.mouse.move(x, y, steps=N)` with N>20 adds multi-second latency. Use `steps=10-15` max for cosmetic moves.
4. **Scene durations will drift from narration** — accept this. The `Pacer` class logs exact scene boundaries; `compose.py` uses those plus the narration durations to apply per-scene `setpts` speedup/slowdown so the final video syncs to audio.
5. **Don't click actions that take >10s** (AI re-runs, long searches). Hover over the button to draw attention, but don't actually click — narration can describe the effect without waiting for it.
6. **Scroll smoothly** — call `scroll_by()` helper (small steps, short per-step delay) rather than one giant wheel event. Looks more natural.

## Voice options

**Default: Kokoro on mac-m3** (OpenAI-compatible service at `http://127.0.0.1:8021` via reverse SSH tunnel). Natural-sounding, free, local. 54 voices available — default `af_heart` (adult female, American English). Pick another by setting `KOKORO_VOICE=af_nova` (or any other) before running `gen_narration.py`. To list all voices: `curl http://127.0.0.1:8021/v1/voices`.

Fallback: `TTS_PROVIDER=gtts` reverts to gTTS (robotic but dependency-free).

Quality ladder if you want to go further:

| Option | Quality | Setup | Cost | When to use |
|---|---|---|---|---|
| **Kokoro on mac-m3** (default) | Very good | Already running | Free, local | Every video unless something specific needs better |
| **gTTS** | Robotic | None | Free | Offline fallback when mac-m3 unreachable |
| **ElevenLabs free tier** | Excellent | API key | 10k chars/month free (≈ 8-10 demos) | Stakeholder-polished one-off |
| **Human recording** | Best | Record WAV, drop into `audio/<scene_id>.mp3` | Your time | When the demo matters a lot and you have 30 min |
| **XTTS v2 voice clone** | Very good + sounds like you | Record 10s sample, Coqui XTTS on a Mac | Free, local | One-time setup, reusable forever |

**To swap TTS provider:** edit `gen_narration.py`'s Kokoro HTTP call to hit a different endpoint and save the MP3 at the same path. Everything downstream (durations, composition) is format-agnostic — it just needs an MP3 per scene.

**To use a human voice:** record a WAV per scene (Voice Memos, Audacity), convert to MP3, place at `audio/<scene_id>.mp3` — skip `gen_narration.py` entirely, but write `audio/durations.txt` manually (one line per scene: `<id>\t<seconds>`).

## What to always ask the user

- **Before recording**: audience, hero case, real-vs-staged data, distribution plan (internal-only? shared externally?)
- **After first cut**: is the narration landing? Any scenes too fast/slow? Any privacy concerns now that real data is visible?
- **Before sending**: approve the exact message text and target channel/group. Posts are visible-to-others and not easily undone.

## Reference: working example

`~/security-ops-platform/demos/videos/ruai/` — the RUAI Reviewer workflow demo built with this skill. 3:39 full cut, 28s teaser. Read it end-to-end if you're unsure how the pieces fit; don't copy from it blind — per-video `scenes.py` and `record.py` are always rewritten, not derived.
