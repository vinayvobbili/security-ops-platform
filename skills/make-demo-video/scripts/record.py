"""Drive Chrome through the RUAI dashboard and record a continuous webm video
whose per-scene durations match the per-scene narration MP3s.

Output:  demos/videos/<feature>/video/<timestamp>.webm
"""
import time
from pathlib import Path

from playwright.sync_api import sync_playwright, Page

HERE = Path(__file__).parent
VIDEO_DIR = HERE / "video"
VIDEO_DIR.mkdir(exist_ok=True)

BASE = "http://localhost:8080"
HERO_ID = 10  # MLN Virtual Agent — 4 AI reviews, High risk

# Read per-scene target durations (seconds)
DURATIONS = {}
for line in (HERE / "audio" / "durations.txt").read_text().splitlines():
    sid, d = line.split("\t")
    DURATIONS[sid] = float(d)


class Pacer:
    """Records scene boundaries relative to wall-clock start of recording."""
    def __init__(self, page: Page):
        self.page = page
        self.scene_start = None
        self.scene_id = None
        self.recording_start = time.monotonic()
        self.log = []

    def begin(self, scene_id: str):
        self.scene_id = scene_id
        self.scene_start = time.monotonic()
        start_offset = self.scene_start - self.recording_start
        print(f"[{scene_id}] begin at {start_offset:.2f}s (audio target {DURATIONS[scene_id]:.1f}s)")

    def end(self):
        end_offset = time.monotonic() - self.recording_start
        actual = time.monotonic() - self.scene_start
        self.log.append((self.scene_id, end_offset - actual, end_offset, actual))
        print(f"[{self.scene_id}] end at {end_offset:.2f}s  actual {actual:.1f}s")

    def write_timings(self, path: Path):
        with open(path, "w") as f:
            f.write("scene_id\tstart_s\tend_s\tduration_s\n")
            for sid, start, end, dur in self.log:
                f.write(f"{sid}\t{start:.3f}\t{end:.3f}\t{dur:.3f}\n")


def smooth_move(page: Page, x: int, y: int, steps: int = 20):
    page.mouse.move(x, y, steps=steps)


def hover_locator(page: Page, locator, steps: int = 15):
    """Smoothly move mouse to the centre of a locator, then hover."""
    try:
        box = locator.bounding_box()
        if box:
            cx = int(box["x"] + box["width"] / 2)
            cy = int(box["y"] + box["height"] / 2)
            smooth_move(page, cx, cy, steps=steps)
    except Exception:
        pass


def scroll_by(page: Page, dy: int, over_ms: int = 1200, steps: int = 30):
    """Smoothly scroll the window by dy pixels over the given duration."""
    step_dy = dy / steps
    step_ms = int(over_ms / steps)
    for _ in range(steps):
        page.mouse.wheel(0, step_dy)
        page.wait_for_timeout(step_ms)


def scroll_element_into_view(page: Page, selector: str, block: str = "start"):
    page.evaluate(
        f"document.querySelector({selector!r})?.scrollIntoView({{behavior:'smooth', block:{block!r}}})"
    )


def run():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=["--no-sandbox"])
        context = browser.new_context(
            viewport={"width": 1920, "height": 1080},
            record_video_dir=str(VIDEO_DIR),
            record_video_size={"width": 1920, "height": 1080},
        )
        page = context.new_page()
        pacer = Pacer(page)

        # -------------------------------------------------------------
        # SCENE 01 — Hook  (dashboard loaded, mouse slowly pans)
        # -------------------------------------------------------------
        page.goto(f"{BASE}/ruai-dashboard", wait_until="domcontentloaded", timeout=30000)
        page.wait_for_timeout(1500)
        pacer.begin("01_hook")
        smooth_move(page, 960, 400, steps=10)
        page.wait_for_timeout(1000)
        smooth_move(page, 1500, 300, steps=10)
        page.wait_for_timeout(1000)
        pacer.end()

        # -------------------------------------------------------------
        # SCENE 02 — Dashboard overview (hover tiles → filter → scroll)
        # -------------------------------------------------------------
        pacer.begin("02_dashboard")
        # Hover through the stat tiles
        for i in range(5):
            tile = page.locator(".ruai-stats .ruai-stat").nth(i)
            hover_locator(page, tile, steps=12)
            page.wait_for_timeout(700)
        # Click "Needs Review" filter
        filt = page.locator('.ruai-filter-btn[data-filter="needs_review"]').first
        hover_locator(page, filt, steps=15)
        page.wait_for_timeout(300)
        filt.click()
        page.wait_for_timeout(800)
        # Hover a risk badge to draw attention
        badge = page.locator(".ruai-table tbody .ruai-risk-badge").first
        try:
            hover_locator(page, badge, steps=15)
        except Exception:
            pass
        page.wait_for_timeout(500)
        # Scroll the table a touch
        scroll_by(page, 200, over_ms=1500, steps=25)
        pacer.end()

        # -------------------------------------------------------------
        # SCENE 03 — AI first pass (open hero submission, walk the panel)
        # -------------------------------------------------------------
        pacer.begin("03_ai_first_pass")
        page.goto(f"{BASE}/ruai-dashboard/{HERO_ID}", wait_until="domcontentloaded", timeout=30000)
        page.wait_for_timeout(800)
        # Hover risk badge in header
        hover_locator(page, page.locator(".ruai-detail-header .ruai-risk-badge").first, steps=15)
        page.wait_for_timeout(1200)
        # Scroll smoothly through the AI review sections
        section_selectors = [
            ".ruai-detail-panel:nth-child(2) h3",  # AI Security Review header
            "h4:has-text('Security Risk by Domain')",
            "h4:has-text('Security Risk Flags')",
            "h4:has-text('Threat Boundary Analysis')",
            "h4:has-text('Clarifying Questions')",
            "h4:has-text('Review Summary')",
        ]
        for sel in section_selectors:
            try:
                loc = page.locator(sel).first
                if loc.count():
                    loc.scroll_into_view_if_needed(timeout=2000)
                    page.wait_for_timeout(1200)
            except Exception:
                pass
        pacer.end()

        # -------------------------------------------------------------
        # SCENE 04 — Re-run + Compare  (hover Re-run, click Compare)
        # -------------------------------------------------------------
        pacer.begin("04_rerun_compare")
        # Scroll back to header
        page.evaluate("window.scrollTo({top: 0, behavior: 'smooth'})")
        page.wait_for_timeout(1200)
        rerun = page.locator('button:has-text("Re-run AI Review")').first
        hover_locator(page, rerun, steps=20)
        page.wait_for_timeout(1800)
        compare = page.locator('button:has-text("Compare")').first
        hover_locator(page, compare, steps=18)
        page.wait_for_timeout(700)
        compare.click()
        page.wait_for_timeout(1500)
        # Scroll inside the modal if possible
        try:
            modal = page.locator(".ruai-modal, [id*='ompare']").first
            if modal.count():
                modal.evaluate("el => el.scrollTo({top: 200, behavior: 'smooth'})")
        except Exception:
            pass
        page.wait_for_timeout(2500)
        # Close modal (click outside or find close button)
        try:
            close_btn = page.locator('button:has-text("Close"), .modal-close, [onclick*="closeCompare"]').first
            if close_btn.count():
                close_btn.click()
            else:
                page.keyboard.press("Escape")
        except Exception:
            page.keyboard.press("Escape")
        page.wait_for_timeout(800)
        pacer.end()

        # -------------------------------------------------------------
        # SCENE 05 — Chat widget  (open, type a question, send)
        # -------------------------------------------------------------
        pacer.begin("05_chat")
        toggle = page.locator("#cwToggle").first
        hover_locator(page, toggle, steps=15)
        page.wait_for_timeout(400)
        toggle.click()
        page.wait_for_timeout(1200)
        # Click the "Risk summary" chip (canned question)
        try:
            chip = page.locator(".cw-chip").first
            hover_locator(page, chip, steps=15)
            page.wait_for_timeout(400)
            chip.click()
        except Exception:
            # Fallback: type a question
            inp = page.locator("#cwInput").first
            inp.click()
            for ch in "Was PII discussed in this submission?":
                page.keyboard.type(ch)
                page.wait_for_timeout(40)
            page.wait_for_timeout(400)
            page.locator("#cwSend").first.click()
        # Let the answer stream briefly
        page.wait_for_timeout(8000)
        # Close the chat widget so pending network requests don't block next navs
        try:
            page.locator("#cwClose").first.click(timeout=1500)
        except Exception:
            pass
        pacer.end()

        # -------------------------------------------------------------
        # SCENE 06 — Manage LLM Prompts
        # -------------------------------------------------------------
        pacer.begin("06_prompts")
        page.goto(f"{BASE}/ruai-prompts", wait_until="domcontentloaded", timeout=30000)
        page.wait_for_timeout(1500)
        scroll_by(page, 350, over_ms=1500, steps=15)
        page.wait_for_timeout(1500)
        try:
            toggle = page.locator('button:has-text("Edit"), button:has-text("Preview")').first
            if toggle.count():
                toggle.click(timeout=1500)
                page.wait_for_timeout(1500)
        except Exception:
            pass
        scroll_by(page, 250, over_ms=1500, steps=15)
        pacer.end()

        # -------------------------------------------------------------
        # SCENE 07 — Manage Docs
        # -------------------------------------------------------------
        pacer.begin("07_docs")
        page.goto(f"{BASE}/ruai-docs", wait_until="domcontentloaded", timeout=30000)
        page.wait_for_timeout(1500)
        scroll_by(page, 400, over_ms=1500, steps=15)
        page.wait_for_timeout(1500)
        scroll_by(page, -150, over_ms=1000, steps=10)
        pacer.end()

        # -------------------------------------------------------------
        # SCENE 08 — Analytics  (back to dashboard, expand analytics)
        # -------------------------------------------------------------
        pacer.begin("08_analytics")
        page.goto(f"{BASE}/ruai-dashboard", wait_until="domcontentloaded", timeout=30000)
        page.wait_for_timeout(1500)
        try:
            analytics_header = page.locator(".ruai-collapsible-header").first
            analytics_header.click(timeout=1500)
            page.wait_for_timeout(1200)
            page.locator("#analytics-section").first.scroll_into_view_if_needed(timeout=2000)
        except Exception:
            pass
        page.wait_for_timeout(1500)
        scroll_by(page, 300, over_ms=1500, steps=15)
        page.wait_for_timeout(1500)
        pacer.end()

        # -------------------------------------------------------------
        # SCENE 09 — Payoff  (hold on dashboard top)
        # -------------------------------------------------------------
        pacer.begin("09_payoff")
        page.evaluate("window.scrollTo({top: 0, behavior: 'smooth'})")
        page.wait_for_timeout(2000)
        smooth_move(page, 960, 400, steps=10)
        page.wait_for_timeout(3000)
        pacer.end()

        # Finalise
        video_path = page.video.path() if page.video else None
        context.close()
        browser.close()

        if video_path:
            target = VIDEO_DIR / "ruai_demo_raw.webm"
            Path(video_path).rename(target)
            print(f"\n✓ Video saved: {target}  ({target.stat().st_size / 1024 / 1024:.1f} MB)")
            pacer.write_timings(VIDEO_DIR / "scene_timings.txt")
            print(f"✓ Timings saved: {VIDEO_DIR / 'scene_timings.txt'}")
        else:
            print("!! No video produced")


if __name__ == "__main__":
    run()
