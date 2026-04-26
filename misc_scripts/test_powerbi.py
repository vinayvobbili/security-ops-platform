#!/usr/bin/env python3
"""Headless browser test for Power BI Explorer.

Usage:
    python misc_scripts/test_powerbi.py --dataset "Client_Health" --question "How many assets are missing Tanium this month?"
"""

import argparse
import sys
import time

from playwright.sync_api import sync_playwright

POWERBI_URL = "http://gdnr.the company.com/powerbi"
CHROME_PATH = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
TIMEOUT_MS = 120_000  # 2 min max — anything over 60s is useless


def run_test(dataset_name: str, question: str, headed: bool = False, screenshot: str = None):
    with sync_playwright() as p:
        browser = p.chromium.launch(
            executable_path=CHROME_PATH,
            headless=not headed,
            args=[],
        )
        page = browser.new_page(viewport={"width": 1400, "height": 900})
        print(f"Opening {POWERBI_URL} ...")
        page.goto(POWERBI_URL, wait_until="networkidle")

        # Wait for dataset buttons to render (async fetch after page load)
        ds_btn = page.locator(f'button.pbi-dataset-item[data-name="{dataset_name}"]')
        try:
            ds_btn.wait_for(state="visible", timeout=15_000)
        except Exception:
            print(f"ERROR: Dataset '{dataset_name}' not found on page")
            browser.close()
            sys.exit(1)

        print(f"Selecting dataset: {dataset_name}")
        ds_btn.click()

        # Wait for schema/chips to load
        page.wait_for_load_state("networkidle")
        time.sleep(3)

        # Wait for chat input to become enabled (schema must load first)
        chat_input = page.locator("#pbiInput")
        chat_input.wait_for(state="visible", timeout=30_000)
        page.wait_for_function(
            "() => !document.querySelector('#pbiInput').disabled",
            timeout=60_000,
        )
        chat_input.fill(question)
        print(f"Asking: {question}")
        t_start = time.time()

        # Submit — press Enter
        chat_input.press("Enter")

        # Wait for a response bubble to appear, then wait for streaming to finish.
        print("Waiting for response ...")
        try:
            # First wait for ANY assistant bubble to appear
            page.wait_for_selector(".pbi-bubble.pbi-assistant, .pbi-assistant", timeout=30_000)
            print("Response bubble appeared, waiting for streaming to finish ...")
            # Wait for the loading indicator to disappear and real content to arrive.
            # The "Generating DAX query..." is a loading message — wait for it to go away.
            page.wait_for_function(
                """() => {
                    const loading = document.querySelector('.pbi-loading-msg, .pbi-loading-bottom');
                    if (loading && loading.offsetParent !== null) return false;
                    const bubbles = document.querySelectorAll('.pbi-msg.pbi-assistant');
                    if (bubbles.length === 0) return false;
                    const last = bubbles[bubbles.length - 1];
                    const text = last.innerText.trim();
                    return text.length > 20 && !text.includes('Generating DAX');
                }""",
                timeout=TIMEOUT_MS,
            )
        except Exception as e:
            print(f"Timeout or error waiting for response: {e}")
            # Debug: dump page state
            page.screenshot(path="/tmp/powerbi_debug.png", full_page=True)
            print("Debug screenshot: /tmp/powerbi_debug.png")
            html = page.locator(".pbi-chat-area, .chat-area, #pbiChatArea, main").first.inner_html()
            print(f"Chat area HTML:\n{html[:2000]}")
            browser.close()
            sys.exit(1)

        # Give charts/tables a moment to render
        time.sleep(3)

        # Extract the response text via JS (more reliable than CSS selectors)
        text = page.evaluate("""() => {
            const bubbles = document.querySelectorAll('.pbi-msg');
            const texts = [];
            for (const b of bubbles) {
                const cls = b.className;
                const t = b.innerText.trim();
                if (t) texts.push({cls, text: t});
            }
            return texts;
        }""")
        if text:
            print(f"\n{'='*60}")
            print("RESPONSE:")
            print(f"{'='*60}")
            for msg in text:
                role = "BOT" if "pbi-assistant" in msg["cls"] else "USER"
                print(f"[{role}] {msg['text']}")
            print(f"{'='*60}\n")
        else:
            print("ERROR: No response messages found")

        if screenshot:
            page.screenshot(path=screenshot, full_page=True)
            print(f"Screenshot saved: {screenshot}")

        elapsed = round(time.time() - t_start, 1)
        browser.close()
        print(f"Test complete. Response time: {elapsed}s {'✓ PASS' if elapsed < 60 else '✗ OVER 60s SLA'}")


def main():
    parser = argparse.ArgumentParser(description="Test Power BI Explorer via headless browser")
    parser.add_argument("--dataset", required=True, help="Dataset name (e.g. Client_Health)")
    parser.add_argument("--question", required=True, help="Question to ask")
    parser.add_argument("--headed", action="store_true", help="Show browser window")
    parser.add_argument("--screenshot", default=None, help="Save screenshot to path")
    args = parser.parse_args()

    run_test(args.dataset, args.question, headed=args.headed, screenshot=args.screenshot)


if __name__ == "__main__":
    main()
