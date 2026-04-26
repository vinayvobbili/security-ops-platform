#!/usr/bin/env python3
"""
Build the Teams app package ZIP for the notification service.

Usage:
    # With placeholder (for review):
    python teams_bots/build_app_package.py

    # With real App ID (for publishing):
    python teams_bots/build_app_package.py --app-id "your-azure-ad-app-id-here"
"""
import argparse
import json
import zipfile
from pathlib import Path

PACKAGE_DIR = Path(__file__).parent / "app_package"
OUTPUT_ZIP = Path(__file__).parent / "toodles-bot.zip"
PLACEHOLDER = "{{AZURE_AD_APP_ID}}"


def build(app_id: str = None):
    manifest_path = PACKAGE_DIR / "manifest.json"
    color_path = PACKAGE_DIR / "color.png"
    outline_path = PACKAGE_DIR / "outline.png"

    for f in (manifest_path, color_path, outline_path):
        if not f.exists():
            raise FileNotFoundError(f"Missing required file: {f}")

    manifest = json.loads(manifest_path.read_text())

    if app_id:
        manifest["id"] = app_id
        manifest["bots"][0]["botId"] = app_id
        print(f"App ID set to: {app_id}")
    else:
        print(f"WARNING: Using placeholder '{PLACEHOLDER}' — replace before publishing")

    with zipfile.ZipFile(OUTPUT_ZIP, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", json.dumps(manifest, indent=2))
        zf.write(color_path, "color.png")
        zf.write(outline_path, "outline.png")

    print(f"Built {OUTPUT_ZIP} ({OUTPUT_ZIP.stat().st_size} bytes)")
    print(f"Contents:")
    with zipfile.ZipFile(OUTPUT_ZIP) as zf:
        for info in zf.infolist():
            print(f"  {info.filename} ({info.file_size} bytes)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build the notification service Teams app package")
    parser.add_argument("--app-id", help="Azure AD App ID (replaces placeholder in manifest)")
    args = parser.parse_args()
    build(args.app_id)
