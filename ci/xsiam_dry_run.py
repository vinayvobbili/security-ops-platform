#!/usr/bin/env python3
"""CI test stage: dry-run every compiled detection against the live XSIAM tenant.

Read-only. For each detection manifest under the given directory it submits the
compiled XQL over a short window and confirms it parses and runs. Any query that
fails to validate fails the pipeline (non-zero exit), so a bad compile can never
be merged.

Usage:
    python ci/xsiam_dry_run.py detections/compiled/

Requires the XSIAM_API_KEY / XSIAM_API_KEY_ID / XSIAM_BASE_URL CI variables.
"""

import sys

from _xsiam_api import XsiamCI, load_manifests


def main(argv):
    path = argv[1] if len(argv) > 1 else "detections/compiled/"
    client = XsiamCI()
    if not client.is_configured():
        print(f"✗ XSIAM not configured — missing {', '.join(client.missing())}")
        return 2

    manifests = load_manifests(path)
    if not manifests:
        print(f"No detection manifests (*.json) found under {path} — nothing to test.")
        return 0

    failures = 0
    for m in manifests:
        name = m.get("name") or m.get("_file")
        xql = m.get("xql") or m.get("xql_query") or ""
        res = client.validate_xql(xql)
        if "error" in res:
            print(f"✗ {name}: {res['error']}")
            failures += 1
        else:
            print(f"✓ {name}: valid XQL — {res.get('results', 0)} event(s) in the window")

    print(f"\n{len(manifests) - failures}/{len(manifests)} detections passed the live dry-run.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
