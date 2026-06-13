#!/usr/bin/env python3
"""CI deploy stage: create correlation rules in XSIAM from compiled detections.

This is the single WRITE path. It is intentionally double-gated:
  * the GitLab `deploy-xsiam` job runs only on `main` and is `when: manual`, so
    a person must click it after the merge; and
  * this script only writes when given `--apply` (or XSIAM_DEPLOY_APPLY=true).
    Without that flag it validates every rule read-only and prints what it WOULD
    create — safe to run anywhere, including locally.

Usage:
    python ci/xsiam_deploy.py detections/compiled/            # preview only
    python ci/xsiam_deploy.py detections/compiled/ --apply    # live create

Requires the XSIAM_API_KEY / XSIAM_API_KEY_ID / XSIAM_BASE_URL CI variables.
"""

import os
import sys

from _xsiam_api import XsiamCI, load_manifests


def main(argv):
    args = [a for a in argv[1:] if not a.startswith("-")]
    path = args[0] if args else "detections/compiled/"
    apply = "--apply" in argv[1:] or (os.environ.get("XSIAM_DEPLOY_APPLY", "").lower() in ("1", "true", "yes"))

    client = XsiamCI()
    if not client.is_configured():
        print(f"✗ XSIAM not configured — missing {', '.join(client.missing())}")
        return 2

    manifests = load_manifests(path)
    if not manifests:
        print(f"No detection manifests (*.json) found under {path} — nothing to deploy.")
        return 0

    mode = "LIVE CREATE" if apply else "PREVIEW (no write — pass --apply to deploy)"
    print(f"XSIAM correlation-rule deploy — {mode}\n")

    failures = 0
    for m in manifests:
        name = m.get("name") or m.get("_file")
        res = client.create_correlation_rule(m, apply=apply)
        if "error" in res:
            print(f"✗ {name}: {res['error']}")
            failures += 1
        elif res.get("created"):
            print(f"✓ {name}: correlation rule created in XSIAM")
        else:
            wc = res.get("would_create", {})
            print(f"• {name}: validated — would create [{wc.get('severity')}], "
                  f"{len(wc.get('mitre_techniques') or [])} ATT&CK technique(s)")

    verb = "created" if apply else "validated"
    print(f"\n{len(manifests) - failures}/{len(manifests)} detections {verb}.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
