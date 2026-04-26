#!/usr/bin/env python3
"""Parse threat intelligence tippers into structured JSON via the Ollama proxy."""

import argparse
import json
import sys
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

PROXY_URL = "http://<internal-host>/chat"
API_KEY = "YOUR_API_KEY_HERE"

SYSTEM_PROMPT = """\
You are a threat intelligence analyst. Parse the provided threat tipper text \
and extract all relevant information into a single JSON object with these fields:

- "title": brief descriptive title for this tipper
- "summary": 1-3 sentence summary of the threat
- "severity": "critical", "high", "medium", "low", or "informational"
- "threat_actors": list of attributed threat actor names/aliases (empty list if none)
- "malware_families": list of malware family names mentioned (empty list if none)
- "ttps": list of MITRE ATT&CK techniques referenced or implied, each as \
  {"technique_id": "T1234", "name": "...", "tactic": "..."}
- "iocs": list of indicators of compromise, each as \
  {"type": "ipv4|ipv6|domain|url|hash-md5|hash-sha1|hash-sha256|email|filename|cve", "value": "..."}
- "affected_products": list of targeted software, OS, or hardware
- "recommended_actions": list of short actionable mitigation steps
- "references": list of URLs or report IDs cited in the text (empty list if none)
- "raw_context": any important context that doesn't fit the above fields

Return ONLY the JSON object — no markdown fencing, no commentary.\
"""


def parse_tipper(text: str) -> dict:
    payload = json.dumps({
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": text},
        ],
        "format": "json",
        "temperature": 0.1,
    }).encode()

    req = Request(
        PROXY_URL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {API_KEY}",
        },
        method="POST",
    )

    with urlopen(req, timeout=120) as resp:
        result = json.loads(resp.read())

    content = result["message"]["content"]
    return json.loads(content)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path, help="Path to the tipper text file")
    parser.add_argument("-o", "--output", type=Path, help="Write JSON to file instead of stdout")
    parser.add_argument("--raw", action="store_true", help="Print raw LLM response without re-formatting")
    args = parser.parse_args()

    if not args.file.is_file():
        print(f"Error: {args.file} not found", file=sys.stderr)
        sys.exit(1)

    text = args.file.read_text(encoding="utf-8")
    if not text.strip():
        print("Error: file is empty", file=sys.stderr)
        sys.exit(1)

    try:
        parsed = parse_tipper(text)
    except URLError as e:
        print(f"Error connecting to proxy: {e}", file=sys.stderr)
        sys.exit(1)
    except (KeyError, json.JSONDecodeError) as e:
        print(f"Error parsing response: {e}", file=sys.stderr)
        sys.exit(1)

    output = json.dumps(parsed, indent=2) if not args.raw else json.dumps(parsed)

    if args.output:
        args.output.write_text(output + "\n", encoding="utf-8")
        print(f"Written to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
