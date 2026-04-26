"""Validate LLM vulnerable-product extraction on historical tippers.

Standalone validation run — does NOT post anything. Fetches recent tippers
from the Threat Hunting area, runs just the VulnerableProductMention LLM
extraction on each, and writes a markdown report under data/validation/
for manual review.

Goal: measure whether the `vulnerable_products` Pydantic field on
NoveltyLLMResponse is (a) catching real CVE-less product mentions and
(b) not over-triggering on products that already have CVE IDs.
"""

import argparse
import logging
import re
import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List

from pydantic import BaseModel, Field

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import services.azdo as azdo
from src.components.tipper_analyzer.llm_init import get_llm_with_temperature
from src.components.tipper_analyzer.models import VulnerableProductMention
from data.data_maps import azdo_area_paths

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

DEFAULT_OUTPUT_PATH = Path(__file__).resolve().parent.parent / "data/validation/vulnerable_products_validation.md"

# Only evaluate tippers that plausibly talk about a vulnerability. Cheap
# pre-filter — we're not measuring recall on non-vuln tippers.
SIGNAL_KEYWORDS = [
    "vulnerab", "cve-", "exploit", "zero-day", "0-day", "rce",
    "affected version", "patch", "advisory", "unauth", "remote code"
]

PROMPT_TEMPLATE = """Extract CVE-less vulnerable products from a CTI threat tipper. Default is EMPTY. Populate only when every check below passes.

**CHECK #1 — CVE EXCLUSION (most important, do this FIRST):**
Scan the entire tipper for any CVE-YYYY-NNNNN pattern. For each candidate product you're thinking of extracting, ask: "Does any CVE in this tipper cover this product?" If YES — even if the CVE is 5 paragraphs away, even if the product also has an explicit version range, even if the tipper reads like a vulnerability advisory — DROP IT. CVEs are extracted separately and drive the same downstream correlation. Duplicating them here causes false-positive asset scans.

If the tipper's whole narrative is "$PRODUCT has vulnerability CVE-YYYY-NNNNN" then vulnerable_products must be EMPTY. Only when a product's vulnerability has NO corresponding CVE anywhere in the text does it belong here.

**CHECK #2 — DEFENDER ASSET:**
The product must be something a defender would deploy or run (server software, application, library, OS, firmware, appliance). Exclude:
- Tools the attacker USES as tradecraft ("actor deploys Cobalt Strike" — not vulnerable, just operated by attacker).
- Products the attacker TARGETS without a direct vulnerability claim against the product ("malicious Chrome extensions steal sessions" — Chrome is not stated as vulnerable).
- Attacker-owned infrastructure ("attacker's VPS runs Laravel Ignition" — attacker's own server, not a defender asset).
- Domains, URLs, IP addresses, hostnames.
- Generic categories ("Linux servers", "web applications", "RDP").
- Victims of credential theft / session hijacking / social engineering — not vulnerability claims.

**CHECK #3 — VULNERABILITY IS IN THE PRODUCT ITSELF, NOT ITS DISTRIBUTION CHANNEL:**
The tipper must claim a defect inside the product's own code, config, or design. Supply-chain incidents — where the *hosting infrastructure*, *update server*, *package registry*, *code-signing cert*, or *download site* was compromised to ship a trojanized build — do NOT qualify. The legitimate product has no flaw in these cases; the issue is a poisoned distribution channel. Omit the product.

**WRONG examples — every one of these was extracted by a prior run and was wrong:**
- Title "Marimo Authentication Bypass Exploit (CVE-2026-39987)" + body "affecting Marimo versions 0.20.4 and earlier" → CVE present → vulnerable_products MUST be empty.
- Title "Critical Authentication Bypass in nginx-ui (CVE-2026-33032)" + body "nginx-ui v2.3.4" → CVE present → empty.
- Body "actively exploiting CVE-2026-35616 and CVE-2026-21643 in FortiClient Enterprise Management Server (EMS) versions 7.4.5 through 7.4.6" → CVEs present → empty. The version range does NOT override CVE exclusion.
- Body "108 malicious Chrome extensions harvest Google account identities" → Chrome not vulnerable → empty.
- Body "exposed attack server running Ubuntu 20.04 LTS with OpenSSH 8.2p1" → attacker infra → empty.
- Title "Notepad++ Supply Chain Attack via Compromised Hosting Infrastructure" + body "threat actors compromised shared hosting to distribute malicious Notepad++ updates" → supply-chain compromise of the *distribution channel*, not a flaw in Notepad++ itself → empty.

**RIGHT examples:**
- Body "exploits an unpatched vulnerability in Adobe Reader 26.00121367; no CVE has been assigned" + NO CVE anywhere in tipper → product=Adobe Reader, vendor=Adobe, version_constraint=26.00121367.
- Body "Apache Struts versions before 2.5.30 are vulnerable" with NO CVE anywhere in tipper → product=Apache Struts, version_constraint=< 2.5.30.

Tipper title: {title}

Tipper text:
{text}
"""


class VPExtraction(BaseModel):
    """Wrapper schema — the LLM returns a list of VulnerableProductMention."""
    vulnerable_products: List[VulnerableProductMention] = Field(
        default_factory=list,
        description="Products/software flagged as vulnerable in the tipper WITHOUT a CVE ID assigned elsewhere.",
    )


def _has_signal(text: str) -> bool:
    lower = text.lower()
    return any(k in lower for k in SIGNAL_KEYWORDS)


def _strip_html(text: str) -> str:
    if not text:
        return ""
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _count_cves(text: str) -> int:
    return len(set(re.findall(r"CVE-\d{4}-\d{4,7}", text, flags=re.IGNORECASE)))


def fetch_candidate_tippers(days_back_end: int, days_back_start: int):
    """Fetch tippers created between days_back_start and days_back_end days ago.

    days_back_end is the newer bound (smaller number, closer to today).
    days_back_start is the older bound (larger number, further from today).
    """
    area_path = azdo_area_paths.get('threat_hunting', 'Detection-Engineering\\DE Rules\\Threat Hunting')
    upper = f"AND [System.CreatedDate] < @Today-{days_back_end}" if days_back_end > 0 else ""
    query = f"""
        SELECT [System.Id], [System.Title], [System.Description], [System.CreatedDate]
        FROM WorkItems
        WHERE [System.AreaPath] UNDER '{area_path}'
          AND [System.CreatedDate] >= @Today-{days_back_start}
          {upper}
        ORDER BY [System.CreatedDate] DESC
    """
    logger.info(f"Fetching tippers created {days_back_start}..{days_back_end} days ago...")
    tippers = azdo.fetch_work_items(query)
    logger.info(f"Fetched {len(tippers)} raw tippers")
    return tippers


def select_candidates(tippers, sample_size: int):
    seen_titles = set()
    selected = []
    for t in tippers:
        fields = t.get('fields', {})
        title = fields.get('System.Title', '') or ''
        description = _strip_html(fields.get('System.Description', ''))
        if not title or title in seen_titles:
            continue
        if not _has_signal(title + " " + description):
            continue
        seen_titles.add(title)
        selected.append({
            'id': t.get('id'),
            'title': title,
            'description': description,
            'created': fields.get('System.CreatedDate', ''),
            'cve_count': _count_cves(title + " " + description),
        })
        if len(selected) >= sample_size:
            break
    return selected


def extract_for_tipper(llm, title: str, text: str):
    # Cap text to keep prompt bounded (LLM handles large docs but we don't
    # need full RF dumps for this check)
    capped = text[:6000]
    prompt = PROMPT_TEMPLATE.format(title=title, text=capped)
    structured = llm.with_structured_output(VPExtraction)
    t0 = time.time()
    try:
        resp = structured.invoke(prompt)
        elapsed = time.time() - t0
        return resp.vulnerable_products, elapsed, None
    except Exception as e:
        return [], time.time() - t0, str(e)


def format_report(results, days_back_end: int, days_back_start: int):
    lines = [
        "# Vulnerable-Product Extraction — Validation",
        "",
        f"_Generated: {datetime.now(timezone.utc).isoformat()}_",
        f"_Sample: {len(results)} tippers from {days_back_start}..{days_back_end} days ago with vuln-adjacent keywords_",
        "",
        "For each tipper: the LLM's extracted `vulnerable_products` is shown alongside a description excerpt and CVE count.",
        "If CVEs > 0 and products are non-empty, the LLM is finding CVE-less mentions ON TOP of CVE-covered ones — review whether those are real or noise.",
        "",
        "---",
        "",
    ]
    for r in results:
        lines.append(f"## #{r['id']} — {r['title']}")
        lines.append(f"- **Created**: {r['created']}")
        lines.append(f"- **CVE mentions in text**: {r['cve_count']}")
        lines.append(f"- **LLM latency**: {r['elapsed']:.1f}s")
        if r['error']:
            lines.append(f"- **Error**: `{r['error']}`")
        lines.append("")
        lines.append("**Description excerpt:**")
        excerpt = r['description'][:800].replace('\n', ' ')
        lines.append(f"> {excerpt}{'...' if len(r['description']) > 800 else ''}")
        lines.append("")
        lines.append("**Extracted `vulnerable_products`:**")
        if not r['products']:
            lines.append("_(empty)_")
        else:
            for p in r['products']:
                vendor = f" (vendor: {p.vendor})" if p.vendor else ""
                vc = p.version_constraint or "_no version given_"
                lines.append(f"- `{p.product}`{vendor} — {vc}")
        lines.append("")
        lines.append("---")
        lines.append("")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--days-back-end", type=int, default=0,
                        help="Newer bound: skip tippers newer than this many days. 0 = today.")
    parser.add_argument("--days-back-start", type=int, default=60,
                        help="Older bound: skip tippers older than this many days.")
    parser.add_argument("--sample-size", type=int, default=50)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_PATH)
    args = parser.parse_args()

    tippers = fetch_candidate_tippers(args.days_back_end, args.days_back_start)
    candidates = select_candidates(tippers, args.sample_size)
    logger.info(f"Selected {len(candidates)} candidates for extraction")

    llm = get_llm_with_temperature(0.0)

    results = []
    for i, c in enumerate(candidates, 1):
        logger.info(f"[{i}/{len(candidates)}] #{c['id']} {c['title'][:60]}")
        products, elapsed, error = extract_for_tipper(llm, c['title'], c['description'])
        results.append({**c, 'products': products, 'elapsed': elapsed, 'error': error})
        logger.info(
            f"  → {len(products)} product(s) in {elapsed:.1f}s"
            + (f" [ERR: {error}]" if error else "")
        )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(format_report(results, args.days_back_end, args.days_back_start))
    logger.info(f"Report written to {args.output}")

    total_products = sum(len(r['products']) for r in results)
    with_hits = sum(1 for r in results if r['products'])
    errors = sum(1 for r in results if r['error'])
    print()
    print(f"Tippers evaluated:     {len(results)}")
    print(f"Tippers with hits:     {with_hits}")
    print(f"Total products found:  {total_products}")
    print(f"Errors:                {errors}")
    print(f"Report:                {args.output}")


if __name__ == "__main__":
    main()
