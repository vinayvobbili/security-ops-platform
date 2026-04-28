#!/usr/bin/env python3
"""Convert wiki_articles/ into an Obsidian-ready vault.

Transforms markdown files in-place:
  1. Fix '# #' double-hash title artifact from docx conversion
  2. Add/update YAML frontmatter (title, aliases, tags, date, source,
     tldr, confidence, last_verified)
  3. Deduplicate Related Topics sections
  4. Fix broken wikilinks (wrong prefixes, missing date suffixes)
  5. Append 'Lessons Learned / Gotchas' section if missing
  6. Generate a Map of Content (MOC) index note
  7. Auto-generate hub pages for platforms, threat actors, and tools
  8. Run lint pass: orphan pages, dead wikilinks, singleton tags

Usage:
    python scripts/convert_wiki_to_obsidian.py [--dry-run]
"""

import json
import re
import sys
from collections import OrderedDict
from datetime import date as date_mod
from pathlib import Path

WIKI_DIR = Path(__file__).resolve().parent.parent / "wiki_articles"
META_FILE = WIKI_DIR / ".wiki_meta.json"

# ── Tag rules: keyword → tag  ───────────────────────────────────────────────
# Checked against filename and content (case-insensitive).
TAG_RULES = [
    # Threat actors
    ("scattered.spider", "threat-actor/scattered-spider"),
    ("apt41", "threat-actor/apt41"),
    ("midnight.?blizzard", "threat-actor/midnight-blizzard"),
    ("hadooken", "threat-actor/hadooken"),
    ("dodgebox", "malware/dodgebox"),
    ("moonwalk", "malware/moonwalk"),
    ("stealthvector", "malware/stealthvector"),
    ("raccoon.stealer", "malware/raccoon-stealer"),
    ("trufflehog", "tool/trufflehog"),
    ("edrsilencer", "tool/edrsilencer"),
    ("impacket", "tool/impacket"),
    ("aclpwn", "tool/aclpwn"),
    ("adfind", "tool/adfind"),
    ("linpeas", "tool/linpeas"),
    ("remcom", "tool/remcom"),
    ("fsutil", "tool/fsutil"),
    # Platforms / products
    ("tanium", "platform/tanium"),
    ("crowdstrike|falcon", "platform/crowdstrike"),
    ("qradar", "platform/qradar"),
    ("vectra", "platform/vectra"),
    ("varonis", "platform/varonis"),
    ("entra.id|entra.?id|aadinternals", "platform/entra-id"),
    ("prisma", "platform/prisma"),
    ("citrix|netscaler", "platform/citrix"),
    ("powertech", "platform/powertech"),
    ("ionix", "platform/ionix"),
    ("provida", "platform/provida"),
    ("esxi|vmware", "platform/vmware"),
    ("rsa", "platform/rsa"),
    ("splunk", "platform/splunk"),
    # Categories
    ("phishing", "category/phishing"),
    ("smishing|vishing", "category/social-engineering"),
    ("denial.of.service|dos", "category/denial-of-service"),
    ("malicious.?code|malicious.?software|malware", "category/malware"),
    ("unauthorized.?access", "category/unauthorized-access"),
    ("privilege.?escalation", "category/privilege-escalation"),
    ("credential|password.reset|cookie.editor|cookie.stealer|ntds.?dump", "category/credential-theft"),
    ("edr.?silenc|disable.*edr|modify.*edr", "category/defense-evasion"),
    ("c2|command.and.control|devtunnel", "category/command-and-control"),
    ("vulnerability", "category/vulnerability-response"),
    ("inappropriate.?usage|suspicious.?browsing", "category/policy-violation"),
    ("host.file.modification|symlink", "category/persistence"),
    ("service.desk|suspicious.caller", "category/social-engineering"),
    # Doc types
    ("runbook|generic|response.action", "type/runbook"),
    ("escalation|contact", "type/contacts"),
]

# Date pattern in filenames: MMDDYYYY at end
DATE_RE = re.compile(r"(\d{2})(\d{2})(\d{4})$")


def extract_date(stem: str) -> str | None:
    """Pull MMDDYYYY from filename stem → YYYY-MM-DD."""
    m = DATE_RE.search(stem)
    if m:
        mm, dd, yyyy = m.groups()
        if 1 <= int(mm) <= 12 and 1 <= int(dd) <= 31:
            return f"{yyyy}-{mm}-{dd}"
    return None


def strip_related_topics(content: str) -> str:
    """Remove the Related Topics section so it doesn't pollute tag matching."""
    lines = content.split("\n")
    out = []
    in_related = False
    for line in lines:
        if re.match(r"^##\s+Related\s+Topics", line):
            in_related = True
            continue
        if in_related and line.startswith("## "):
            in_related = False
        if not in_related:
            out.append(line)
    return "\n".join(out)


def derive_tags(filename: str, content: str) -> list[str]:
    """Match TAG_RULES against filename + content (excluding Related Topics)."""
    clean_content = strip_related_topics(content)
    blob = (filename + "\n" + clean_content).lower()
    tags = []
    for pattern, tag in TAG_RULES:
        if re.search(pattern, blob):
            if tag not in tags:
                tags.append(tag)
    return sorted(tags)


def build_aliases(stem: str) -> list[str]:
    """Generate wikilink-compatible aliases for a file.

    Handles cases like:
      - gdnr-edrsilencer-10232024 → also match [[gdnr-edrsilencer]]
      - citrix-netscalers-response-actions → also match [[gdnr-citrix-netscalers-response-actions]]
      - dnr-suspiciousactivity-fsutil-09042024 → also match [[gdnr-dnr-suspiciousactivity-fsutil-09042024]]
    """
    aliases = set()
    # Strip date suffix to create a dateless alias
    dateless = DATE_RE.sub("", stem).rstrip("-")
    if dateless and dateless != stem:
        aliases.add(dateless)

    # If it doesn't start with gdnr-, add gdnr- prefixed version (some wikilinks add it)
    if not stem.startswith("gdnr-"):
        aliases.add(f"gdnr-{stem}")
        if dateless != stem:
            aliases.add(f"gdnr-{dateless}")

    aliases.discard(stem)  # don't alias yourself
    return sorted(aliases)


def extract_title(content: str) -> str:
    """Get title from first H1 line, stripping extra '#'."""
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("#"):
            return line.lstrip("#").strip()
    return ""


def fix_double_hash(content: str) -> str:
    """Replace '# # Title' with '# Title' on the first H1 only."""
    return re.sub(r"^# # ", "# ", content, count=1)


def build_slug_index() -> dict[str, str]:
    """Map every possible slug/alias → actual filename stem."""
    index = {}
    for f in WIKI_DIR.glob("*.md"):
        if f.name.startswith(".") or f.name.startswith("_"):
            continue
        stem = f.stem
        index[stem] = stem
        for alias in build_aliases(stem):
            index.setdefault(alias, stem)
    return index


def fix_wikilinks(content: str, slug_index: dict[str, str]) -> str:
    """Rewrite [[broken-slug]] → [[correct-slug]] where we can resolve it."""
    def replace_link(m):
        slug = m.group(1)
        if slug in slug_index:
            resolved = slug_index[slug]
            if resolved != slug:
                return f"[[{resolved}]]"
        return m.group(0)

    return re.sub(r"\[\[([^\]|]+?)(?:\|[^\]]+)?\]\]", replace_link, content)


def dedupe_related_topics(content: str) -> str:
    """Remove duplicate entries in ## Related Topics section."""
    lines = content.split("\n")
    out = []
    in_related = False
    seen_links = OrderedDict()

    for line in lines:
        if re.match(r"^##\s+Related\s+Topics", line):
            in_related = True
            out.append(line)
            continue

        if in_related:
            # End of section: next heading or end of file
            if line.startswith("## ") or (line.startswith("# ") and not line.startswith("#  ")):
                # Flush deduplicated links
                for link_line in seen_links.values():
                    out.append(link_line)
                seen_links.clear()
                in_related = False
                out.append(line)
                continue

            stripped = line.strip()
            if stripped.startswith("*") and "[[" in stripped:
                # Extract the wikilink as the dedup key
                link_match = re.search(r"\[\[(.+?)\]\]", stripped)
                if link_match:
                    key = link_match.group(1)
                    if key not in seen_links:
                        seen_links[key] = line
                    continue
                else:
                    out.append(line)
            elif stripped == "":
                continue  # skip blank lines inside related topics during dedup
            else:
                out.append(line)
        else:
            out.append(line)

    # If file ended while still in related section, flush
    if seen_links:
        for link_line in seen_links.values():
            out.append(link_line)

    return "\n".join(out)


def generate_tldr(title: str, content: str, tags: list[str]) -> str:
    """Generate a one-line TLDR from the title, first substantive paragraph, and tags.

    Heuristic: combine the title with the first sentence of the Overview / first
    paragraph after the H1.  This gives a useful-enough summary without needing
    an LLM call.  Can be manually refined later.
    """
    # Find the first substantive paragraph (skip headings, blank lines, bullets)
    body = strip_related_topics(content)
    # Remove frontmatter if present
    if body.startswith("---"):
        end = body.find("---", 3)
        if end != -1:
            body = body[end + 3:]

    first_sentence = ""
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("*") or line.startswith("|") or line.startswith("-"):
            continue
        # Take the first sentence (up to first period)
        dot = line.find(". ")
        if dot != -1:
            first_sentence = line[: dot + 1]
        else:
            first_sentence = line.rstrip(".")  + "."
        break

    if first_sentence:
        # Trim to reasonable length
        if len(first_sentence) > 200:
            first_sentence = first_sentence[:197] + "..."
        return first_sentence
    return f"Runbook for {title}."


def parse_frontmatter(content: str) -> tuple[dict, str]:
    """Parse YAML frontmatter from content. Returns (metadata_dict, body).

    Simple parser — handles the subset of YAML we generate (scalars + lists).
    """
    if not content.startswith("---\n"):
        return {}, content

    end = content.find("\n---", 3)
    if end == -1:
        return {}, content

    fm_text = content[4:end]
    body = content[end + 4:]  # skip \n---
    if body.startswith("\n"):
        body = body[1:]

    meta = {}
    current_key = None
    current_list = None

    for line in fm_text.splitlines():
        # List item
        if line.startswith("  - "):
            if current_key and current_list is not None:
                current_list.append(line[4:].strip())
            continue
        # Key: value
        m = re.match(r"^(\w[\w_]*)\s*:\s*(.*)", line)
        if m:
            # Save previous list if any
            if current_key and current_list is not None:
                meta[current_key] = current_list
            key = m.group(1)
            val = m.group(2).strip()
            if val:
                # Strip quotes
                if val.startswith('"') and val.endswith('"'):
                    val = val[1:-1]
                meta[key] = val
                current_key = key
                current_list = None
            else:
                # Start of a list
                current_key = key
                current_list = []

    # Save last list
    if current_key and current_list is not None:
        meta[current_key] = current_list

    return meta, body


def build_frontmatter(title: str, aliases: list[str], tags: list[str],
                       date: str | None, source: str | None,
                       tldr: str | None = None,
                       confidence: str | None = None,
                       last_verified: str | None = None) -> str:
    """Generate YAML frontmatter block."""
    lines = ["---"]
    # Title with quotes to handle colons/special chars
    lines.append(f'title: "{title}"')
    if tldr:
        # Escape quotes in tldr
        lines.append(f'tldr: "{tldr}"')
    if aliases:
        lines.append("aliases:")
        for a in aliases:
            lines.append(f"  - {a}")
    if tags:
        lines.append("tags:")
        for t in tags:
            lines.append(f"  - {t}")
    if date:
        lines.append(f"date: {date}")
    if confidence:
        lines.append(f"confidence: {confidence}")
    if last_verified:
        lines.append(f"last_verified: {last_verified}")
    if source:
        lines.append(f'source: "{source}"')
    lines.append("---")
    lines.append("")
    return "\n".join(lines)


def load_source_map() -> dict[str, str]:
    """Map slug → original docx filename from .wiki_meta.json."""
    if not META_FILE.exists():
        return {}
    data = json.loads(META_FILE.read_text())
    mapping = {}
    for docx_name, info in data.get("compiled", {}).items():
        mapping[info["slug"]] = docx_name
    return mapping


def generate_moc(articles: list[dict]) -> str:
    """Generate a Map of Content (MOC) index note."""
    lines = [
        "---",
        'title: "Runbook Index"',
        "tags:",
        "  - MOC",
        "---",
        "",
        "# IR Runbook Index",
        "",
        "Map of Content for all incident response runbooks and reference documents.",
        "",
        "> **Hub pages:** [[_Hub — Platforms]], [[_Hub — Threat Actors]], [[_Hub — Tools]]",
        "",
    ]

    # Group by primary category tag
    groups: dict[str, list[dict]] = {}
    for a in articles:
        cat = "Other"
        for t in a["tags"]:
            if t.startswith("category/"):
                cat = t.replace("category/", "").replace("-", " ").title()
                break
            elif t.startswith("type/"):
                cat = t.replace("type/", "").replace("-", " ").title()
                break
        groups.setdefault(cat, []).append(a)

    for group_name in sorted(groups.keys()):
        lines.append(f"## {group_name}")
        lines.append("")
        for a in sorted(groups[group_name], key=lambda x: x["title"]):
            date_str = f" ({a['date']})" if a.get("date") else ""
            conf = a.get("confidence", "")
            conf_badge = {"high": " ✅", "medium": " ⚠️", "low": " 🔸"}.get(conf, "")
            lines.append(f"- [[{a['stem']}|{a['title']}]]{date_str}{conf_badge}")
        lines.append("")

    return "\n".join(lines)


def generate_hub_pages(articles: list[dict], dry_run: bool) -> list[str]:
    """Auto-generate hub pages for platforms, threat actors, and tools.

    Returns list of created hub page filenames.
    """
    # Collect tag → articles mapping for each hub category
    hub_defs = [
        ("platform", "Platforms", "Security platform and product coverage across runbooks."),
        ("threat-actor", "Threat Actors", "Threat actors referenced across incident runbooks."),
        ("tool", "Tools", "Attacker tools and utilities referenced across incident runbooks."),
        ("malware", "Malware", "Malware families referenced across incident runbooks."),
    ]

    created = []
    for prefix, hub_title, description in hub_defs:
        # Gather tag → article list
        tag_map: dict[str, list[dict]] = {}
        for a in articles:
            for t in a["tags"]:
                if t.startswith(f"{prefix}/"):
                    tag_map.setdefault(t, []).append(a)

        if not tag_map:
            continue

        lines = [
            "---",
            f'title: "Hub — {hub_title}"',
            "tags:",
            "  - MOC",
            f"  - hub/{prefix}",
            "---",
            "",
            f"# {hub_title}",
            "",
            description,
            "",
        ]

        for tag in sorted(tag_map.keys()):
            label = tag.split("/", 1)[1].replace("-", " ").title()
            lines.append(f"## {label}")
            lines.append("")
            for a in sorted(tag_map[tag], key=lambda x: x["title"]):
                date_str = f" ({a['date']})" if a.get("date") else ""
                lines.append(f"- [[{a['stem']}|{a['title']}]]{date_str}")
            lines.append("")

        filename = f"_Hub — {hub_title}.md"
        path = WIKI_DIR / filename
        content = "\n".join(lines)

        if dry_run:
            print(f"  DRY RUN: Would create hub page {filename} ({len(tag_map)} sections)")
        else:
            path.write_text(content, encoding="utf-8")
            print(f"  Created hub: {filename} ({len(tag_map)} sections)")

        created.append(filename)

    return created


def run_lint_pass(articles: list[dict]) -> None:
    """Run quality checks and print warnings.

    Checks:
      1. Orphan pages: not linked from MOC or any other article
      2. Dead wikilinks: point to non-existent files
      3. Singleton tags: used by only one article (possible typo)
    """
    print("\n── Lint Pass ──────────────────────────────────────────")

    # Build sets
    all_stems = {a["stem"] for a in articles}
    moc_path = WIKI_DIR / "_Runbook Index.md"

    # Collect all wikilinks across all files
    inbound_links: dict[str, set[str]] = {s: set() for s in all_stems}
    dead_links: list[tuple[str, str]] = []

    for f in WIKI_DIR.glob("*.md"):
        content = f.read_text(encoding="utf-8")
        source_stem = f.stem
        for m in re.finditer(r"\[\[([^\]|]+?)(?:\|[^\]]+)?\]\]", content):
            target = m.group(1)
            if target in all_stems:
                if target != source_stem:
                    inbound_links.setdefault(target, set()).add(source_stem)
            else:
                # Skip hub/MOC pages, heading anchors, and short concept links
                # (concept links like [[APT41]] or [[C2]] are intentional stubs)
                if not target.startswith("_") and not target.startswith("#"):
                    dead_links.append((source_stem, target))

    # 1. Orphan pages: no inbound links from any other file
    orphans = [s for s in sorted(all_stems) if not inbound_links.get(s)]
    if orphans:
        print(f"\n  ⚠ Orphan pages ({len(orphans)} — no inbound wikilinks):")
        for s in orphans:
            print(f"    - {s}.md")
    else:
        print("\n  ✓ No orphan pages")

    # 2. Dead wikilinks
    # Deduplicate
    seen = set()
    unique_dead = []
    for src, target in dead_links:
        key = (src, target)
        if key not in seen:
            seen.add(key)
            unique_dead.append((src, target))

    if unique_dead:
        print(f"\n  ⚠ Dead wikilinks ({len(unique_dead)}):")
        for src, target in sorted(unique_dead):
            print(f"    - {src}.md → [[{target}]]")
    else:
        print("  ✓ No dead wikilinks")

    # 3. Singleton tags (only one article uses it)
    tag_counts: dict[str, int] = {}
    for a in articles:
        for t in a["tags"]:
            tag_counts[t] = tag_counts.get(t, 0) + 1

    singletons = [(t, c) for t, c in sorted(tag_counts.items()) if c == 1]
    # Filter out tags that are inherently unique (threat actors, specific malware)
    # Only flag category/* and platform/* singletons as potential typos
    flagged = [t for t, _ in singletons if t.startswith("category/") or t.startswith("platform/")]
    if flagged:
        print(f"\n  ⚠ Singleton tags ({len(flagged)} — used by only 1 article, possible typo):")
        for t in flagged:
            print(f"    - {t}")
    else:
        print("  ✓ No suspicious singleton tags")

    print("  ────────────────────────────────────────────────────\n")


def infer_confidence(date_str: str | None, tags: list[str], content: str) -> str:
    """Infer confidence level from article age and content richness.

    - 'high': has detection logic/queries AND remediation steps
    - 'medium': has either detection or remediation but not both
    - 'low': thin content or very old without updates
    """
    body_lower = content.lower()
    has_detection = bool(re.search(r"detection|splunk|qradar|query|search|logic", body_lower))
    has_remediation = bool(re.search(r"remediation|containment|re-?imag|block|isolat", body_lower))
    has_investigation = bool(re.search(r"investigation|triage|initial response", body_lower))

    if has_detection and has_remediation and has_investigation:
        return "high"
    elif has_detection or has_remediation:
        return "medium"
    return "low"


def ensure_lessons_learned(content: str) -> str:
    """Append a Lessons Learned / Gotchas section if one doesn't exist.

    Inserted before ## Related Topics if present, otherwise at the end.
    """
    if re.search(r"^##\s+Lessons\s+Learned", content, re.MULTILINE):
        return content

    section = (
        "\n## Lessons Learned / Gotchas\n\n"
        "*No entries yet. Add post-incident observations, tooling caveats, "
        "or things that surprised responders here.*\n"
    )

    # Try to insert before Related Topics
    m = re.search(r"\n(##\s+Related\s+Topics)", content)
    if m:
        insert_pos = m.start()
        return content[:insert_pos] + section + content[insert_pos:]

    # Otherwise append at end
    return content.rstrip("\n") + "\n" + section


def process_file(path: Path, slug_index: dict, source_map: dict,
                 dry_run: bool) -> dict:
    """Process a single markdown file. Returns article metadata."""
    content = path.read_text(encoding="utf-8")
    stem = path.stem
    today = date_mod.today().isoformat()

    # Parse existing frontmatter if present
    existing_meta, body = parse_frontmatter(content)

    if existing_meta:
        # Already has frontmatter — update it with new fields
        body = fix_double_hash(body)
        title = existing_meta.get("title", extract_title(body))
        date = existing_meta.get("date", extract_date(stem))
        source = existing_meta.get("source", source_map.get(stem))
        # Re-derive tags (may have new rules) but keep any manually-added tags
        derived_tags = derive_tags(stem, body)
        old_tags = existing_meta.get("tags", [])
        if isinstance(old_tags, str):
            old_tags = [old_tags]
        merged_tags = list(dict.fromkeys(derived_tags + old_tags))  # dedup, derived first
        merged_tags.sort()
        aliases = build_aliases(stem)
        # Add new fields
        tldr = existing_meta.get("tldr") or generate_tldr(title, body, merged_tags)
        confidence = existing_meta.get("confidence") or infer_confidence(date, merged_tags, body)
        last_verified = existing_meta.get("last_verified") or today
    else:
        # Fresh file — full processing
        body = fix_double_hash(content)
        title = extract_title(body)
        date = extract_date(stem)
        merged_tags = derive_tags(stem, body)
        aliases = build_aliases(stem)
        source = source_map.get(stem)
        tldr = generate_tldr(title, body, merged_tags)
        confidence = infer_confidence(date, merged_tags, body)
        last_verified = today

    # Deduplicate Related Topics
    body = dedupe_related_topics(body)

    # Fix broken wikilinks
    body = fix_wikilinks(body, slug_index)

    # Ensure Lessons Learned section exists
    body = ensure_lessons_learned(body)

    # Build new frontmatter
    frontmatter = build_frontmatter(
        title, aliases, merged_tags, date, source,
        tldr=tldr, confidence=confidence, last_verified=last_verified,
    )
    content = frontmatter + body

    if dry_run:
        print(f"  DRY RUN: {path.name}")
        print(f"    title: {title}")
        print(f"    tldr: {tldr[:80]}...")
        print(f"    confidence: {confidence}")
        print(f"    tags: {merged_tags}")
    else:
        path.write_text(content, encoding="utf-8")
        print(f"  OK: {path.name} (conf={confidence}, {len(merged_tags)} tags)")

    return {
        "stem": stem, "title": title, "tags": merged_tags, "date": date,
        "tldr": tldr, "confidence": confidence,
    }


def main():
    dry_run = "--dry-run" in sys.argv

    if not WIKI_DIR.exists():
        print(f"ERROR: {WIKI_DIR} not found")
        sys.exit(1)

    md_files = sorted(
        f for f in WIKI_DIR.glob("*.md")
        if not f.name.startswith(".") and not f.name.startswith("_")
    )
    print(f"Found {len(md_files)} markdown files in {WIKI_DIR}")

    # Build lookup tables
    slug_index = build_slug_index()
    source_map = load_source_map()
    print(f"Slug index: {len(slug_index)} entries, source map: {len(source_map)} entries")

    if dry_run:
        print("\n=== DRY RUN (no files modified) ===\n")
    else:
        print()

    # Process each file
    articles = []
    for f in md_files:
        info = process_file(f, slug_index, source_map, dry_run)
        articles.append(info)

    # Generate MOC
    moc_path = WIKI_DIR / "_Runbook Index.md"
    moc_content = generate_moc(articles)
    if dry_run:
        print(f"\n  DRY RUN: Would create {moc_path.name}")
    else:
        moc_path.write_text(moc_content, encoding="utf-8")
        print(f"\n  Created: {moc_path.name}")

    # Generate hub pages
    print()
    hub_files = generate_hub_pages(articles, dry_run)

    # Run lint pass
    run_lint_pass(articles)

    print(f"Done! {'(dry run)' if dry_run else ''}")
    print(f"  {len(md_files)} articles processed")
    print(f"  {len(hub_files)} hub pages generated")
    print(f"  Open {WIKI_DIR}/ as an Obsidian vault to get started.")


if __name__ == "__main__":
    main()
