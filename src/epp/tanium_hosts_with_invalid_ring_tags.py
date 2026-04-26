"""
Tanium Host Invalid Ring Tag Analyzer

Identifies Tanium hosts that have incorrect ring tags based on:

1. Environment validation (servers only — workstation rings are %-distributed, not env-based):
   - Ring 1: dev, poc, lab, integration, development, sandbox, int
   - Ring 2: qa, test, testing
   - Ring 3: staging, uat, pre-prod, dr, qa/dr
   - Ring 4: production or unknown environments

2. Country/Region validation (all hosts — servers and workstations):
   - Validates ring tag region matches expected region for host's current country
   - Uses regions_by_country_tanium.json (Japan → JP, not JAPAN like CrowdStrike)
   - Example: A host in France (EMEA region) should not have US ring tags

Creates two reports:
- Complete dataset of all hosts with ring tags (with analysis columns)
- Filtered report showing only hosts with invalid ring tags
"""

import json
import logging
import re
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import pandas as pd

from services import service_now
from services.tanium import TaniumClient
from src.epp.tanium_pmli_hosts import is_pmli_hostname
from src.utils.excel_formatting import apply_professional_formatting

logger = logging.getLogger(__name__)

ROOT_DIRECTORY = Path(__file__).parent.parent.parent
DATA_DIR = ROOT_DIRECTORY / "data" / "transient" / "epp_device_tagging"

EASTERN_TZ = ZoneInfo("America/New_York")

# Environment to ring mappings for servers (must match tanium_hosts_without_ring_tag.py)
RING_1_ENVS = {"dev", "development", "sandbox", "lab", "poc", "integration", "int"}
RING_2_ENVS = {"test", "testing", "qa"}
RING_3_ENVS = {"stage", "staging", "uat", "pre-prod", "preprod", "dr", "qa/dr"}
# Ring 4 = production or unknown

# Tanium-specific region mappings (Japan → JP, not JAPAN)
REGIONS_FILE = ROOT_DIRECTORY / "data" / "regions_by_country_tanium.json"
with open(REGIONS_FILE, "r") as f:
    REGIONS_BY_COUNTRY = json.load(f)

# Tanium ring tag pattern: EPP_ECMTag_{REGION}_{SRV|Wks}_Ring{N}
RING_TAG_PATTERN = re.compile(
    r"EPP_ECMTag_([A-Za-z]+)_(SRV|Wks)_Ring(\d+)", re.IGNORECASE
)


def get_expected_ring(env):
    """Return expected ring number based on environment (servers only)."""
    if env in RING_1_ENVS:
        return 1
    if env in RING_2_ENVS:
        return 2
    if env in RING_3_ENVS:
        return 3
    return 4


def analyze_ring_tags(hosts_df):
    """Analyze hosts and mark those with invalid ring tags.

    Server tags (SRV): validated on environment AND region.
    Workstation tags (Wks): validated on region ONLY (ring number is %-distributed).
    Ring 0: exempt from all validation.
    """
    total_hosts = len(hosts_df)
    logger.info(f"Starting Tanium ring tag analysis for {total_hosts} hosts")

    # Collect results positionally, then assign once — `df.loc[idx, col] = val`
    # per-row is O(rows × cols) on arrow-backed string columns (observed 5-15 min
    # on 85K rows). Two bulk column assigns at the end are O(rows).
    has_invalid = [False] * total_hosts
    comments = [""] * total_hosts

    # Pre-extract columns as numpy arrays so we don't pay Series-construction
    # cost on every iterrows yield.
    tags_arr = hosts_df["Current Tags"].to_numpy()
    hostname_arr = (
        hosts_df.get("Hostname", pd.Series([""] * total_hosts))
        .fillna("").astype(str).to_numpy()
    )
    env_arr = (
        hosts_df.get("SNOW_environment", pd.Series([""] * total_hosts))
        .fillna("").astype(str).str.strip().str.lower().to_numpy()
    )
    country_arr = (
        hosts_df.get("SNOW_country", pd.Series([""] * total_hosts))
        .fillna("").astype(str).str.strip().to_numpy()
    )

    for pos in range(total_hosts):
        if pos > 0 and pos % 10000 == 0:
            pct = (pos / total_hosts) * 100
            logger.info(f"Progress: {pos}/{total_hosts} hosts analyzed ({pct:.1f}%)")

        current_tags = tags_arr[pos]
        if current_tags is None or (isinstance(current_tags, float) and pd.isna(current_tags)):
            continue
        current_tags = str(current_tags)

        matches = RING_TAG_PATTERN.findall(current_tags)
        if not matches:
            continue

        entries = [
            {
                "region": region,
                "type": tag_type.upper(),
                "ring": int(ring_num),
                "full_tag": f"EPP_ECMTag_{region}_{tag_type}_Ring{ring_num}",
            }
            for region, tag_type, ring_num in matches
        ]

        # Ring 0 → exempt from all validation
        if any(e["ring"] == 0 for e in entries):
            continue

        srv_entries = [e for e in entries if e["type"] == "SRV"]
        wks_entries = [e for e in entries if e["type"] == "WKS"]

        def _append(new_text, _pos=pos):
            if comments[_pos]:
                comments[_pos] = f"{comments[_pos]}; {new_text}"
            else:
                comments[_pos] = new_text

        # --- multiple ring tags of the same category ---
        if len(srv_entries) > 1:
            has_invalid[pos] = True
            _append("multiple SRV ring tags found")

        if len(wks_entries) > 1:
            has_invalid[pos] = True
            _append("multiple Wks ring tags found")

        # --- environment validation (SRV only) ---
        env = env_arr[pos]
        if env and srv_entries:
            expected_ring = get_expected_ring(env)
            for entry in srv_entries:
                if entry["ring"] != expected_ring:
                    has_invalid[pos] = True
                    _append(
                        f"{env} server should be Ring {expected_ring}, has Ring {entry['ring']}"
                    )

        # --- country / region validation (all tag types) ---
        # India hosts split into PMLI (subsidiary — detected by hostname) vs MGCC
        # (everything else). SNOW country is "India" in both cases, so hostname
        # is the only signal that can distinguish them.
        country = country_arr[pos]
        expected_region = None
        if country == "India" and is_pmli_hostname(hostname_arr[pos]):
            expected_region = "PMLI"
        elif country and country in REGIONS_BY_COUNTRY:
            expected_region = REGIONS_BY_COUNTRY[country]

        if expected_region:
            for entry in entries:
                if entry["ring"] == 0:
                    continue
                actual_region = entry["region"]
                if actual_region and actual_region.casefold() != expected_region.casefold():
                    has_invalid[pos] = True
                    _append(
                        f"host in '{country}' (region {expected_region}) "
                        f"has tag for region {actual_region}"
                    )

    hosts_df["has_invalid_ring_tag"] = has_invalid
    hosts_df["comment"] = comments

    invalid_count = int(sum(has_invalid))
    logger.info(
        f"Completed ring tag analysis: {total_hosts} hosts processed, "
        f"{invalid_count} with invalid tags"
    )


def generate_report(instance_filter="cloud", progress_callback=None):
    """Generate the complete invalid ring tag analysis report.

    Args:
        instance_filter: "cloud" or "on-prem"
        progress_callback: Optional callable(str) invoked at each pipeline milestone.
            Exceptions inside the callback are logged and swallowed so they never
            break the job.

    Returns:
        Path to the filtered (invalid-only) report, or None if no invalid tags found.
    """
    def _progress(msg):
        logger.info(msg)
        if progress_callback is None:
            return
        try:
            progress_callback(msg)
        except Exception as e:
            logger.warning(f"progress_callback failed (non-fatal): {e}")

    today_date = datetime.now(EASTERN_TZ).strftime("%m-%d-%Y")
    output_dir = DATA_DIR / today_date
    output_dir.mkdir(parents=True, exist_ok=True)

    instance_label = instance_filter.replace("-", "_") if instance_filter else "all"

    # Step 1: Fetch all hosts from Tanium
    _progress(f"Step 1/5: Fetching all Tanium hosts ({instance_filter})...")
    normalized = instance_filter.lower().replace("-", "") if instance_filter else None
    client = TaniumClient(instance=normalized)
    all_hosts_file = client.get_and_export_all_computers(
        filename=f"all_tanium_hosts_{instance_label}.xlsx"
    )
    if not all_hosts_file:
        raise ValueError(f"No computers retrieved from Tanium ({instance_filter})!")

    # Step 2: Filter hosts that already have ring tags
    all_hosts_df = pd.read_excel(all_hosts_file, engine="openpyxl")
    _progress(f"Step 2/5: Read {len(all_hosts_df):,} hosts; filtering those with ring tags...")

    hosts_with_ring_tags = all_hosts_df[
        all_hosts_df["Current Tags"]
        .str.contains(r"EPP_ECMTag_.*_(?:SRV|Wks)_Ring", regex=True, case=False, na=False)
    ].copy()
    _progress(f"Step 2/5: Found {len(hosts_with_ring_tags):,} hosts with ring tags")

    if len(hosts_with_ring_tags) == 0:
        _progress("No hosts with ring tags found — nothing to analyze.")
        return None

    # Step 3: Save intermediate file for SNOW enrichment
    ring_tags_file = output_dir / f"tanium_hosts_with_ring_tags_{instance_label}.xlsx"
    hosts_with_ring_tags.to_excel(ring_tags_file, index=False, engine="openpyxl")
    apply_professional_formatting(ring_tags_file)

    # Step 4: Enrich with ServiceNow
    _progress(
        f"Step 4/5: Enriching {len(hosts_with_ring_tags):,} hosts via ServiceNow "
        "(slowest step — rate-limited API, ~30–45 min typical)..."
    )
    enriched_file_path = service_now.enrich_host_report(ring_tags_file)
    enriched_hosts = pd.read_excel(enriched_file_path, engine="openpyxl")
    _progress("Step 4/5: ServiceNow enrichment complete")

    # Step 5: Analyze ring tags
    _progress(f"Step 5/5: Analyzing ring tags on {len(enriched_hosts):,} hosts...")
    analyze_ring_tags(enriched_hosts)

    # Step 6: Save complete report (all hosts with analysis columns)
    complete_report_path = output_dir / f"tanium_hosts_with_invalid_ring_tags_{instance_label}.xlsx"
    enriched_hosts.to_excel(complete_report_path, index=False, engine="openpyxl")
    apply_professional_formatting(complete_report_path)

    # Step 7: Filtered report (invalid only)
    invalid_hosts = enriched_hosts[enriched_hosts["has_invalid_ring_tag"]].copy()
    if invalid_hosts.empty:
        logger.info("No hosts with invalid ring tags found")
        return None

    # Build an 'Invalid Tags' column listing only the ring tags on each host
    def _extract_ring_tags(row):
        tags = row.get("Current Tags", "")
        if pd.isna(tags):
            return ""
        return ", ".join(
            f"EPP_ECMTag_{r}_{t}_Ring{n}"
            for r, t, n in RING_TAG_PATTERN.findall(str(tags))
        )

    invalid_hosts["Invalid Tags"] = invalid_hosts.apply(_extract_ring_tags, axis=1)

    columns_to_keep = [
        "Hostname",
        "ID",
        "Current Tags",
        "Invalid Tags",
        "Last Seen",
        "OS Platform",
        "Source",
        "SNOW_id",
        "SNOW_ciClass",
        "SNOW_environment",
        "SNOW_country",
        "SNOW_lifecycleStatus",
        "comment",
    ]
    columns_to_keep = [c for c in columns_to_keep if c in invalid_hosts.columns]

    filtered_report_path = (
        output_dir / f"tanium_hosts_with_invalid_ring_tags_only_{instance_label}.xlsx"
    )
    invalid_hosts[columns_to_keep].to_excel(
        filtered_report_path, index=False, engine="openpyxl"
    )
    apply_professional_formatting(filtered_report_path)
    logger.info(f"Found {len(invalid_hosts)} hosts with invalid ring tags")

    return filtered_report_path
