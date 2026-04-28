"""Auto-generate charts and chips from any Power BI dataset schema.

Given COLUMNSTATISTICS output, identifies the best columns for visualizations,
runs a few targeted DAX queries to fetch distribution data, and returns
Chart.js-ready configs.
"""

import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)

# ── Palette ──
PALETTE = [
    "#0046ad", "#00a651", "#f6be00", "#6a1b9a", "#dc2626",
    "#f59e0b", "#3b82f6", "#10b981", "#8b5cf6", "#ec4899",
    "#14b8a6", "#f97316", "#06b6d4", "#84cc16", "#a855f7",
]

# ── Column classification ──

_DATE_PATTERNS = re.compile(
    r"(?i)(date|created|modified|updated|closed|timestamp|time_stamp|_at$|_on$|_dt$)",
)
_ID_PATTERNS = re.compile(
    r"(?i)(^id$|_id$|_key$|_pk$|_fk$|guid|uuid|rownum|index)",
)
_SKIP_PATTERNS = re.compile(
    r"(?i)(RowNumber|path|url|link|image|photo|icon|thumb|hash|token|password|secret)",
)


def _classify_column(col_name: str, cardinality: int, min_val, max_val) -> str:
    """Classify a column as 'categorical', 'date', 'numeric', 'id', or 'skip'."""
    if _SKIP_PATTERNS.search(col_name):
        return "skip"
    if _ID_PATTERNS.search(col_name):
        return "id"
    if _DATE_PATTERNS.search(col_name):
        return "date"
    # Check if min/max look like dates (ISO format strings)
    if isinstance(min_val, str) and re.match(r"\d{4}-\d{2}-\d{2}", min_val):
        return "date"
    # Numeric with high cardinality → numeric
    if isinstance(min_val, (int, float)) and isinstance(max_val, (int, float)):
        if cardinality > 20:
            return "numeric"
        return "categorical"
    # Text with reasonable cardinality → categorical
    if 2 <= cardinality <= 30:
        return "categorical"
    if cardinality > 30:
        return "skip"
    return "skip"


def _pick_main_table(schema_rows: list[dict]) -> str:
    """Pick the most likely 'main' table — the one with the most columns."""
    table_counts: dict[str, int] = {}
    for row in schema_rows:
        tbl = row.get("[Table Name]", "")
        if not tbl or "DateTable" in tbl or "LocalDateTable" in tbl:
            continue
        table_counts[tbl] = table_counts.get(tbl, 0) + 1
    if not table_counts:
        return ""
    return max(table_counts, key=table_counts.get)


def _sanitize_col(col: str) -> str:
    """Strip brackets if present: [Foo] -> Foo."""
    return col.strip("[]")


def build_charts_and_chips(pbi_client, dataset_id: str, schema_rows: list[dict],
                           dataset_name: str = "") -> dict:
    """Analyze schema, run a few DAX queries, return charts + chips + KPIs.

    Args:
        pbi_client: PowerBIClient instance
        dataset_id: Power BI dataset ID
        schema_rows: Rows from COLUMNSTATISTICS()
        dataset_name: Human-readable dataset name (for curated chip lookup)

    Returns:
        {"charts": [...], "chips": [...], "kpis": [...]}
    """
    main_table = _pick_main_table(schema_rows)
    if not main_table:
        return {"charts": [], "chips": [], "kpis": []}

    # Classify columns in the main table
    categoricals = []
    dates = []
    numerics = []

    for row in schema_rows:
        tbl = row.get("[Table Name]", "")
        if tbl != main_table:
            continue
        col = _sanitize_col(row.get("[Column Name]", ""))
        if not col or "RowNumber" in col:
            continue
        card = row.get("[Cardinality]", 0) or 0
        min_v = row.get("[Min]")
        max_v = row.get("[Max]")
        kind = _classify_column(col, card, min_v, max_v)

        if kind == "categorical":
            categoricals.append({"name": col, "cardinality": card})
        elif kind == "date":
            dates.append({"name": col, "min": min_v, "max": max_v})
        elif kind == "numeric":
            numerics.append({"name": col, "cardinality": card, "min": min_v, "max": max_v})

    # Sort categoricals by cardinality (prefer 3-15 range for good charts)
    categoricals.sort(key=lambda c: abs(c["cardinality"] - 8))

    # Get total row count
    row_count = _get_row_count(pbi_client, dataset_id, main_table)

    charts = []
    kpis = []

    # KPI: row count
    if row_count:
        kpis.append({"label": f"Total {main_table} Rows", "value": f"{row_count:,}", "color": "#0046ad"})

    # KPI: column count
    main_cols = sum(1 for r in schema_rows if r.get("[Table Name]") == main_table and "RowNumber" not in r.get("[Column Name]", ""))
    kpis.append({"label": "Columns", "value": str(main_cols), "color": "#00a651"})

    # KPI: from numeric columns (first numeric with reasonable range)
    for num in numerics[:2]:
        if isinstance(num["min"], (int, float)) and isinstance(num["max"], (int, float)):
            kpis.append({
                "label": f"{num['name']} Range",
                "value": f"{num['min']:,.0f} – {num['max']:,.0f}",
                "color": "#6a1b9a",
            })
            break

    # ── Chart 1 & 2: Top categorical distributions ──
    for i, cat in enumerate(categoricals[:2]):
        chart = _build_distribution_chart(
            pbi_client, dataset_id, main_table, cat["name"], cat["cardinality"],
            chart_type="bar" if i == 0 else "doughnut",
            color_offset=i * 3,
        )
        if chart:
            charts.append(chart)

    # ── Chart 3: Date trend (if date column exists) ──
    if dates:
        chart = _build_date_trend(pbi_client, dataset_id, main_table, dates[0]["name"])
        if chart:
            charts.append(chart)

    # ── Chart 4: Another categorical or cross-tab ──
    if len(categoricals) > 2:
        chart = _build_distribution_chart(
            pbi_client, dataset_id, main_table, categoricals[2]["name"],
            categoricals[2]["cardinality"], chart_type="horizontalBar", color_offset=6,
        )
        if chart:
            charts.append(chart)

    # ── Build chips ──
    chips = _build_chips(main_table, categoricals, dates, numerics, dataset_name=dataset_name)

    return {"charts": charts, "chips": chips, "kpis": kpis}


def _get_row_count(pbi_client, dataset_id: str, table: str) -> Optional[int]:
    """Get total row count for a table."""
    try:
        dax = f'EVALUATE ROW("Count", COUNTROWS(\'{table}\'))'
        result = pbi_client.execute_dax(dataset_id, dax)
        if result.get("rows"):
            return result["rows"][0].get("[Count]", 0)
    except Exception as exc:
        logger.warning("Row count query failed for %s: %s", table, exc)
    return None


def _build_distribution_chart(
    pbi_client, dataset_id: str, table: str, column: str,
    cardinality: int, chart_type: str = "bar", color_offset: int = 0,
) -> Optional[dict]:
    """Build a distribution chart for a categorical column."""
    try:
        top_n = min(cardinality, 15)
        dax = f"""EVALUATE
TOPN({top_n},
    ADDCOLUMNS(
        VALUES('{table}'[{column}]),
        "Count", CALCULATE(COUNTROWS('{table}'))
    ),
    [Count], DESC
)"""
        result = pbi_client.execute_dax(dataset_id, dax)
        if result.get("error") or not result.get("rows"):
            return None

        rows = result["rows"]
        col_key = f"'{table}'[{column}]" if f"'{table}'[{column}]" in rows[0] else (
            f"[{column}]" if f"[{column}]" in rows[0] else list(rows[0].keys())[0]
        )
        count_key = "[Count]" if "[Count]" in rows[0] else list(rows[0].keys())[-1]

        labels = [str(r.get(col_key, "?"))[:30] for r in rows]
        values = [r.get(count_key, 0) for r in rows]

        if chart_type == "doughnut":
            colors = PALETTE[color_offset:color_offset + len(labels)]
            while len(colors) < len(labels):
                colors += PALETTE
            colors = colors[:len(labels)]
            datasets = [{"label": "Count", "data": values, "colors": colors}]
        else:
            datasets = [{"label": "Count", "data": values, "color": PALETTE[color_offset % len(PALETTE)]}]

        return {
            "id": f"dist-{column.lower().replace(' ', '-')[:20]}",
            "title": f"{_humanize(column)} Distribution",
            "type": chart_type,
            "labels": labels,
            "datasets": datasets,
            "xLabel": _humanize(column),
            "yLabel": "Count",
            "clickQuery": f"Tell me more about the {_humanize(column)} distribution",
        }
    except Exception as exc:
        logger.warning("Distribution chart failed for %s.%s: %s", table, column, exc)
        return None


def _build_date_trend(
    pbi_client, dataset_id: str, table: str, date_column: str,
) -> Optional[dict]:
    """Build a monthly trend chart from a date column."""
    try:
        dax = f"""EVALUATE
ADDCOLUMNS(
    SUMMARIZE('{table}', '{table}'[{date_column}].[Year], '{table}'[{date_column}].[MonthNo]),
    "Count", CALCULATE(COUNTROWS('{table}')),
    "Label", FORMAT(
        DATE('{table}'[{date_column}].[Year], '{table}'[{date_column}].[MonthNo], 1),
        "YYYY-MM"
    )
)"""
        result = pbi_client.execute_dax(dataset_id, dax)
        if result.get("error") or not result.get("rows"):
            # Fallback: simpler date grouping
            dax = f"""EVALUATE
TOPN(12,
    ADDCOLUMNS(
        VALUES('{table}'[{date_column}].[Month]),
        "Count", CALCULATE(COUNTROWS('{table}'))
    ),
    [Count], DESC
)"""
            result = pbi_client.execute_dax(dataset_id, dax)
            if result.get("error") or not result.get("rows"):
                return None

        rows = result["rows"]
        # Try to find the label and count keys
        keys = list(rows[0].keys())
        label_key = next((k for k in keys if "Label" in k or "Month" in k or "Year" in k), keys[0])
        count_key = next((k for k in keys if "Count" in k), keys[-1])

        # Sort by label if possible
        try:
            rows.sort(key=lambda r: str(r.get(label_key, "")))
        except Exception:
            pass

        # Limit to last 12 periods
        rows = rows[-12:]
        labels = [str(r.get(label_key, "?"))[:10] for r in rows]
        values = [r.get(count_key, 0) for r in rows]

        return {
            "id": f"trend-{date_column.lower().replace(' ', '-')[:20]}",
            "title": f"Trend by {_humanize(date_column)}",
            "type": "line",
            "labels": labels,
            "datasets": [{"label": "Count", "data": values, "color": "#0046ad"}],
            "xLabel": _humanize(date_column),
            "yLabel": "Count",
            "clickQuery": f"Show me the trend over time by {_humanize(date_column)}",
        }
    except Exception as exc:
        logger.warning("Date trend chart failed for %s.%s: %s", table, date_column, exc)
        return None


# ── Curated chips by dataset name (case-insensitive substring match) ──
# These replace the auto-generated chips when the dataset name matches.
CURATED_CHIPS: dict[str, list[dict]] = {
    "os currency": [
        {"label": "Current vs expired servers", "query": "How many servers are current vs expired vs extended?"},
        {"label": "OS currency by region", "query": "Show me OS currency breakdown by region"},
        {"label": "Expired OS versions", "query": "Which OS versions have the most expired hosts?"},
        {"label": "Workstation currency", "query": "How many workstations are running a current vs expired OS?"},
        {"label": "End of life this year", "query": "Which operating systems are reaching end of life this year?"},
        {"label": "Summarize the data", "query": "Give me a high-level summary of OS currency across servers and workstations"},
    ],
    "client_health": [
        {"label": "Missing security tools", "query": "How many assets are missing each security tool this month?"},
        {"label": "Coverage by region", "query": "How does security tool coverage compare across regions?"},
        {"label": "HVA vs non-HVA gaps", "query": "Are there more coverage gaps on HVA or non-HVA assets?"},
        {"label": "Tool coverage trend", "query": "How has tool coverage changed over the last few months?"},
        {"label": "Worst countries", "query": "Which countries have the most assets missing security tools?"},
        {"label": "Exempt vs non-exempt", "query": "How many missing tools are due to exemptions vs actual gaps?"},
    ],
    "crowdstrike": [
        {"label": "Sensor coverage", "query": "How many assets have CrowdStrike installed vs missing?"},
        {"label": "Agent versions", "query": "What CrowdStrike agent versions are deployed and how many are outdated?"},
        {"label": "Coverage by country", "query": "Which countries have the worst CrowdStrike coverage?"},
        {"label": "Servers vs workstations", "query": "How does CrowdStrike coverage compare between servers and workstations?"},
        {"label": "Offline sensors", "query": "How many CrowdStrike sensors have not been seen recently?"},
        {"label": "Summarize the data", "query": "Give me a high-level summary of CrowdStrike deployment status"},
    ],
    "workstation patching": [
        {"label": "Patch compliance rate", "query": "What is the current workstation patch compliance rate?"},
        {"label": "Compliance by country", "query": "Which countries have the lowest patch compliance?"},
        {"label": "Compliance trend", "query": "How has patch compliance changed month over month?"},
        {"label": "Missing patches", "query": "How many workstations are missing patches and how many patches are missing?"},
        {"label": "HVA compliance", "query": "What is the patch compliance rate for HVA assets?"},
        {"label": "Summarize the data", "query": "Give me a high-level summary of workstation patching compliance"},
    ],
    "server os patching": [
        {"label": "Patch compliance", "query": "What is the current server patch compliance rate?"},
        {"label": "Non-compliant servers", "query": "How many servers are non-compliant and what are they missing?"},
        {"label": "Compliance by region", "query": "How does server patch compliance compare across regions?"},
        {"label": "Compliance trend", "query": "How has server patch compliance changed over the last few months?"},
        {"label": "HVA servers", "query": "What is the patch compliance rate for HVA servers?"},
        {"label": "Summarize the data", "query": "Give me a high-level summary of server OS patching"},
    ],
    "ssl vulnerability": [
        {"label": "Open SSL issues", "query": "How many SSL certificate issues are currently open?"},
        {"label": "Issues by type", "query": "What are the most common types of SSL certificate issues?"},
        {"label": "Aging issues", "query": "How many SSL issues have been open for more than 30 days?"},
        {"label": "Issues by region", "query": "Which regions have the most SSL certificate issues?"},
        {"label": "Priority breakdown", "query": "How many SSL issues are Priority 1 vs Priority 2?"},
        {"label": "Summarize the data", "query": "Give me a high-level summary of SSL vulnerability status"},
    ],
    "dns infoblox": [
        {"label": "DNS compliance", "query": "How many assets are using approved InfoBlox DNS vs non-approved DNS?"},
        {"label": "DNS by country", "query": "Which countries have the most assets with non-compliant DNS?"},
        {"label": "DNS classification", "query": "Show me the breakdown of DNS classification categories"},
        {"label": "Servers vs workstations", "query": "How does DNS compliance compare between servers and workstations?"},
        {"label": "Summarize the data", "query": "Give me a high-level summary of DNS configuration compliance"},
    ],
    "venafi": [
        {"label": "Certificate expiry", "query": "How many certificates are expiring in the next 30 days?"},
        {"label": "Expired certificates", "query": "How many certificates have already expired?"},
        {"label": "Certificates by issuer", "query": "Show me the certificate breakdown by issuing CA"},
        {"label": "Certificate health", "query": "How many certificates are healthy vs have issues?"},
        {"label": "Summarize the data", "query": "Give me a high-level summary of certificate management status"},
    ],
    "tanium": [
        {"label": "Tanium coverage", "query": "How many assets have Tanium installed vs missing?"},
        {"label": "Coverage by country", "query": "Which countries have the lowest Tanium coverage?"},
        {"label": "Coverage trend", "query": "How has Tanium coverage changed over the last few months?"},
        {"label": "Servers vs workstations", "query": "How does Tanium coverage compare between servers and workstations?"},
        {"label": "Summarize the data", "query": "Give me a high-level summary of Tanium deployment status"},
    ],
    "endpoint_cmdb": [
        {"label": "Asset inventory", "query": "How many servers vs workstations are in the CMDB?"},
        {"label": "Assets by country", "query": "Which countries have the most assets?"},
        {"label": "Security tool coverage", "query": "How many assets have each security tool installed?"},
        {"label": "Operational status", "query": "How many assets are operational vs retired vs pipeline?"},
        {"label": "Summarize the data", "query": "Give me a high-level summary of the endpoint CMDB inventory"},
    ],
    "sacm_dashboard": [
        {"label": "CMDB accuracy", "query": "What is the current CMDB data accuracy rate?"},
        {"label": "Missing data", "query": "Which CMDB fields have the most missing or incomplete data?"},
        {"label": "Accuracy by country", "query": "How does CMDB data quality compare across countries?"},
        {"label": "Summarize the data", "query": "Give me a high-level summary of SACM dashboard metrics"},
    ],
    "sacm_scorecard": [
        {"label": "Scorecard summary", "query": "What are the current SACM scorecard ratings?"},
        {"label": "Scores by region", "query": "How do SACM scores compare across regions?"},
        {"label": "HVA scorecard", "query": "What are the SACM scores for HVA assets?"},
        {"label": "Summarize the data", "query": "Give me a high-level summary of the SACM scorecard"},
    ],
    "macos_compliance": [
        {"label": "macOS compliance rate", "query": "What percentage of Macs are running a compliant OS version?"},
        {"label": "OS version distribution", "query": "Show me the breakdown of macOS versions in use"},
        {"label": "Outdated Macs", "query": "How many Macs are running an unsupported macOS version?"},
        {"label": "Compliance by country", "query": "Which countries have the lowest macOS compliance?"},
        {"label": "Summarize the data", "query": "Give me a high-level summary of macOS compliance"},
    ],
    "cmdb vs security": [
        {"label": "Tool discrepancies", "query": "Which security tools have the biggest gap between CMDB and actual deployment?"},
        {"label": "Missing from CMDB", "query": "How many assets appear in security tools but not in the CMDB?"},
        {"label": "Missing tools", "query": "How many CMDB assets are missing from each security tool?"},
        {"label": "Summarize the data", "query": "Give me a high-level summary comparing CMDB vs security tool data"},
    ],
    "gs currency": [
        {"label": "Currency status", "query": "How many assets are current vs expired vs extended?"},
        {"label": "Currency by region", "query": "How does OS currency compare across regions?"},
        {"label": "Expired by OS", "query": "Which operating systems have the most expired hosts?"},
        {"label": "Summarize the data", "query": "Give me a high-level summary of global services OS currency"},
    ],
}


def _humanize(name: str) -> str:
    """Turn 'OS_Version' into 'OS Version'."""
    return name.replace("_", " ")


def _build_chips(
    table: str, categoricals: list, dates: list, numerics: list,
    dataset_name: str = "",
) -> list[dict]:
    """Generate context-aware suggestion chips from schema metadata."""
    # Check curated chips first (case-insensitive substring match)
    if dataset_name:
        name_lower = dataset_name.lower()
        for key, curated in CURATED_CHIPS.items():
            if key in name_lower:
                return curated

    chips = []

    # Categorical-based chips
    for cat in categoricals[:3]:
        col = _humanize(cat["name"])
        chips.append({
            "label": f"Breakdown by {col}",
            "query": f"Show me the breakdown by {col}",
        })

    # Date-based chips
    if dates:
        col = _humanize(dates[0]["name"])
        chips.append({
            "label": "Trend over time",
            "query": f"Show me the trend over time by {col}",
        })

    # Numeric-based chips
    for num in numerics[:2]:
        col = _humanize(num["name"])
        chips.append({
            "label": f"Top 10 by {col}",
            "query": f"What are the top 10 records by {col}?",
        })

    # General chips
    chips.append({
        "label": "Summarize the data",
        "query": "Give me a summary of this dataset",
    })

    return chips[:8]  # Cap at 8
