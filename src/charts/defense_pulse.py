"""
control-efficacy analytics Analysis — Systemic security gap analysis, trends, and remediation
strategies derived from XSOAR incident data.

Produces 4 charts and 1 Markdown report for three stakeholder groups:
  - Technology Owners (remediation matrix)
  - Security Awareness Teams (awareness trends & campaign triggers)
  - CISO (executive summary, controls effectiveness)

Usage:
    python src/charts/defense_pulse.py --date 12-08-2025
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Literal

from pydantic import BaseModel, Field, field_validator

# Add the project root to Python path FIRST
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import pytz
from matplotlib import transforms
from matplotlib.patches import FancyBboxPatch

from src.charts.chart_style import apply_chart_style
from data.data_maps import TICKET_TYPE_MAPPING
from src.charts.defense_pulse_mappings import (
    enrich_ticket,
    get_remediation,
)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

log_level = logging.DEBUG if os.getenv('DEBUG_LOGS', '').lower() in ('true', '1', 'yes') else logging.INFO
logging.basicConfig(level=log_level, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

ROOT_DIRECTORY = Path(__file__).parent.parent.parent
EASTERN = pytz.timezone('US/Eastern')

# Styling constants
BG_COLOR = '#f8f9fa'
BORDER_COLOR = '#1A237E'
BRAND_COLOR = '#3F51B5'

# Category color palette (for heatmap / bar charts)
CATEGORY_COLORS = [
    '#1A237E', '#283593', '#303F9F', '#3949AB', '#3F51B5',
    '#5C6BC0', '#7986CB', '#9FA8DA', '#C5CAE9', '#E8EAF6',
    '#0D47A1', '#1565C0', '#1976D2', '#1E88E5', '#2196F3',
    '#42A5F5', '#64B5F6', '#90CAF9',
]

# Impact colors matching the project convention
IMPACT_COLORS = {
    "Malicious True Positive": "#b71c1c",
    "Detected": "#ffd700",
    "Prevented": "#2e7d32",
    "Benign True Positive": "#4caf50",
    "False Positive": "#81c784",
    "Ignore": "#808080",
    "Automated": "#26A69A",
    "Resolved": "#FF8F00",
    "Security Testing": "#1976d2",
    "QA": "#add8e6",
    "": "#d3d3d3",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _disposition_stats(df: pd.DataFrame) -> dict:
    """Compute blocked/escalated/MTP counts from a ticket DataFrame."""
    total = len(df)
    blocked = df[df['disposition'] == 'Blocked by Controls'].shape[0]
    escalated = df[df['disposition'] == 'Escalated to Human'].shape[0]
    blocked_pct = blocked / (blocked + escalated) * 100 if (blocked + escalated) else 0
    mtp = df[df['impact'] == 'Malicious True Positive'].shape[0]
    mtp_pct = mtp / total * 100 if total else 0
    return {
        'blocked': blocked, 'escalated': escalated, 'blocked_pct': blocked_pct,
        'mtp': mtp, 'mtp_pct': mtp_pct,
    }


def _short_type(ticket_type: str) -> str:
    """Abbreviate a ticket type using the project-wide mapping."""
    return TICKET_TYPE_MAPPING.get(ticket_type, ticket_type)


def _add_border(fig) -> None:
    """Add rounded border matching project convention."""
    fig.patch.set_edgecolor('none')
    fig.patch.set_linewidth(0)
    fancy_box = FancyBboxPatch(
        (0, 0), width=1.0, height=1.0,
        boxstyle="round,pad=0,rounding_size=0.01",
        edgecolor=BORDER_COLOR, facecolor='none',
        linewidth=4, transform=fig.transFigure,
        zorder=1000, clip_on=False,
    )
    fig.patches.append(fancy_box)


def _add_footer(fig) -> None:
    """Add timestamp + GS-DnR watermark."""
    now_eastern = datetime.now(EASTERN).strftime('%m/%d/%Y %I:%M %p %Z')
    trans = transforms.blended_transform_factory(fig.transFigure, fig.transFigure)
    fig.text(
        0.02, 0.02, f"Generated@ {now_eastern}",
        ha='left', va='bottom', fontsize=10, color=BORDER_COLOR, fontweight='bold',
        bbox=dict(boxstyle="round,pad=0.4", facecolor='white', alpha=0.9,
                  edgecolor=BORDER_COLOR, linewidth=1.5),
        transform=trans,
    )
    _wm_tag = os.environ.get("WATERMARK_TAG", "")
    if _wm_tag:
        fig.text(
            0.98, 0.02, _wm_tag, ha='right', va='bottom', fontsize=10,
            alpha=0.7, color=BRAND_COLOR, style='italic', fontweight='bold',
            transform=trans,
        )


def _save_chart(fig, output_dir: Path, filename: str) -> Path:
    """Save figure and close it."""
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / filename
    fig.savefig(path, dpi=300, bbox_inches='tight', pad_inches=0.05, facecolor=BG_COLOR)
    plt.close(fig)
    logger.info(f"Saved chart: {path}")
    return path


# ---------------------------------------------------------------------------
# Data Loading
# ---------------------------------------------------------------------------

def _load_previous_kpis(output_dir: Path) -> dict:
    """Load KPIs from the most recent *previous* dated folder.

    Scans web/static/charts/ for dated folders (MM-DD-YYYY) that have a
    control-efficacy analytics KPI JSON and returns the contents of the most recent one
    that is NOT the current output_dir.
    """
    charts_root = ROOT_DIRECTORY / "web" / "static" / "charts"
    if not charts_root.exists():
        return {}

    candidates = []
    for folder in charts_root.iterdir():
        if not folder.is_dir() or folder == output_dir:
            continue
        kpi_file = folder / "control-efficacy analytics - KPIs.json"
        if kpi_file.exists():
            candidates.append(kpi_file)

    if not candidates:
        return {}

    # Most recently modified KPI file
    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    try:
        return json.loads(candidates[0].read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        logger.warning(f"Could not read previous KPIs: {e}")
        return {}


def _find_latest_snapshot() -> str:
    """Find the most recent cached ticket snapshot date folder."""
    secops_dir = ROOT_DIRECTORY / "data" / "transient" / "secOps"
    candidates = []
    for folder in secops_dir.iterdir():
        ticket_file = folder / "past_90_days_tickets.json"
        if folder.is_dir() and ticket_file.exists():
            candidates.append(folder.name)
    if not candidates:
        raise FileNotFoundError(f"No ticket snapshots found in {secops_dir}")
    # Sort by folder modification time (most recent first)
    candidates.sort(key=lambda d: (secops_dir / d).stat().st_mtime, reverse=True)
    return candidates[0]


def load_tickets(date_str: str = None) -> List[Dict[str, Any]]:
    """Load cached ticket data and enrich every ticket with derived fields.

    Args:
        date_str: Date folder name (e.g. '12-08-2025'). If None, uses the latest snapshot.
    """
    if date_str is None:
        date_str = _find_latest_snapshot()
        logger.info(f"Auto-detected latest snapshot: {date_str}")

    data_path = ROOT_DIRECTORY / "data" / "transient" / "secOps" / date_str / "past_90_days_tickets.json"
    if not data_path.exists():
        raise FileNotFoundError(f"Cached ticket data not found: {data_path}")

    with open(data_path, "r") as f:
        raw = json.load(f)

    tickets = raw.get("data", raw) if isinstance(raw, dict) else raw
    logger.info(f"Loaded {len(tickets)} tickets from {data_path}")

    # Exclude duplicates (same pattern as ticket_pattern_analysis.py)
    before = len(tickets)
    tickets = [t for t in tickets if t.get('closeReason', '').lower() != 'duplicate']
    if before != len(tickets):
        logger.info(f"Excluded {before - len(tickets)} duplicate tickets ({len(tickets)} remaining)")

    for t in tickets:
        enrich_ticket(t)

    return tickets


# ---------------------------------------------------------------------------
# Chart 1: Category vs Impact Heatmap
# ---------------------------------------------------------------------------

def chart_category_impact_heatmap(tickets: List[dict], output_dir: Path) -> Path:
    """Security Category (rows) vs Impact (columns) heatmap."""
    apply_chart_style()

    df = pd.DataFrame(tickets)
    pivot = df.groupby(['security_category', 'impact']).size().unstack(fill_value=0)

    # Order impacts consistently
    impact_order = [i for i in [
        "Malicious True Positive", "Detected", "Prevented", "Benign True Positive",
        "False Positive", "Automated", "Ignore", "Resolved", "Security Testing", "QA", "",
    ] if i in pivot.columns]
    extra = [c for c in pivot.columns if c not in impact_order]
    pivot = pivot[impact_order + extra]

    # Sort rows by total descending
    pivot = pivot.loc[pivot.sum(axis=1).sort_values(ascending=False).index]

    fig, ax = plt.subplots(figsize=(16, max(8, int(len(pivot) * 0.7) + 2)), facecolor=BG_COLOR)
    fig.patch.set_facecolor(BG_COLOR)

    data = pivot.values.astype(float)
    im = ax.imshow(data, cmap='YlOrRd', aspect='auto')

    # Annotate cells
    for i in range(data.shape[0]):
        for j in range(data.shape[1]):
            val = int(data[i, j])
            if val > 0:
                text_color = 'white' if val > data.max() * 0.6 else 'black'
                ax.text(j, i, str(val), ha='center', va='center',
                        fontsize=9, fontweight='bold', color=text_color)

    ax.set_xticks(range(len(pivot.columns)))
    ax.set_xticklabels(pivot.columns, rotation=40, ha='right', fontsize=9)
    ax.set_yticks(range(len(pivot.index)))
    ax.set_yticklabels(pivot.index, fontsize=9)

    cbar = fig.colorbar(im, ax=ax, shrink=0.6, pad=0.02)
    cbar.set_label('Incident Count', fontsize=10, color=BORDER_COLOR)

    cbar.outline.set_edgecolor(BORDER_COLOR)

    total = int(data.sum())
    ax.set_title(f'Security Category vs Impact Distribution  ({total:,} incidents)',
                 fontsize=16, fontweight='bold', color=BORDER_COLOR, pad=20)

    _add_border(fig)
    _add_footer(fig)
    plt.tight_layout(rect=(0, 0.05, 1, 0.95))
    return _save_chart(fig, output_dir, 'control-efficacy analytics - Category Impact Heatmap.png')


# ---------------------------------------------------------------------------
# Chart 2: Root Cause vs Detection Source (stacked bar)
# ---------------------------------------------------------------------------

def chart_root_cause_detection_source(tickets: List[dict], output_dir: Path) -> Path:
    """Horizontal stacked bar — Root Cause on Y, Detection Source segments."""
    apply_chart_style()

    df = pd.DataFrame(tickets)
    df['source_short'] = df['type'].map(_short_type)

    pivot = df.groupby(['root_cause', 'source_short']).size().unstack(fill_value=0)
    pivot = pivot.loc[pivot.sum(axis=1).sort_values(ascending=True).index]  # ascending for horizontal

    fig, ax = plt.subplots(figsize=(16, max(8, int(len(pivot) * 0.6) + 2)), facecolor=BG_COLOR)
    fig.patch.set_facecolor(BG_COLOR)

    sources = pivot.columns.tolist()
    colors = CATEGORY_COLORS[:len(sources)]
    bottoms = np.zeros(len(pivot))

    for idx, source in enumerate(sources):
        vals = pivot[source].values
        ax.barh(range(len(pivot)), vals, left=bottoms, height=0.6,
                       label=source, color=colors[idx % len(colors)], edgecolor='white', linewidth=0.5)
        # Label segments with count > 0
        for i, (v, b) in enumerate(zip(vals, bottoms)):
            if v > 0 and v >= pivot.values.max() * 0.03:  # only label if >= 3% of max
                ax.text(b + v / 2, i, str(int(v)), ha='center', va='center',
                        fontsize=7, fontweight='bold', color='white')
        bottoms += vals

    ax.set_yticks(range(len(pivot)))
    ax.set_yticklabels(pivot.index, fontsize=9)
    ax.set_xlabel('Incident Count', fontsize=11, color=BORDER_COLOR)

    total = int(pivot.values.sum())
    ax.set_title(f'Root Cause vs Detection Source  ({total:,} incidents)',
                 fontsize=16, fontweight='bold', color=BORDER_COLOR, pad=20)

    ax.legend(loc='lower right', fontsize=8, framealpha=0.9, ncol=2)

    ax.spines['top'].set_visible(False)

    ax.spines['right'].set_visible(False)

    _add_border(fig)
    _add_footer(fig)
    plt.tight_layout(rect=(0, 0.05, 1, 0.95))
    return _save_chart(fig, output_dir, 'control-efficacy analytics - Root Cause Detection Source.png')


# ---------------------------------------------------------------------------
# Chart 3: control-efficacy analytics Dashboard (disposition ratio + donut)
# ---------------------------------------------------------------------------

def chart_defense_pulse_dashboard(tickets: List[dict], output_dir: Path) -> Path:
    """Blocked vs Escalated ratio per Detection Source + overall donut inset."""
    apply_chart_style()

    df = pd.DataFrame(tickets)
    df['source_short'] = df['type'].map(_short_type)

    # Filter to Blocked / Escalated only (drop "Other")
    df_disp = df[df['disposition'].isin(['Blocked by Controls', 'Escalated to Human'])].copy()

    pivot = df_disp.groupby(['source_short', 'disposition']).size().unstack(fill_value=0)
    for col in ['Blocked by Controls', 'Escalated to Human']:
        if col not in pivot.columns:
            pivot[col] = 0
    pivot = pivot[['Blocked by Controls', 'Escalated to Human']]
    pivot['total'] = pivot.sum(axis=1)
    pivot = pivot.sort_values('total', ascending=True)

    fig = plt.figure(figsize=(16, max(8, int(len(pivot) * 0.55) + 3)), facecolor=BG_COLOR)
    fig.patch.set_facecolor(BG_COLOR)

    # Main stacked bar area (left 75%)
    ax = fig.add_axes((0.12, 0.10, 0.55, 0.78))
    ax.set_facecolor(BG_COLOR)

    blocked = pivot['Blocked by Controls'].values
    escalated = pivot['Escalated to Human'].values
    y_pos = range(len(pivot))

    ax.barh(list(y_pos), blocked, height=0.6, label='Blocked by Controls',
            color='#2e7d32', edgecolor='white', linewidth=0.5)
    ax.barh(list(y_pos), escalated, left=blocked, height=0.6, label='Escalated to Human',
            color='#b71c1c', edgecolor='white', linewidth=0.5)

    # Percentage labels
    for i in range(len(pivot)):
        total = blocked[i] + escalated[i]
        if total > 0:
            pct_blocked = blocked[i] / total * 100
            # Label on right side of bar
            ax.text(total + pivot['total'].max() * 0.01, i,
                    f'{pct_blocked:.0f}% blocked', va='center', fontsize=8, color='#2e7d32', fontweight='bold')

    ax.set_yticks(list(y_pos))
    ax.set_yticklabels(pivot.index, fontsize=9)
    ax.set_xlabel('Incident Count', fontsize=11, color=BORDER_COLOR)
    ax.legend(loc='upper left', fontsize=9, framealpha=0.9)

    ax.spines['top'].set_visible(False)

    ax.spines['right'].set_visible(False)

    # Overall donut inset (right 20%)
    ax_donut = fig.add_axes((0.74, 0.28, 0.24, 0.50))
    ax_donut.set_facecolor(BG_COLOR)
    total_blocked = int(blocked.sum())
    total_escalated = int(escalated.sum())
    sizes = [total_blocked, total_escalated]
    donut_colors = ['#2e7d32', '#b71c1c']
    wedges, texts, autotexts = ax_donut.pie(
        sizes, colors=donut_colors, autopct='%1.0f%%',
        startangle=90, pctdistance=0.75,
        wedgeprops=dict(width=0.35, edgecolor='white', linewidth=2),
        textprops=dict(fontsize=11, fontweight='bold'),
    )
    for at in autotexts:
        at.set_color('white')
    ax_donut.set_title('Overall', fontsize=12, fontweight='bold', color=BORDER_COLOR, pad=8)
    ax_donut.text(0, 0, f'{total_blocked + total_escalated:,}\ntotal',
                  ha='center', va='center', fontsize=11, fontweight='bold', color=BORDER_COLOR)

    total = len(df)
    fig.suptitle(f'control-efficacy analytics Dashboard  ({total:,} incidents)',
                 fontsize=16, fontweight='bold', color=BORDER_COLOR, y=0.97)

    _add_border(fig)
    _add_footer(fig)
    return _save_chart(fig, output_dir, 'control-efficacy analytics - Dashboard.png')


# ---------------------------------------------------------------------------
# Chart 4: Awareness Trends (weekly line chart)
# ---------------------------------------------------------------------------

def chart_awareness_trends(tickets: List[dict], output_dir: Path) -> Path:
    """Weekly line chart of Human Error + Social Engineering root causes over 90 days."""
    apply_chart_style()

    awareness_causes = {'Human Error', 'Social Engineering'}
    df = pd.DataFrame(tickets)
    df['created_dt'] = pd.to_datetime(df['created'], format='ISO8601', utc=True)
    df_aware = df[df['root_cause'].isin(awareness_causes)].copy()

    # Weekly buckets

    df_aware['week'] = df_aware['created_dt'].dt.tz_convert(None).dt.to_period('W').apply(lambda p: p.start_time)

    weekly = df_aware.groupby(['week', 'root_cause']).size().unstack(fill_value=0)
    for col in awareness_causes:
        if col not in weekly.columns:
            weekly[col] = 0
    weekly = weekly.sort_index()

    fig, ax = plt.subplots(figsize=(16, 8), facecolor=BG_COLOR)
    fig.patch.set_facecolor(BG_COLOR)

    colors_map = {'Human Error': '#FF8F00', 'Social Engineering': '#b71c1c'}
    for cause in awareness_causes:
        vals = weekly[cause].values
        weeks = weekly.index
        ax.plot(weeks, vals, marker='o', markersize=5, linewidth=2,
                label=cause, color=colors_map.get(cause, '#333'))

        # Highlight spike weeks (> 1.5x trailing 4-week avg)
        for i in range(4, len(vals)):
            trailing_avg = vals[i - 4:i].mean()
            if trailing_avg > 0 and vals[i] > trailing_avg * 1.5:
                ax.annotate(
                    f'{int(vals[i])}',
                    xy=(weeks[i], vals[i]),
                    xytext=(0, 12), textcoords='offset points',
                    fontsize=9, fontweight='bold', color='red', ha='center',
                    arrowprops=dict(arrowstyle='->', color='red', lw=1.2),
                )

    ax.set_xlabel('Week', fontsize=11, color=BORDER_COLOR)
    ax.set_ylabel('Incident Count', fontsize=11, color=BORDER_COLOR)

    total = int(df_aware.shape[0])
    ax.set_title(f'Awareness-Related Incident Trends  ({total:,} incidents)',
                 fontsize=16, fontweight='bold', color=BORDER_COLOR, pad=20)

    ax.legend(fontsize=10, framealpha=0.9)

    ax.spines['top'].set_visible(False)

    ax.spines['right'].set_visible(False)

    # Format x-axis
    fig.autofmt_xdate(rotation=45, ha='right')

    _add_border(fig)
    _add_footer(fig)
    plt.tight_layout(rect=(0, 0.05, 1, 0.95))
    return _save_chart(fig, output_dir, 'control-efficacy analytics - Awareness Trends.png')


# ---------------------------------------------------------------------------
# Feature Stats: Cost, Attack Vectors, Identity, Repeat Offenders
# ---------------------------------------------------------------------------

def _cost_stats(df: pd.DataFrame, hourly_rate: int) -> dict:
    """Compute cost-per-incident metrics for escalated tickets.

    Uses median resolution time (robust to outliers) and estimates active
    analyst hours as ~2 hours per calendar day of resolution time.  This
    avoids the false assumption that an analyst works 24/7 for the entire
    ticket lifetime.
    """
    escalated = df[df['disposition'] == 'Escalated to Human'].copy()
    # Filter to tickets with valid resolution time (0-365 days)
    with_res = escalated[
        (escalated['resolution_time_days'].notna()) &
        (escalated['resolution_time_days'] >= 0) &
        (escalated['resolution_time_days'] <= 365)
    ]
    if len(with_res) == 0:
        return {
            'analyst_hourly_cost': hourly_rate,
            'median_resolution_days': 0,
            'avg_analyst_hours': 0,
            'cost_per_incident': 0,
            'total_human_cost': 0,
            'escalated_with_resolution': 0,
        }
    median_res_days = float(with_res['resolution_time_days'].median())
    # Estimate ~2 active analyst hours per calendar day, minimum 1 hour
    avg_analyst_hours = max(median_res_days * 2, 1.0)
    cost_per = avg_analyst_hours * hourly_rate
    total_cost = cost_per * len(with_res)
    return {
        'analyst_hourly_cost': hourly_rate,
        'median_resolution_days': round(median_res_days, 1),
        'avg_analyst_hours': round(avg_analyst_hours, 1),
        'cost_per_incident': round(cost_per, 2),
        'total_human_cost': round(total_cost, 2),
        'escalated_with_resolution': len(with_res),
    }


def _attack_vector_stats(df: pd.DataFrame) -> list:
    """Group tickets by attack vector with per-vector stats."""
    vectors = df.groupby('attack_vector').apply(
        lambda g: pd.Series({
            'count': len(g),
            'blocked_pct': round(
                g[g['disposition'] == 'Blocked by Controls'].shape[0] /
                max(g[g['disposition'].isin(['Blocked by Controls', 'Escalated to Human'])].shape[0], 1) * 100, 1
            ),
            'mtp': int((g['impact'] == 'Malicious True Positive').sum()),
        })
    )

    vectors = vectors.sort_values('count', ascending=False).reset_index()

    total = len(df)
    result = []
    for _, row in vectors.iterrows():
        result.append({
            'vector': row['attack_vector'],
            'count': int(row['count']),
            'pct': round(row['count'] / total * 100, 1) if total else 0,
            'blocked_pct': round(row['blocked_pct'], 1),
            'mtp': int(row['mtp']),
        })
    return result


def _identity_stats(df: pd.DataFrame) -> dict:
    """Compute identity-specific metrics from ticket data."""
    identity = df[df['attack_vector'] == 'Identity'].copy()
    total_all = len(df)
    total_id = len(identity)

    # Sub-type breakdown
    leaked = identity[identity['type'] == 'Leaked Credentials'].shape[0]
    cred_compromise = identity[identity['root_cause'] == 'Credential Compromise'].shape[0]
    brute_force = identity[identity['name'].str.contains(r'brute.?force', case=False, na=False)].shape[0]
    access_violations = identity[identity['name'].str.contains(r'Access\s*Pass', case=False, na=False)].shape[0]

    # Weekly trend
    if total_id > 0 and 'created_dt' in identity.columns:
    
        identity['week'] = identity['created_dt'].dt.tz_convert(None).dt.to_period('W').apply(lambda p: p.start_time)
        weekly = identity.groupby('week').size()
        if len(weekly) >= 4:
            last_4_avg = weekly.iloc[-4:].mean()
            current = weekly.iloc[-1]
            if current > last_4_avg * 1.1:
                trend = 'increasing'
            elif current < last_4_avg * 0.9:
                trend = 'decreasing'
            else:
                trend = 'stable'
        else:
            trend = 'insufficient_data'
    else:
        trend = 'no_data'

    # Blocked pct for identity
    id_actionable = identity[identity['disposition'].isin(['Blocked by Controls', 'Escalated to Human'])]
    id_blocked = identity[identity['disposition'] == 'Blocked by Controls'].shape[0]
    blocked_pct = round(id_blocked / max(len(id_actionable), 1) * 100, 1)

    return {
        'total': total_id,
        'pct_of_total': round(total_id / total_all * 100, 1) if total_all else 0,
        'leaked_credentials': leaked,
        'credential_compromise': cred_compromise,
        'brute_force': brute_force,
        'access_violations': access_violations,
        'weekly_trend': trend,
        'blocked_pct': blocked_pct,
    }


def _repeat_offender_stats(df: pd.DataFrame) -> dict:
    """Compute Pareto / repeat offender analysis for users and hosts."""

    def _top10_with_types(counts_series, field):
        """Build top-10 list with primary detection sources per entity."""
        top10 = counts_series.head(10)
        result = []
        for entity, cnt in top10.items():
            types = df[df[field] == entity]['type'].map(_short_type).value_counts().head(3).index.tolist()
            result.append({'entity': str(entity), 'count': int(cnt), 'types': types})
        return result

    def _pareto_stats(counts, field):
        """Compute Pareto stats + top-10 for a groupby size series."""
        if len(counts) == 0:
            return {'total_unique': 0, 'top10_count': 0, 'top10_pct_incidents': 0,
                    'pct_for_80': 0, 'top10': []}
        counts = counts.sort_values(ascending=False)
        total_incidents = counts.sum()
        total_entities = len(counts)

        top10 = counts.head(10)

        # Pareto: find X% of entities that generate 80% of incidents
        cumulative = counts.cumsum()
        threshold_80 = total_incidents * 0.80
        entities_for_80 = int((cumulative <= threshold_80).sum()) + 1
        pct_for_80 = round(entities_for_80 / total_entities * 100, 1)

        return {
            'total_unique': total_entities,
            'top10_count': min(10, total_entities),
            'top10_pct_incidents': round(top10.sum() / total_incidents * 100, 1) if total_incidents else 0,
            'pct_for_80': pct_for_80,
            'top10': _top10_with_types(counts, field),
        }

    # Filter valid users
    valid_users = df[
        (df['username'].notna()) &
        (~df['username'].isin(['Unknown', '', 'N/A']))
    ]
    user_counts = valid_users.groupby('username').size().sort_values(ascending=False)

    # Filter valid hosts
    valid_hosts = df[
        (df['hostname'].notna()) &
        (~df['hostname'].isin(['Unknown', '', 'N/A']))
    ]
    host_counts = valid_hosts.groupby('hostname').size().sort_values(ascending=False)

    return {
        'users': _pareto_stats(user_counts, 'username'),
        'hosts': _pareto_stats(host_counts, 'hostname'),
    }


# ---------------------------------------------------------------------------
# Chart 5: Repeat Offender Pareto Curves
# ---------------------------------------------------------------------------

def chart_repeat_offenders(tickets: List[dict], output_dir: Path) -> Path:
    """Dual Pareto curve: users (left) and hosts (right)."""
    apply_chart_style()

    df = pd.DataFrame(tickets)

    # Filter valid users and hosts
    valid_users = df[(df['username'].notna()) & (~df['username'].isin(['Unknown', '', 'N/A']))]
    valid_hosts = df[(df['hostname'].notna()) & (~df['hostname'].isin(['Unknown', '', 'N/A']))]

    user_counts = valid_users.groupby('username').size().sort_values(ascending=False)
    host_counts = valid_hosts.groupby('hostname').size().sort_values(ascending=False)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 7), facecolor=BG_COLOR)
    fig.patch.set_facecolor(BG_COLOR)

    def _plot_pareto(ax, counts, label, color):
        if len(counts) == 0:
            ax.text(0.5, 0.5, f'No valid {label} data', ha='center', va='center',
                    transform=ax.transAxes, fontsize=12, color=BORDER_COLOR)
            return
        total = counts.sum()
        n = len(counts)
        cum_entities = np.arange(1, n + 1) / n * 100
        cum_incidents = counts.cumsum().values / total * 100

        ax.fill_between(cum_entities, cum_incidents, alpha=0.15, color=color)
        ax.plot(cum_entities, cum_incidents, linewidth=2.5, color=color, label=f'{label} ({n:,} unique)')

        # 80% line
        ax.axhline(y=80, color='#b71c1c', linestyle='--', linewidth=1.2, alpha=0.7)
        ax.text(95, 82, '80%', fontsize=9, color='#b71c1c', ha='right', fontweight='bold')

        # Find and annotate the 80% threshold
        threshold = total * 0.80
        entities_for_80 = int((counts.cumsum() <= threshold).sum()) + 1
        pct_entities = entities_for_80 / n * 100

        ax.axvline(x=pct_entities, color='#b71c1c', linestyle=':', linewidth=1, alpha=0.5)
        ax.annotate(
            f'Top {pct_entities:.0f}% → 80% of incidents',
            xy=(pct_entities, 80), xytext=(min(pct_entities + 15, 85), 65),
            fontsize=9, fontweight='bold', color='#b71c1c',
            arrowprops=dict(arrowstyle='->', color='#b71c1c', lw=1.2),
        )

        # Diagonal reference (perfectly even distribution)
        ax.plot([0, 100], [0, 100], color='#999', linestyle='--', linewidth=0.8, alpha=0.5)

        ax.set_xlim(0, 100)
        ax.set_ylim(0, 100)
        ax.set_xlabel(f'Cumulative % of {label}', fontsize=10, color=BORDER_COLOR)
        ax.set_ylabel('Cumulative % of Incidents', fontsize=10, color=BORDER_COLOR)
        ax.set_title(f'{label} Concentration', fontsize=13, fontweight='bold', color=BORDER_COLOR, pad=12)
        ax.legend(fontsize=9, loc='lower right')
    
        ax.spines['top'].set_visible(False)
    
        ax.spines['right'].set_visible(False)

    _plot_pareto(ax1, user_counts, 'Users', '#1A237E')
    _plot_pareto(ax2, host_counts, 'Hosts', '#b71c1c')

    fig.suptitle('Repeat Offender Analysis — Pareto Concentration',
                 fontsize=16, fontweight='bold', color=BORDER_COLOR, y=0.98)

    _add_border(fig)
    _add_footer(fig)
    plt.tight_layout(rect=(0, 0.05, 1, 0.93))
    return _save_chart(fig, output_dir, 'control-efficacy analytics - Repeat Offenders.png')


# ---------------------------------------------------------------------------
# AI Analysis (LLM-generated insights)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Structured schema — mirrors the Control-Efficacy & Fix-Prioritization spec.
# Deterministic fields (run_metadata, observed_control_interactions) are
# computed in Python; the LLM only fills the judgment-heavy sections.
# ---------------------------------------------------------------------------

_CONTROL_DOMAIN = Literal["PREVENT", "DETECT", "CONTAIN", "RECOVER", "GOVERN"]
_CIR_OUTCOME = Literal["BLOCKED", "ALERTED", "MISSED", "BYPASSED", "NOT_APPLICABLE", "UNKNOWN"]
_FAILURE_OUTCOME = Literal["MISSED", "BYPASSED", "UNKNOWN"]
_CONFIDENCE = Literal["HIGH", "MEDIUM", "LOW"]
_FIX_TYPE = Literal["CONTROL_TUNING", "TELEMETRY", "PROCESS", "AUTOMATION", "ARCHITECTURE", "TRAINING", "GOVERNANCE"]
_PRIORITY = Literal["HIGH", "MEDIUM", "LOW"]
_METRIC_DIR = Literal["UP", "DOWN"]


class _Evidence(BaseModel):
    detection_source: Optional[str] = None
    event_source: Optional[str] = None
    log_source: Optional[str] = None
    security_category: Optional[str] = None
    security_subcategory: Optional[str] = None
    root_cause: Optional[str] = None
    close_notes_excerpt: Optional[str] = None


class _ExecutiveBLUF(BaseModel):
    control_health_statement: str = Field(description="One-paragraph statement on whether controls are holding. Stick to evidence from the data.")
    top_failure_modes: List[str] = Field(description="Names of the 2-4 most important failure modes (mechanism, not category).")
    top_fix_now: List[str] = Field(description="Titles of the 2-4 highest-ranked fixes that should happen next.")
    confidence: _CONFIDENCE


class _SupportingCIR(BaseModel):
    incident_id: Optional[str] = None
    control_name: str
    outcome: _FAILURE_OUTCOME
    confidence: _CONFIDENCE

    @field_validator("outcome", mode="before")
    @classmethod
    def _coerce_outcome(cls, v):
        # LLMs occasionally cite BLOCKED/ALERTED incidents as supporting a failure
        # mode (they are reasoning about "the control engaged but still left residual
        # risk"). The spec narrows supporting_cirs to failure outcomes only, so coerce
        # everything else to UNKNOWN rather than dropping the whole record.
        if isinstance(v, str):
            u = v.strip().upper()
            if u in ("MISSED", "BYPASSED", "UNKNOWN"):
                return u
            return "UNKNOWN"
        return v


class _FailureMode(BaseModel):
    failure_mode_id: str = Field(description="ID in the form FM-001, FM-002, ...")
    name: str = Field(description="Short failure-mode name (e.g. 'MFA bypass via helpdesk reset').")
    description: str
    associated_controls: List[str]
    mapped_techniques: List[str] = Field(description="MITRE ATT&CK technique IDs if inferable, else empty list.")
    evidence_summary: str
    supporting_cirs: List[_SupportingCIR]
    hypothesized_root_causes: List[str]
    what_to_measure_next: List[str]
    confidence: _CONFIDENCE


class _WhereObserved(BaseModel):
    incident_id: Optional[str] = None
    evidence: str


class _HumanCompensationSignal(BaseModel):
    signal_id: str = Field(description="ID in the form HC-001, HC-002, ...")
    pattern: str
    where_observed: List[_WhereObserved]
    why_it_matters: str
    likely_underlying_failure_modes: List[str] = Field(description="Failure mode IDs (FM-###) this signal points to.")
    confidence: _CONFIDENCE


class _SuccessMetric(BaseModel):
    metric: str
    desired_direction: _METRIC_DIR
    how_measured: str


class _FPIScoring(BaseModel):
    R_recurrence: Optional[int] = Field(default=None, ge=0, le=5)
    I_impact: Optional[int] = Field(default=None, ge=0, le=5)
    T_time_penalty: Optional[int] = Field(default=None, ge=0, le=5)
    H_human_cost: Optional[int] = Field(default=None, ge=0, le=5)
    E_external_alignment: Optional[int] = Field(default=None, ge=0, le=5)
    fpi_total: Optional[float] = None


class _FixCandidate(BaseModel):
    fix_id: str = Field(description="ID in the form FIX-001, FIX-002, ...")
    title: str
    failure_modes_addressed: List[str] = Field(description="One or more FM-### IDs — every fix MUST map to a failure mode.")
    fix_type: _FIX_TYPE
    what_changes: str
    where_it_applies: List[str]
    why_now: str
    success_metrics: List[_SuccessMetric]
    risk_reduction_mechanism: str
    dependencies: List[str]
    validation_plan: List[str]
    fpi_scoring: _FPIScoring
    rank: Optional[int] = None
    confidence: _CONFIDENCE


class _ExternalIntelAlignment(BaseModel):
    intel_item_id: str
    intel_summary: str
    mapped_techniques: List[str]
    which_failure_modes_it_weights: List[str]
    how_it_changes_urgency: str
    constraints: str


class _DataGap(BaseModel):
    gap_id: str = Field(description="ID in the form DG-001, DG-002, ...")
    missing_data: str
    impact_on_analysis: str
    how_to_collect: List[str]
    priority: _PRIORITY

    @field_validator("how_to_collect", mode="before")
    @classmethod
    def _wrap_str_as_list(cls, v):
        # LLMs sometimes emit a single string instead of a list — accept both.
        if isinstance(v, str):
            return [v] if v.strip() else []
        return v


class _QualityChecks(BaseModel):
    no_people_performance_evaluation: bool
    no_fabricated_counts_or_dates: bool
    all_fixes_tied_to_failure_modes: bool
    external_intel_not_used_as_proof: bool
    json_schema_valid: bool


class DefensePulseStructuredAnalysis(BaseModel):
    """LLM-emitted portion of the control-efficacy analysis.

    run_metadata and observed_control_interactions are computed deterministically
    from the ticket data in Python and merged into the final JSON, so the LLM
    only produces the judgment-heavy sections.
    """
    executive_bluf: _ExecutiveBLUF
    failure_modes: List[_FailureMode]
    human_compensation_signals: List[_HumanCompensationSignal]
    fix_candidates: List[_FixCandidate]
    external_intel_alignment: List[_ExternalIntelAlignment]
    data_gaps: List[_DataGap]
    quality_checks: _QualityChecks


# ---------------------------------------------------------------------------
# Deterministic CIR derivation
# ---------------------------------------------------------------------------

_TYPE_TO_CONTROL_DOMAIN: Dict[str, str] = {
    "CrowdStrike Falcon Detection": "DETECT",
    "CrowdStrike Falcon Incident": "DETECT",
    "Qradar Alert": "DETECT",
    "Splunk Alert": "DETECT",
    "Vectra Detection": "DETECT",
    "Akamai Alert": "PREVENT",
    "Prisma Cloud Compute Runtime Alert": "DETECT",
    "UEBA Prisma Cloud": "DETECT",
    "DSPM Risk Findings": "GOVERN",
    "Varonis Alert": "DETECT",
    "Employee Reported Incident": "GOVERN",
    "Lost or Stolen Computer": "CONTAIN",
    "Leaked Credentials": "DETECT",
    "Third Party Compromise": "GOVERN",
    "Area1 Alert": "PREVENT",
    "IOC Hunt": "DETECT",
    "SDM Escalation": "GOVERN",
    "Case": "GOVERN",
}

# Incident types that imply controls did NOT catch the threat first
_TYPES_THAT_SUGGEST_MISS = {"Employee Reported Incident", "SDM Escalation", "IOC Hunt"}


def _derive_cir_outcome(ticket: dict) -> tuple:
    """Return (outcome, confidence, why) for a single ticket's control interaction."""
    ticket_type = ticket.get("type", "") or ""
    disposition = ticket.get("disposition", "") or ""
    impact = ticket.get("impact", "") or ""

    # Security testing is expected traffic — not a control-efficacy event.
    if impact == "Security Testing":
        return ("NOT_APPLICABLE", "HIGH", "Security testing activity; control outcome not evaluable")

    # Routine automated hunts / remediations that found nothing to act on.
    if impact == "Ignore":
        return ("NOT_APPLICABLE", "HIGH", f"{ticket_type} with impact=Ignore — automated processing found no actionable signal")

    # Types that inherently imply controls did NOT catch the threat first.
    if ticket_type in _TYPES_THAT_SUGGEST_MISS:
        if impact == "Malicious True Positive":
            return (
                "MISSED", "MEDIUM",
                f"{ticket_type} with confirmed malicious activity — automated controls did not detect this first",
            )
        # Benign / FP user reports: control wasn't bypassed, just user-driven.
        return ("NOT_APPLICABLE", "MEDIUM",
                f"{ticket_type} without confirmed maliciousness — user-driven workflow, not a control-efficacy event")

    # Explicit control wins.
    if impact in ("Prevented", "Automated") or disposition == "Blocked by Controls":
        return ("BLOCKED", "HIGH",
                f"disposition={disposition or 'auto'}, impact={impact} — control engaged and neutralized")

    # Detection fired + human confirmed real threat.
    if disposition == "Escalated to Human" and impact == "Malicious True Positive":
        return ("ALERTED", "HIGH", "Detection fired and human analysis confirmed malicious activity")

    if disposition == "Escalated to Human":
        return ("ALERTED", "MEDIUM", f"Detection fired and was escalated; outcome impact={impact or 'unspecified'}")

    return ("UNKNOWN", "LOW", f"Insufficient signal (disposition={disposition or 'unset'}, impact={impact or 'unset'})")


def _build_cirs(tickets: List[dict], cap: Optional[int] = 300) -> List[dict]:
    """Emit schema-compliant IncidentCIR dicts, one per ticket, prioritizing
    audit-critical outcomes (MISSED/BYPASSED/ALERTED/UNKNOWN) and capping
    total records to keep the JSON file a reasonable size.

    Pass cap=None to get the full unsorted list (used for cluster aggregation
    over the entire population before persistence-time capping).
    """
    # Ordering: audit-critical outcomes stay at the top when capping.
    _OUTCOME_RANK = {
        "MISSED": 0, "BYPASSED": 1, "ALERTED": 2, "UNKNOWN": 3, "BLOCKED": 4, "NOT_APPLICABLE": 5,
    }

    records = []
    for t in tickets:
        outcome, confidence, why = _derive_cir_outcome(t)
        control_name = t.get("type") or "Unknown control"
        control_domain = _TYPE_TO_CONTROL_DOMAIN.get(t.get("type", ""), "DETECT")

        close_notes = (t.get("closeNotes") or "").strip()
        excerpt = close_notes[:240] if close_notes else None

        records.append({
            "_outcome_rank": _OUTCOME_RANK.get(outcome, 9),
            "incident_id": str(t.get("id")) if t.get("id") is not None else None,
            "incident_name": (t.get("name") or "").strip() or None,
            "severity": t.get("severity_display") or None,
            "status": t.get("status_display") or None,
            "occurred_utc": t.get("created") or None,  # occurred_date not in the cached shape
            "created_utc": t.get("created") or None,
            "closed_utc": t.get("closed") or None,
            "control_interactions": [{
                "control_name": control_name,
                "control_domain": control_domain,
                "expected_to_engage": True,
                "evidence": {
                    "detection_source": t.get("type") or None,
                    "event_source": None,
                    "log_source": None,
                    "security_category": t.get("security_category") or None,
                    "security_subcategory": t.get("root_cause") or None,
                    "root_cause": t.get("root_cause") or None,
                    "close_notes_excerpt": excerpt,
                },
                "outcome": outcome,
                "confidence": confidence,
                "why": why,
                "recommended_validation": _cir_validation_steps(outcome, t),
            }],
        })

    # Sort by outcome rank (audit-critical first), then cap if requested.
    records.sort(key=lambda r: r["_outcome_rank"])
    for r in records:
        r.pop("_outcome_rank", None)
    return records if cap is None else records[:cap]


def _cir_validation_steps(outcome: str, ticket: dict) -> List[str]:
    """Return concrete validation steps for a given CIR outcome."""
    t = ticket.get("type", "")
    if outcome == "MISSED":
        return [
            f"Review the raw telemetry for control {t} at the incident time; confirm whether an alert should have fired.",
            "Check rule coverage and tuning thresholds against the observed TTP.",
        ]
    if outcome == "BYPASSED":
        return [
            f"Re-run the detection pipeline on the original event data for {t} to verify reproducibility.",
            "Identify which control layer was evaded and map to the responsible control owner.",
        ]
    if outcome == "UNKNOWN":
        return [
            "Pull the ticket's close notes and analyst notes; re-classify once the disposition is confirmed.",
            "If still unclassifiable, treat as a data-quality gap on incident closure notes.",
        ]
    return []


def _aggregate_cir_clusters(cirs: List[dict]) -> List[dict]:
    """Cluster CIRs by (technology_owner/detection_source, security_category, outcome)
    with counts and representative incident IDs — this is what feeds the LLM."""
    buckets: Dict[tuple, dict] = {}
    for cir in cirs:
        ci = cir["control_interactions"][0]
        ev = ci["evidence"]
        key = (ev.get("detection_source") or "Unknown", ev.get("security_category") or "Unknown", ci["outcome"])
        b = buckets.setdefault(key, {
            "detection_source": key[0],
            "security_category": key[1],
            "outcome": key[2],
            "count": 0,
            "sample_incident_ids": [],
            "sample_names": [],
            "sample_close_notes": [],
        })
        b["count"] += 1
        if len(b["sample_incident_ids"]) < 5 and cir.get("incident_id"):
            b["sample_incident_ids"].append(cir["incident_id"])
            if cir.get("incident_name"):
                b["sample_names"].append(cir["incident_name"][:120])
            if ev.get("close_notes_excerpt"):
                b["sample_close_notes"].append(ev["close_notes_excerpt"][:160])
    clusters = sorted(buckets.values(), key=lambda x: x["count"], reverse=True)
    return clusters


# ---------------------------------------------------------------------------
# Prompt + LLM invocation
# ---------------------------------------------------------------------------

def _build_analysis_prompt(stats: dict, clusters: List[dict], total_cirs: int) -> str:
    """Render the full Control-Efficacy & Fix-Prioritization developer prompt."""
    parts: List[str] = []
    parts.append(
        "[DEVELOPER / TASK PROMPT — CONTROL EFFICACY & FIX PRIORITIZATION]\n\n"
        "Analyze the provided incident dataset to produce decision-grade, audit-defensible\n"
        "insight for an Incident Management + Response Engineering organization.\n\n"
        "Your analysis MUST answer:\n"
        "  (A) Are our controls holding?\n"
        "  (B) Where are we getting hit (repeatable attacker success paths / control failures)?\n"
        "  (C) What should we fix next (based on evidence + constrained prioritization)?\n\n"
        "IMPORTANT: Your purpose is NOT to summarize incidents, count alerts, or list top categories.\n"
        "Your purpose is to evaluate cybersecurity controls as they interact with attacker behavior:\n"
        "control engagement, control failure modes, human compensation signals, and fix priorities.\n"
    )

    parts.append(
        "\n=== NON-NEGOTIABLE OPERATING RULES ===\n"
        "R1. UNIT OF ANALYSIS = CONTROL INTERACTION (NOT INCIDENT). CIRs are pre-computed for you below.\n"
        "R2. FAILURE MODE > CATEGORY. Prefer repeatable failure mechanisms over category labels.\n"
        "    'Phishing' is not a failure mode. 'MFA bypass via helpdesk workflow' is.\n"
        "R3. FACT vs INFERENCE vs UNKNOWN. FACT = directly supported by the data; INFERENCE = plausible\n"
        "    interpretation (must be labeled); UNKNOWN = insufficient data (must be stated).\n"
        "R4. PROHIBITED: PEOPLE PERFORMANCE EVALUATION. Do not rank, score, compare, or evaluate\n"
        "    employees, analysts, teams, or individuals. You may refer to 'analyst actions' generically.\n"
        "R5. EXTERNAL INTEL RULE. External intel can ONLY increase urgency (weighting) when it matches an\n"
        "    internally observed failure mode. External intel alone is NOT proof of internal exposure.\n"
        "R6. NO FABRICATION. Do not fabricate counts, dates, dwell times, durations, or metrics. If a value\n"
        "    cannot be computed from the provided data, omit it and add a data_gaps entry.\n"
    )

    parts.append(
        "\n=== REQUIRED ANALYSIS FLOW ===\n"
        "Step D: Cluster MISSED/BYPASSED/UNKNOWN CIRs into named failure modes. Each failure mode must\n"
        "  include description, associated controls, supporting CIRs (with incident IDs), hypothesized\n"
        "  root causes (labeled as hypothesis), what to measure next, and a confidence rating.\n"
        "Step E: Extract human compensation signals (repeated triage loops, escalations, 'unable to\n"
        "  investigate', duplicates, reopen patterns, unusually long closure cycles — only if supported).\n"
        "  Treat these as process/control debt signals, never as individual performance issues.\n"
        "Step F: Produce 0-10 fix candidates. Every fix MUST map to >=1 failure mode and include success\n"
        "  metrics and a validation plan.\n"
        "Step G: Rank fixes by FPI = (2*R) + (2*I) + (1.5*T) + (1.5*H) + (0.5*E), each component 0-5.\n"
        "  Leave components null if data doesn't support scoring; rank ordinally if FPI totals are null.\n"
    )

    parts.append(
        "\n=== ENVIRONMENT CONTEXT ===\n"
        f"Organization: {stats.get('company_name') or 'the organization'}\n"
        f"Operating team: {stats.get('team_name') or 'Security Operations'}\n"
        f"Time window: last 90 days, ending {datetime.utcnow().strftime('%Y-%m-%d')} UTC.\n"
    )

    parts.append(
        "\n=== KPI SNAPSHOT (informational; DO NOT summarize — use ONLY to ground failure-mode claims) ===\n"
        f"Total incidents analyzed: {stats.get('total_incidents', 0):,}\n"
        f"Blocked by controls: {stats.get('blocked_count', 0):,} ({stats.get('blocked_pct', 0)}%)\n"
        f"Escalated to human: {stats.get('escalated_count', 0):,}\n"
        f"Malicious True Positives: {stats.get('mtp_count', 0):,} ({stats.get('mtp_pct', 0)}%)\n"
        f"Active detection sources: {stats.get('detection_sources', 0)}\n"
    )

    # Detection efficiency
    det_eff = stats.get('detection_efficiency') or []
    if det_eff:
        parts.append("\n=== DETECTION EFFICIENCY BY SOURCE ===")
        for row in det_eff:
            parts.append(f"  {row['source']}: {row['total']} total, {row['mtp']} MTP, {row['signal_ratio']:.1f}% signal ratio")

    # Root cause breakdown
    root_causes = stats.get('root_cause_breakdown') or []
    if root_causes:
        parts.append("\n=== ROOT CAUSE BREAKDOWN ===")
        for row in root_causes[:12]:
            parts.append(f"  {row['cause']}: {row['count']} ({row['pct']:.1f}%)")

    # Spike weeks (external intel proxy)
    spikes = stats.get('spike_weeks') or []
    if spikes:
        parts.append("\n=== FLAGGED SPIKE WEEKS (>1.5x trailing avg) ===")
        for s in spikes:
            parts.append(f"  {s['week']} — {s['category']}: {s['count']} (trailing avg {s['trailing_avg']})")

    # Tech owners
    owners = stats.get('technology_owners') or []
    if owners:
        parts.append("\n=== TECHNOLOGY OWNERS (team → tools they manage) ===")
        for o in owners[:15]:
            parts.append(f"  {o['owner']}: {', '.join(o['sources'])} ({o['total']} incidents)")

    # CIR clusters — the actual input for failure-mode synthesis
    parts.append(f"\n=== PRE-COMPUTED CIR CLUSTERS ({total_cirs} CIRs total, grouped by detection_source × category × outcome) ===")
    parts.append("Each row below is a cluster of CIRs. Use these to synthesize failure modes and fixes.")
    parts.append("Focus your analysis on MISSED, BYPASSED, UNKNOWN, and high-volume ALERTED clusters.")
    for c in clusters[:40]:
        sample = ", ".join(c['sample_incident_ids'][:3]) if c['sample_incident_ids'] else "—"
        parts.append(
            f"  [{c['outcome']}] {c['detection_source']} / {c['security_category']}"
            f" — count={c['count']}, sample_ids=[{sample}]"
        )
        for nm in c['sample_names'][:2]:
            parts.append(f"      name: {nm}")
        for note in c['sample_close_notes'][:1]:
            parts.append(f"      close_notes: {note}")

    parts.append(
        "\n=== OUTPUT INSTRUCTION ===\n"
        "Return ONLY the structured fields (executive_bluf, failure_modes, human_compensation_signals,\n"
        "fix_candidates, external_intel_alignment, data_gaps, quality_checks). Do NOT emit run_metadata\n"
        "or observed_control_interactions — those are filled deterministically.\n"
        "\n"
        "- failure_modes: 2-6 named mechanisms with supporting_cirs citing incident IDs from the clusters above.\n"
        "  CRITICAL: supporting_cirs.outcome MUST be one of {MISSED, BYPASSED, UNKNOWN} only. A BLOCKED or\n"
        "  ALERTED incident is, by definition, a control WIN and does NOT support a failure mode.\n"
        "    WRONG: {\"incident_id\": \"123\", \"control_name\": \"Qradar Alert\", \"outcome\": \"BLOCKED\", ...}\n"
        "    WRONG: {\"incident_id\": \"456\", \"control_name\": \"Qradar Alert\", \"outcome\": \"ALERTED\", ...}\n"
        "    RIGHT: {\"incident_id\": \"789\", \"control_name\": \"Qradar Alert\", \"outcome\": \"MISSED\", ...}\n"
        "  If you want to cite an ALERTED incident as proof of residual risk, rephrase the failure mode so\n"
        "  that the SUPPORTING evidence is a MISSED/UNKNOWN record, not the ALERTED one.\n"
        "\n"
        "- fix_candidates: 0-10, every one mapped to >=1 FM-###. Score R/I/T/H/E where data supports it;\n"
        "  leave null otherwise. Compute fpi_total when all five components are present.\n"
        "- human_compensation_signals: 0-5 process-debt signals, never individual performance.\n"
        "- external_intel_alignment: [] (no external intel feed wired in).\n"
        "- data_gaps: log every field you wanted but could not compute (e.g. per-incident event_source,\n"
        "  log_source, occurred_date, dwell time). how_to_collect MUST be a list of strings.\n"
        "    WRONG: \"how_to_collect\": \"Add event_source field to the ticket schema.\"\n"
        "    RIGHT: \"how_to_collect\": [\"Add event_source field to the ticket schema.\"]\n"
        "- quality_checks: set each boolean honestly based on your own output.\n"
    )
    return "\n".join(parts)


def _derive_markdown_for_legacy_ui(analysis: dict) -> dict:
    """Transform the new structured analysis into the legacy markdown keys so
    the existing UI panels (and PPTX screenshots) keep rendering during the
    transition. Each panel gets a bulleted summary derived from the JSON.
    """
    bluf = analysis.get("executive_bluf") or {}
    failure_modes = analysis.get("failure_modes") or []
    fixes = analysis.get("fix_candidates") or []
    hcs = analysis.get("human_compensation_signals") or []
    gaps = analysis.get("data_gaps") or []

    insight_lines = [bluf.get("control_health_statement", ""), ""]
    for fm in failure_modes:
        conf = (fm.get("confidence") or "").upper()
        insight_lines.append(f"- **[{conf}] {fm.get('name','')}** — {fm.get('description','')}")
    ai_insights_md = "\n".join(insight_lines).strip()

    action_lines = []
    ranked = sorted(fixes, key=lambda f: (f.get("rank") or 999))
    for fx in ranked:
        fpi = fx.get("fpi_scoring") or {}
        total = fpi.get("fpi_total")
        fpi_tag = f"FPI {total:.1f}" if isinstance(total, (int, float)) else "FPI n/a"
        rank = fx.get("rank")
        rank_tag = f"#{rank} · " if rank else ""
        action_lines.append(f"- **{rank_tag}{fx.get('title','')}** [{fpi_tag}] — {fx.get('what_changes','')}")
    ai_actions_md = "\n".join(action_lines).strip()

    remed_lines = []
    if hcs:
        remed_lines.append("**Human compensation signals**")
        for s in hcs:
            remed_lines.append(f"- {s.get('pattern','')} — {s.get('why_it_matters','')}")
        remed_lines.append("")
    if gaps:
        remed_lines.append("**Data gaps**")
        for g in gaps:
            remed_lines.append(f"- [{(g.get('priority') or '').upper()}] {g.get('missing_data','')} — {g.get('impact_on_analysis','')}")
    ai_remediation_md = "\n".join(remed_lines).strip()

    return {
        "ai_insights_md": ai_insights_md,
        "ai_actions_md": ai_actions_md,
        "ai_remediation_md": ai_remediation_md,
    }


def _generate_ai_analysis(stats: dict, tickets: List[dict]) -> dict:
    """Generate the Control-Efficacy & Fix-Prioritization analysis.

    Deterministic steps (CIR derivation, cluster aggregation, run metadata) run in
    Python. The LLM is only invoked for the judgment-heavy portions (failure modes,
    fix candidates, human compensation signals, data gaps, quality checks).

    Returns a dict with:
      - ai_analysis: the full structured JSON (schema-compliant)
      - ai_insights_md / ai_actions_md / ai_remediation_md: derived markdown for legacy UI panels
      - ai_prompt: the exact prompt sent to the LLM (for audit / UI info-icon)
    Returns {} on LLM failure so the caller can carry forward prior content.
    """
    try:
        from src.components.tipper_analyzer.llm_init import get_llm

        # ── Deterministic steps (run even if LLM is down) ────────────────────
        full_cirs = _build_cirs(tickets, cap=None)  # every ticket, for cluster stats
        clusters = _aggregate_cir_clusters(full_cirs)
        cirs = full_cirs[:300]  # cap what we persist so the KPI JSON stays small

        run_metadata = {
            "analysis_timestamp_utc": datetime.utcnow().isoformat(timespec="seconds") + "Z",
            "data_sources": ["xsoar_tickets_past_90_days"],
            "records_analyzed": len(tickets),
            "time_window": {
                "start_utc": min((t.get("created") for t in tickets if t.get("created")), default=None),
                "end_utc": max((t.get("created") for t in tickets if t.get("created")), default=None),
            },
        }

        llm = get_llm()
        if llm is None:
            logger.warning("LLM unavailable — skipping AI analysis")
            return {}

        prompt = _build_analysis_prompt(stats, clusters, total_cirs=len(cirs))
        structured_llm = llm.with_structured_output(DefensePulseStructuredAnalysis)
        response = structured_llm.invoke(prompt)
        llm_output = response.model_dump()

        # ── Assemble the full JSON (Python-deterministic + LLM-judgment) ─────
        analysis = {
            "run_metadata": run_metadata,
            "executive_bluf": llm_output["executive_bluf"],
            "observed_control_interactions": cirs,
            "failure_modes": llm_output["failure_modes"],
            "human_compensation_signals": llm_output["human_compensation_signals"],
            "fix_candidates": llm_output["fix_candidates"],
            "external_intel_alignment": llm_output["external_intel_alignment"],
            "data_gaps": llm_output["data_gaps"],
            "quality_checks": llm_output["quality_checks"],
        }

        legacy_md = _derive_markdown_for_legacy_ui(analysis)

        logger.info(
            "AI analysis generated: %d failure modes, %d fixes, %d signals, %d gaps",
            len(analysis["failure_modes"]),
            len(analysis["fix_candidates"]),
            len(analysis["human_compensation_signals"]),
            len(analysis["data_gaps"]),
        )
        return {
            "ai_analysis": analysis,
            "ai_prompt": prompt,
            **legacy_md,
        }

    except Exception as e:
        logger.warning(f"AI analysis failed (silent fallback): {e}")
        return {}


# ---------------------------------------------------------------------------
# Interactive Chart Data (for frontend drill-downs)
# ---------------------------------------------------------------------------

def _compute_chart_data(tickets: List[dict]) -> dict:
    """Compute raw data for interactive frontend charts and drill-downs."""
    df = pd.DataFrame(tickets)
    df['source_short'] = df['type'].map(_short_type)
    df['created_dt'] = pd.to_datetime(df['created'], format='ISO8601', utc=True)
    total = len(df)

    # ---- Category vs Impact heatmap ----
    cat_impact = df.groupby(['security_category', 'impact']).size().unstack(fill_value=0)
    impact_order = [i for i in [
        "Malicious True Positive", "Detected", "Prevented", "Benign True Positive",
        "False Positive", "Automated", "Ignore", "Resolved", "Security Testing", "QA", "",
    ] if i in cat_impact.columns]
    extra = [c for c in cat_impact.columns if c not in impact_order]
    cat_impact = cat_impact[impact_order + extra]
    cat_impact = cat_impact.loc[cat_impact.sum(axis=1).sort_values(ascending=False).index]

    # ---- Root Cause vs Detection Source ----
    rc_source = df.groupby(['root_cause', 'source_short']).size().unstack(fill_value=0)
    rc_source = rc_source.loc[rc_source.sum(axis=1).sort_values(ascending=False).index]

    # ---- Blocked vs Escalated per source ----
    df_disp = df[df['disposition'].isin(['Blocked by Controls', 'Escalated to Human'])].copy()
    disp_pivot = df_disp.groupby(['source_short', 'disposition']).size().unstack(fill_value=0)
    for col in ['Blocked by Controls', 'Escalated to Human']:
        if col not in disp_pivot.columns:
            disp_pivot[col] = 0
    disp_pivot = disp_pivot[['Blocked by Controls', 'Escalated to Human']]
    disp_pivot['total'] = disp_pivot.sum(axis=1)
    disp_pivot = disp_pivot.sort_values('total', ascending=False)

    # ---- Awareness weekly trends ----
    awareness_causes = {'Human Error', 'Social Engineering'}
    df_aware = df[df['root_cause'].isin(awareness_causes)].copy()
    if len(df_aware) > 0:
        df_aware['week'] = df_aware['created_dt'].dt.tz_convert(None).dt.to_period('W').apply(
            lambda p: p.start_time)
        weekly = df_aware.groupby(['week', 'root_cause']).size().unstack(fill_value=0)
        for col in awareness_causes:
            if col not in weekly.columns:
                weekly[col] = 0
        weekly = weekly.sort_index()
        awareness_data = {
            'weeks': [w.strftime('%Y-%m-%d') for w in weekly.index],
            'human_error': [int(x) for x in weekly['Human Error'].values],
            'social_engineering': [int(x) for x in weekly['Social Engineering'].values],
        }
    else:
        awareness_data = {'weeks': [], 'human_error': [], 'social_engineering': []}

    # ---- Category breakdown (Total Incidents KPI drill-down) ----
    cat_counts = df['security_category'].value_counts()
    category_breakdown = [
        {'category': str(cat), 'count': int(cnt), 'pct': round(cnt / total * 100, 1)}
        for cat, cnt in cat_counts.items()
    ]

    # ---- MTP breakdown by category ----
    mtp_df = df[df['impact'] == 'Malicious True Positive']
    mtp_by_cat = mtp_df['security_category'].value_counts()
    mtp_breakdown = [
        {'category': str(cat), 'count': int(cnt)}
        for cat, cnt in mtp_by_cat.items()
    ]

    # ---- Per-source efficiency (Control Effectiveness drill-down) ----
    source_eff = df.groupby('source_short').apply(
        lambda g: pd.Series({
            'total': len(g),
            'blocked': int((g['disposition'] == 'Blocked by Controls').sum()),
            'escalated': int((g['disposition'] == 'Escalated to Human').sum()),
            'mtp': int((g['impact'] == 'Malicious True Positive').sum()),
        })
    ).sort_values('total', ascending=False)
    source_efficiency = []
    for src, row in source_eff.iterrows():
        b, e = int(row['blocked']), int(row['escalated'])
        source_efficiency.append({
            'source': str(src), 'total': int(row['total']),
            'blocked': b, 'escalated': e,
            'block_rate': round(b / max(b + e, 1) * 100, 1),
            'mtp': int(row['mtp']),
            'signal_ratio': round(int(row['mtp']) / max(int(row['total']), 1) * 100, 1),
        })

    # ---- Deep-link mappings (category / source → raw ticket types) ----
    cat_to_types = {
        str(cat): sorted(grp.unique().tolist())
        for cat, grp in df.groupby('security_category')['type']
    }
    src_to_types = {
        str(src): sorted(grp.unique().tolist())
        for src, grp in df.groupby('source_short')['type']
    }

    return {
        'heatmap': {
            'categories': cat_impact.index.tolist(),
            'impacts': [str(c) for c in cat_impact.columns],
            'matrix': [[int(v) for v in row] for row in cat_impact.values],
        },
        'root_cause': {
            'root_causes': rc_source.index.tolist(),
            'sources': rc_source.columns.tolist(),
            'matrix': [[int(v) for v in row] for row in rc_source.values],
        },
        'dashboard': {
            'sources': disp_pivot.index.tolist(),
            'blocked': [int(x) for x in disp_pivot['Blocked by Controls'].values],
            'escalated': [int(x) for x in disp_pivot['Escalated to Human'].values],
        },
        'awareness': awareness_data,
        'category_breakdown': category_breakdown,
        'mtp_breakdown': mtp_breakdown,
        'source_efficiency': source_efficiency,
        'category_to_types': cat_to_types,
        'source_to_types': src_to_types,
    }


# ---------------------------------------------------------------------------
# Markdown Report
# ---------------------------------------------------------------------------

def generate_report(tickets: List[dict], output_dir: Path) -> Path:
    """Generate the control-efficacy analytics Strategic Report Markdown file."""
    df = pd.DataFrame(tickets)
    df['created_dt'] = pd.to_datetime(df['created'], format='ISO8601', utc=True)
    df['source_short'] = df['type'].map(_short_type)
    total = len(df)
    now_str = datetime.now(EASTERN).strftime('%B %d, %Y %I:%M %p %Z')

    lines: List[str] = []
    w = lines.append  # shorthand

    w(f"# control-efficacy analytics - Strategic Report")
    w(f"")
    w(f"*Generated: {now_str}*  ")
    w(f"*Data: {total:,} incidents over 90-day window*")
    w("")

    # ---- Executive Summary ------------------------------------------------
    w("## Executive Summary")
    w("")

    cat_counts = df['security_category'].value_counts()
    top_cat = cat_counts.index[0] if len(cat_counts) > 0 else "N/A"
    top_cat_count = int(cat_counts.iloc[0]) if len(cat_counts) > 0 else 0
    top_cat_pct = top_cat_count / total * 100 if total else 0

    ds = _disposition_stats(df)
    blocked, escalated, blocked_pct = ds['blocked'], ds['escalated'], ds['blocked_pct']
    mtp, mtp_pct = ds['mtp'], ds['mtp_pct']

    w(f"- **Top category:** {top_cat} ({top_cat_count:,} incidents, {top_cat_pct:.1f}% of total)")
    w(f"- **Controls effectiveness:** {blocked_pct:.0f}% of actionable incidents blocked by automated controls")
    w(f"- **True threat rate:** {mtp:,} Malicious True Positives ({mtp_pct:.1f}% of all incidents)")
    w(f"- **Total detection sources:** {df['type'].nunique()} active")
    w("")

    # ---- Period Comparison ------------------------------------------------
    prev = _load_previous_kpis(output_dir)
    if prev:
        w("## Period Comparison")
        w("")
        w("| Metric | Previous | Current | Change |")
        w("|--------|:--------:|:-------:|:------:|")

        def _fmt_change(cur_val, prev_val, as_pct=False, lower_good=False):
            """Format a change cell with favorable/unfavorable tag."""
            if prev_val is None or prev_val == 0:
                return "N/A"
            delta = cur_val - prev_val
            if as_pct:
                sign = '+' if delta > 0 else ''
                direction = 'favorable' if (delta < 0) == lower_good else 'unfavorable'
                return f"{sign}{delta:.1f}pp ({direction})"
            else:
                pct_chg = (delta / prev_val) * 100
                sign = '+' if delta > 0 else ''
                direction = 'favorable' if (delta < 0) == lower_good else 'unfavorable'
                return f"{sign}{int(delta):,} ({pct_chg:+.1f}%, {direction})"

        w(f"| Total Incidents | {prev.get('total_incidents', 'N/A'):,} | {total:,} | {_fmt_change(total, prev.get('total_incidents'), lower_good=True)} |")
        w(f"| Blocked % | {prev.get('blocked_pct', 'N/A')}% | {blocked_pct:.0f}% | {_fmt_change(blocked_pct, prev.get('blocked_pct'), as_pct=True, lower_good=False)} |")
        w(f"| MTP Rate | {prev.get('mtp_pct', 'N/A')}% | {mtp_pct:.1f}% | {_fmt_change(mtp_pct, prev.get('mtp_pct'), as_pct=True, lower_good=True)} |")
        w(f"| Top Category % | {prev.get('top_category_pct', 'N/A')}% | {top_cat_pct:.1f}% | {_fmt_change(top_cat_pct, prev.get('top_category_pct'), as_pct=True, lower_good=True)} |")

        prev_top = prev.get('top_category', '')
        if prev_top and prev_top != top_cat:
            w(f"\n*Note: Top category changed from **{prev_top}** to **{top_cat}***")
        w("")

    # ---- Volume Trends & Spike Analysis -----------------------------------
    w("## Volume Trends & Spike Analysis")
    w("")

    df['week'] = df['created_dt'].dt.tz_convert(None).dt.to_period('W').apply(lambda p: p.start_time)
    weekly_cat = df.groupby(['week', 'security_category']).size().unstack(fill_value=0).sort_index()

    spike_rows = []
    for cat in weekly_cat.columns:
        vals = weekly_cat[cat].values
        for i in range(4, len(vals)):
            trailing_avg = vals[i - 4:i].mean()
            if trailing_avg > 0 and vals[i] > trailing_avg * 1.5:
                week_label = weekly_cat.index[i].strftime('%Y-%m-%d')
                spike_rows.append((week_label, cat, int(vals[i]), f"{trailing_avg:.0f}"))

    if spike_rows:
        w("**Flagged weeks** (volume > 1.5x trailing 4-week average):")
        w("")
        w("| Week | Category | Count | Trailing Avg |")
        w("|------|----------|------:|-------------:|")
        for week, cat, count, avg in sorted(spike_rows):
            w(f"| {week} | {cat} | {count} | {avg} |")
    else:
        w("No significant volume spikes detected in the analysis period.")
    w("")

    # ---- Detection Efficiency Analysis ------------------------------------
    w("## Detection Efficiency Analysis")
    w("")
    w("Signal ratio = Malicious True Positive / Total per source")
    w("")
    w("| Detection Source | Total | MTP | Signal Ratio |")
    w("|-----------------|------:|----:|-------------:|")

    source_stats = df.groupby('source_short').agg(
        total=('id', 'size'),
        mtp=('impact', lambda x: (x == 'Malicious True Positive').sum()),
    ).sort_values('total', ascending=False)

    for src, row in source_stats.iterrows():
        ratio = row['mtp'] / row['total'] * 100 if row['total'] else 0
        w(f"| {src} | {int(row['total']):,} | {int(row['mtp']):,} | {ratio:.1f}% |")
    w("")

    # ---- Root Cause Analysis ----------------------------------------------
    w("## Root Cause Analysis")
    w("")
    rc_counts = df['root_cause'].value_counts()
    w("| Root Cause | Count | % of Total |")
    w("|------------|------:|-----------:|")
    for rc, count in rc_counts.items():
        pct = count / total * 100
        w(f"| {rc} | {count:,} | {pct:.1f}% |")
    w("")

    # ---- Awareness Campaign Triggers --------------------------------------
    w("## Awareness Campaign Triggers")
    w("")
    awareness_causes = {'Human Error', 'Social Engineering'}
    df_aware = df[df['root_cause'].isin(awareness_causes)]
    aware_count = len(df_aware)
    aware_pct = aware_count / total * 100 if total else 0
    w(f"Awareness-related incidents: **{aware_count:,}** ({aware_pct:.1f}% of total)")
    w("")

    if aware_count > 0:
        # Top affected regions
        region_counts = df_aware['affected_region'].value_counts().head(5)
        w("**Top affected regions:**")
        w("")
        for region, cnt in region_counts.items():
            w(f"- {region}: {cnt:,} incidents")
        w("")

        # Weekly trend summary
        aware_weekly = df_aware.groupby('week').size()
        if len(aware_weekly) >= 4:
            last_4_avg = aware_weekly.iloc[-4:].mean()
            current = aware_weekly.iloc[-1] if len(aware_weekly) > 0 else 0
            trend = "increasing" if current > last_4_avg * 1.1 else "stable" if current > last_4_avg * 0.9 else "decreasing"
            w(f"**Trend:** {trend} (current week: {int(current)}, trailing 4-week avg: {last_4_avg:.0f})")
        w("")

    # ---- Controls Effectiveness -------------------------------------------
    w("## Controls Effectiveness")
    w("")
    w(f"| Disposition | Count | % |")
    w(f"|-------------|------:|--:|")
    for disp in ['Blocked by Controls', 'Escalated to Human', 'Other']:
        cnt = df[df['disposition'] == disp].shape[0]
        pct = cnt / total * 100 if total else 0
        w(f"| {disp} | {cnt:,} | {pct:.1f}% |")
    w("")

    # Per-source breakdown
    w("**Per detection source:**")
    w("")
    w("| Source | Blocked | Escalated | Block Rate |")
    w("|--------|--------:|----------:|-----------:|")
    disp_pivot = df.groupby('source_short')['disposition'].value_counts().unstack(fill_value=0)
    for col in ['Blocked by Controls', 'Escalated to Human']:
        if col not in disp_pivot.columns:
            disp_pivot[col] = 0
    for src in disp_pivot.index:
        b = int(disp_pivot.loc[src, 'Blocked by Controls'])
        e = int(disp_pivot.loc[src, 'Escalated to Human'])
        rate = b / (b + e) * 100 if (b + e) else 0
        w(f"| {src} | {b:,} | {e:,} | {rate:.0f}% |")
    w("")

    # ---- Remediation Matrix -----------------------------------------------
    w("## Remediation Matrix")
    w("")
    w("| Security Category | Root Cause | Technology Owner | Suggested Action | Priority |")
    w("|-------------------|------------|------------------|------------------|----------|")

    # Build unique (category, root_cause, owner) combos sorted by volume then priority
    combos = df.groupby(['security_category', 'root_cause', 'technology_owner']).size().reset_index(name='count')
    combos = combos.sort_values('count', ascending=False)

    seen = set()
    for _, row in combos.iterrows():
        key = (row['security_category'], row['root_cause'])
        if key in seen:
            continue
        seen.add(key)
        rem = get_remediation(row['security_category'], row['root_cause'])
        w(f"| {row['security_category']} | {row['root_cause']} | {row['technology_owner']} | {rem['action']} | {rem['priority']} |")
    w("")

    # ---- Human Intervention Cost -------------------------------------------
    from my_config import get_config
    config = get_config()
    cost = _cost_stats(df, config.analyst_hourly_cost)
    w("## Human Intervention Cost")
    w("")
    w(f"Analyst hourly rate: **${config.analyst_hourly_cost}/hr**")
    w("")
    w("| Metric | Value |")
    w("|--------|------:|")
    w(f"| Escalated incidents with resolution data | {cost['escalated_with_resolution']:,} |")
    w(f"| Median resolution time | {cost['median_resolution_days']:.1f} days |")
    w(f"| Est. analyst hours per incident | {cost['avg_analyst_hours']:.1f} hrs |")
    w(f"| Cost per escalated incident | ${cost['cost_per_incident']:,.2f} |")
    w(f"| **Total human intervention cost** | **${cost['total_human_cost']:,.2f}** |")
    w("")

    # ---- Attack Vector Analysis ---------------------------------------------
    av_stats = _attack_vector_stats(df)
    w("## Attack Vector Analysis")
    w("")
    w("| Attack Vector | Count | % of Total | Blocked % | MTP |")
    w("|---------------|------:|-----------:|----------:|----:|")
    for av in av_stats:
        w(f"| {av['vector']} | {av['count']:,} | {av['pct']:.1f}% | {av['blocked_pct']:.0f}% | {av['mtp']:,} |")
    w("")

    # ---- Identity & Access Security -----------------------------------------
    id_stats = _identity_stats(df)
    w("## Identity & Access Security")
    w("")
    w(f"Identity incidents: **{id_stats['total']:,}** ({id_stats['pct_of_total']:.1f}% of total)")
    w("")
    w("| Sub-type | Count |")
    w("|----------|------:|")
    w(f"| Leaked Credentials | {id_stats['leaked_credentials']:,} |")
    w(f"| Credential Compromise | {id_stats['credential_compromise']:,} |")
    w(f"| Brute Force | {id_stats['brute_force']:,} |")
    w(f"| Access Violations | {id_stats['access_violations']:,} |")
    w("")
    w(f"Weekly trend: **{id_stats['weekly_trend']}** · Identity controls blocked: **{id_stats['blocked_pct']:.0f}%**")
    w("")

    # ---- Repeat Offender Analysis -------------------------------------------
    ro_stats = _repeat_offender_stats(df)
    w("## Repeat Offender Analysis")
    w("")
    w("### Users")
    w(f"- Unique users: {ro_stats['users']['total_unique']:,}")
    w(f"- Top {ro_stats['users']['pct_for_80']:.0f}% of users generate 80% of incidents")
    if ro_stats['users']['top10']:
        w("")
        w("| Rank | User | Incident Count | Primary Sources |")
        w("|-----:|------|---------------:|-----------------|")
        for i, u in enumerate(ro_stats['users']['top10'], 1):
            types_str = ', '.join(u['types']) if u['types'] else '-'
            w(f"| {i} | {u['entity']} | {u['count']:,} | {types_str} |")
    w("")
    w("### Hosts")
    w(f"- Unique hosts: {ro_stats['hosts']['total_unique']:,}")
    w(f"- Top {ro_stats['hosts']['pct_for_80']:.0f}% of hosts generate 80% of incidents")
    if ro_stats['hosts']['top10']:
        w("")
        w("| Rank | Host | Incident Count | Primary Sources |")
        w("|-----:|------|---------------:|-----------------|")
        for i, h in enumerate(ro_stats['hosts']['top10'], 1):
            types_str = ', '.join(h['types']) if h['types'] else '-'
            w(f"| {i} | {h['entity']} | {h['count']:,} | {types_str} |")
    w("")

    # ---- Continuous Remediation (placeholder for AI-generated content) ------
    w("## Continuous Remediation")
    w("")
    w("*This section is populated with AI-generated recommendations when the inference engine is available.*")
    w("")
    w("The following root cause concentrations drive remediation priorities:")
    w("")
    rc_counts = df['root_cause'].value_counts()
    top_rc = rc_counts.head(5)
    w("| Root Cause | Incidents | % of Total | Suggested Focus |")
    w("|------------|----------:|-----------:|-----------------|")
    for rc, count in top_rc.items():
        pct = count / total * 100
        rem = get_remediation(
            df[df['root_cause'] == rc]['security_category'].mode().iloc[0] if not df[df['root_cause'] == rc].empty else '',
            rc,
        )
        w(f"| {rc} | {count:,} | {pct:.1f}% | {rem['action'][:80]}{'…' if len(rem['action']) > 80 else ''} |")
    w("")

    w("---")
    _wm_tag = os.environ.get("WATERMARK_TAG", "")
    if _wm_tag:
        w(f"*Report generated by control-efficacy analytics Analysis | {_wm_tag}*")
    else:
        w("*Report generated by control-efficacy analytics Analysis*")

    # Write files
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "control-efficacy analytics - Strategic Report.md"
    report_path.write_text("\n".join(lines), encoding="utf-8")
    logger.info(f"Saved report: {report_path}")

    # Save KPI summary JSON for the dashboard
    kpi_path = output_dir / "control-efficacy analytics - KPIs.json"
    kpis = {
        "total_incidents": total,
        "top_category": top_cat,
        "top_category_count": top_cat_count,
        "top_category_pct": round(top_cat_pct, 1),
        "blocked_count": blocked,
        "escalated_count": escalated,
        "blocked_pct": round(blocked_pct, 0),
        "mtp_count": mtp,
        "mtp_pct": round(mtp_pct, 1),
        "detection_sources": int(df['type'].nunique()),
        "awareness_count": aware_count,
        "awareness_pct": round(aware_pct, 1),
        # Top attack vector (by alert count)
        "top_attack_vector": av_stats[0]['vector'] if av_stats else "N/A",
        "top_attack_vector_pct": av_stats[0]['pct'] if av_stats else 0,
        # New feature KPIs
        "cost": cost,
        "attack_vectors": av_stats,
        "identity": id_stats,
        "repeat_offenders": ro_stats,
    }
    # Compute trend deltas vs previous run
    prev = _load_previous_kpis(output_dir)
    if prev:
        def _delta(cur, prev_val):
            if prev_val is None or prev_val == 0:
                return None
            return round(((cur - prev_val) / prev_val) * 100, 1)

        d = _delta(total, prev.get('total_incidents'))
        if d is not None:
            kpis['delta_total_pct'] = d
        d = _delta(blocked_pct, prev.get('blocked_pct'))
        if d is not None:
            kpis['delta_blocked_pct'] = d
        d = _delta(mtp_pct, prev.get('mtp_pct'))
        if d is not None:
            kpis['delta_mtp_pct'] = d
        d = _delta(top_cat_pct, prev.get('top_category_pct'))
        if d is not None:
            kpis['delta_top_category_pct'] = d
        d = _delta(kpis['top_attack_vector_pct'], prev.get('top_attack_vector_pct'))
        if d is not None:
            kpis['delta_top_av_pct'] = d
        kpis['previous_kpis'] = prev

    # ---- AI-generated insights & actions -----------------------------------
    # Collect extra stats needed by the prompt (not persisted in KPI JSON)
    ai_stats = dict(kpis)  # shallow copy of core KPIs

    # Detection efficiency per source
    ai_stats['detection_efficiency'] = [
        {"source": src, "total": int(row['total']), "mtp": int(row['mtp']),
         "signal_ratio": row['mtp'] / row['total'] * 100 if row['total'] else 0}
        for src, row in source_stats.iterrows()
    ]

    # Root cause breakdown
    ai_stats['root_cause_breakdown'] = [
        {"cause": rc, "count": int(count), "pct": count / total * 100}
        for rc, count in rc_counts.items()
    ]

    # Spike weeks
    ai_stats['spike_weeks'] = [
        {"week": week, "category": cat, "count": count, "trailing_avg": avg}
        for week, cat, count, avg in sorted(spike_rows)
    ]

    # Awareness trend direction
    if aware_count > 0 and 'week' in df.columns:
        aware_weekly = df[df['root_cause'].isin({'Human Error', 'Social Engineering'})].groupby('week').size()
        if len(aware_weekly) >= 4:
            last_4_avg = aware_weekly.iloc[-4:].mean()
            current_wk = aware_weekly.iloc[-1] if len(aware_weekly) > 0 else 0
            if current_wk > last_4_avg * 1.1:
                ai_stats['awareness_trend'] = 'increasing'
            elif current_wk < last_4_avg * 0.9:
                ai_stats['awareness_trend'] = 'decreasing'
            else:
                ai_stats['awareness_trend'] = 'stable'

    # Top 5 remediation items
    remed_items = []
    seen_remed = set()
    for _, row in combos.iterrows():
        remed_key = (row['security_category'], row['root_cause'])
        if remed_key in seen_remed:
            continue
        seen_remed.add(remed_key)
        rem = get_remediation(row['security_category'], row['root_cause'])
        remed_items.append({
            "category": row['security_category'],
            "root_cause": row['root_cause'],
            "action": rem['action'],
            "priority": rem['priority'],
        })
        if len(remed_items) >= 5:
            break
    ai_stats['remediation_top5'] = remed_items

    # Technology owners — aggregate sources per owning team for the prompt
    owner_sources = df.groupby('technology_owner').agg(
        sources=('source_short', lambda x: sorted(x.unique().tolist())),
        total=('id', 'size'),
    ).sort_values('total', ascending=False)
    ai_stats['technology_owners'] = [
        {"owner": owner, "sources": row['sources'], "total": int(row['total'])}
        for owner, row in owner_sources.iterrows()
    ]

    # Environment context from config
    from my_config import get_config as _get_config
    _cfg = _get_config()
    ai_stats['company_name'] = _cfg.company_name
    ai_stats['team_name'] = _cfg.team_name

    ai_result = _generate_ai_analysis(ai_stats, tickets)
    if ai_result:
        kpis.update(ai_result)
    else:
        # Carry forward previous AI content so an LLM outage doesn't erase it
        for key in ('ai_analysis', 'ai_insights_md', 'ai_actions_md', 'ai_remediation_md', 'ai_prompt'):
            if prev.get(key):
                kpis[key] = prev[key]
                logger.info(f"Carried forward {key} from previous run")

    # Add interactive chart data for frontend drill-downs
    kpis['chart_data'] = _compute_chart_data(tickets)

    kpi_path.write_text(json.dumps(kpis, indent=2), encoding="utf-8")

    return report_path


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def send_webex_notification(tickets: List[dict], room_id: str = None) -> None:
    """Send a Webex message with key findings and a link to the dashboard.

    Args:
        tickets: Enriched ticket dicts.
        room_id: Override Webex room. Defaults to dev/test space.
    """
    try:
        from my_config import get_config
        from webexpythonsdk import WebexAPI

        config = get_config()
        room_id = room_id or config.webex_room_id_dev_test_space
        bot_token = config.webex_bot_access_token_moneyball

        if not room_id or not bot_token:
            logger.warning("Webex notification skipped — no room ID or bot token configured")
            return

        webex = WebexAPI(access_token=bot_token)

        df = pd.DataFrame(tickets)
        total = len(df)
        cat_counts = df['security_category'].value_counts()
        top_cat = cat_counts.index[0]
        top_cat_pct = cat_counts.iloc[0] / total * 100

        ds = _disposition_stats(df)
        blocked, escalated, blocked_pct = ds['blocked'], ds['escalated'], ds['blocked_pct']
        mtp = ds['mtp']

        base_url = config.web_server_url
        dashboard_url = f"{base_url}/defense-pulse"
        now_str = datetime.now(EASTERN).strftime('%B %d, %Y')

        # Detection sources count
        det_sources = df['type'].nunique()

        # Awareness incidents
        awareness_cats = {'Social Engineering', 'Human Error'}
        awareness_count = df[df['root_cause'].isin(awareness_cats)].shape[0]

        # Top detection source by volume
        src_counts = df['type'].map(_short_type).value_counts()
        top_src = src_counts.index[0] if len(src_counts) > 0 else 'N/A'
        top_src_count = src_counts.iloc[0] if len(src_counts) > 0 else 0

        md = (
            f"## 🛡️ control-efficacy analytics — Biweekly Analysis\n"
            f"📅 **{now_str}** · 90-day rolling window\n\n"
            f"---\n\n"
            f"- 📊 **Total Incidents:** {total:,} across {det_sources} detection sources\n"
            f"- 🏷️ **Top Category:** {top_cat} ({top_cat_pct:.0f}%)\n"
            f"- 🛡️ **Blocked by Controls:** {blocked_pct:.0f}% ({blocked:,} of {blocked + escalated:,})\n"
            f"- 🎯 **True Threats:** {mtp:,} Malicious True Positives ({mtp / total * 100:.1f}%)\n"
            f"- 📡 **Busiest Source:** {top_src} ({top_src_count:,} alerts)\n"
            f"- 🎓 **Awareness Incidents:** {awareness_count:,} ({awareness_count / total * 100:.1f}%)\n\n"
            f"---\n\n"
            f"🔗 **[View Full Dashboard]({dashboard_url})** for charts, AI insights, and the strategic report.\n"
        )

        webex.messages.create(roomId=room_id, markdown=md)
        logger.info("Sent control-efficacy analytics Webex notification")

    except Exception as e:
        logger.error(f"Failed to send Webex notification: {e}")


def generate_all(date_str: str = None, room_id: str = None) -> None:
    """Generate all control-efficacy analytics charts and report.

    Args:
        date_str: Date folder for cached data. If None, uses the latest snapshot.
        room_id: Override Webex room for notification. Defaults to dev/test space.
    """
    tickets = load_tickets(date_str)

    today_date = datetime.now().strftime('%m-%d-%Y')
    output_dir = ROOT_DIRECTORY / "web" / "static" / "charts" / today_date

    generated: List[Path] = [
        chart_category_impact_heatmap(tickets, output_dir),
        chart_root_cause_detection_source(tickets, output_dir),
        chart_defense_pulse_dashboard(tickets, output_dir),
        chart_awareness_trends(tickets, output_dir),
        chart_repeat_offenders(tickets, output_dir),
        generate_report(tickets, output_dir),
    ]

    # Notify via Webex
    send_webex_notification(tickets, room_id=room_id)

    print(f"\ncontrol-efficacy analytics Analysis complete — {len(generated)} files generated:")
    for p in generated:
        print(f"  {p}")


def make_chart(room_id: str = None) -> None:
    """Entry point matching other chart modules' make_chart() convention.

    Uses the latest available ticket snapshot automatically.
    """
    generate_all(room_id=room_id)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='control-efficacy analytics Analysis')
    parser.add_argument('--date', default=None,
                        help='Date folder for cached data (e.g. 12-08-2025). Defaults to latest.')
    args = parser.parse_args()
    generate_all(args.date)
