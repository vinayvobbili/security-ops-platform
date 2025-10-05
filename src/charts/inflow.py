import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Tuple, Any

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import pytz
from matplotlib import transforms

from my_config import get_config
from services.xsoar import TicketHandler

# Add the project root to Python path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))


@dataclass
class ChartConfig:
    """Configuration for chart styling and behavior."""
    figure_size: Tuple[int, int] = (14, 10)
    font_family: List[str] = None
    background_color: str = '#f8f9fa'
    border_color: str = '#1A237E'
    border_width: int = 2

    def __post_init__(self):
        if self.font_family is None:
            # Use only bundled / always-available fonts to avoid warnings
            self.font_family = ['DejaVu Sans', 'sans-serif']


@dataclass
class ColorSchemes:
    """Color schemes for different chart categories."""

    SEVERITY_COLORS = {
        "Critical": "#DC2626", "High": "#EA580C", "Medium": "#CA8A04",
        "Low": "#16A34A", "Informational": "#3B82F6", "Info": "#3B82F6",
        "Unknown": "#6B7280", "4": "#DC2626", "3": "#EA580C",
        "2": "#CA8A04", "1": "#16A34A", "0": "#3B82F6", "": "#6B7280",
        # Add float mappings for numeric severity levels
        "4.0": "#DC2626", "3.0": "#EA580C", "2.0": "#CA8A04", 
        "1.0": "#16A34A", "0.0": "#3B82F6", "0.5": "#06B6D4"  # 0.5 gets teal color
    }
    
    @staticmethod
    def get_severity_color(severity) -> str:
        """Get color for severity with proper type handling."""
        # Handle various severity formats
        if severity is None or severity == '':
            return ColorSchemes.SEVERITY_COLORS.get('Unknown', '#6B7280')
        
        # Convert to string and try direct lookup
        sev_str = str(severity).strip()
        if sev_str in ColorSchemes.SEVERITY_COLORS:
            return ColorSchemes.SEVERITY_COLORS[sev_str]
        
        # Try as float if it's numeric
        try:
            sev_float = float(severity)
            # Map float values to standard severity levels
            if sev_float >= 4.0:
                return ColorSchemes.SEVERITY_COLORS["Critical"]
            elif sev_float >= 3.0:
                return ColorSchemes.SEVERITY_COLORS["High"] 
            elif sev_float >= 2.0:
                return ColorSchemes.SEVERITY_COLORS["Medium"]
            elif sev_float >= 1.0:
                return ColorSchemes.SEVERITY_COLORS["Low"]
            elif sev_float >= 0.5:
                return "#06B6D4"  # Teal for 0.5
            else:
                return ColorSchemes.SEVERITY_COLORS["Informational"]
        except (ValueError, TypeError):
            pass
        
        return ColorSchemes.SEVERITY_COLORS.get('Unknown', '#6B7280')

    IMPACT_COLORS = {
        "Significant": "#ff0000", "Confirmed": "#ffa500",
        "Malicious True Positive": "#b71c1c", "Detected": "#ffd700",
        "Prevented": "#2e7d32", "Ignore": "#808080",
        "Benign True Positive": "#4caf50", "Testing": "#add8e6",
        "Security Testing": "#1976d2", "False Positive": "#81c784",
        "Unknown": "#d3d3d3"
    }

    IMPACT_ORDER = [
        "Significant", "Malicious True Positive", "Confirmed", "Detected",
        "Prevented", "Benign True Positive", "False Positive", "Ignore",
        "Testing", "Security Testing", "Unknown"
    ]

    # Order for visual display with MTP at top (same as IMPACT_ORDER)
    VISUAL_ORDER = IMPACT_ORDER


class ChartStyler:
    """Handles chart styling and visual elements."""

    def __init__(self, config: ChartConfig):
        self.config = config
        self._setup_matplotlib()

    def _setup_matplotlib(self):
        """Configure matplotlib settings."""
        plt.style.use('default')
        import matplotlib
        matplotlib.rcParams['font.family'] = self.config.font_family

    def apply_base_styling(self, fig, ax):
        """Apply base styling to figure and axes."""
        fig.patch.set_facecolor(self.config.background_color)
        ax.set_facecolor('#ffffff')
        ax.grid(False)

        for spine in ax.spines.values():
            spine.set_visible(False)

    def add_border(self, fig):
        """Add blue rounded border to figure."""
        from matplotlib.patches import FancyBboxPatch

        # Set figure background
        fig.patch.set_facecolor(self.config.background_color)

        # Remove any existing FancyBboxPatch borders
        fig.patches = [p for p in fig.patches if not isinstance(p, FancyBboxPatch)]

        # Add rounded rectangle border
        fancy_box = FancyBboxPatch(
            (0.005, 0.005), 0.99, 0.99,  # Position and size with small margin
            boxstyle="round,pad=0.01,rounding_size=0.02",  # Rounded corners
            edgecolor=self.config.border_color,
            facecolor='none',
            linewidth=self.config.border_width,
            transform=fig.transFigure,
            zorder=1000,
            clip_on=False
        )
        fig.patches.append(fancy_box)

    def add_timestamp(self, fig):
        """Add timestamp to bottom left of figure."""
        eastern = pytz.timezone('US/Eastern')
        timestamp = datetime.now(eastern).strftime('%m/%d/%Y %I:%M %p %Z')
        trans = transforms.blended_transform_factory(fig.transFigure, fig.transFigure)

        plt.text(0.01, 0.02, f"Generated@ {timestamp}",
                 transform=trans, ha='left', va='bottom',
                 fontsize=10, color=self.config.border_color, fontweight='bold',
                 bbox=dict(boxstyle="round,pad=0.4", facecolor='white', alpha=0.9,
                           edgecolor=self.config.border_color, linewidth=1.5))

    def add_watermark(self, fig):
        """Add GS-DnR watermark to bottom right."""
        fig.text(0.99, 0.01, 'GS-DnR', ha='right', va='bottom',
                 fontsize=10, alpha=0.7, color='#3F51B5',
                 style='italic', fontweight='bold')


class DataProcessor:
    """Handles data processing and transformation."""

    @staticmethod
    def process_tickets_for_inflow(tickets: List[Dict]) -> pd.DataFrame:
        """Process tickets for inflow analysis."""
        df = pd.DataFrame(tickets)
        df['ticket_type'] = df['type'].fillna('Unknown')
        df['severity'] = df['severity'].fillna('Unknown')

        df['ticket_type'] = df['ticket_type'].replace('', 'Unknown')
        # Remove METCIRT prefix from ticket type names
        df['ticket_type'] = df['ticket_type'].str.replace(r'^METCIRT\s*', '', regex=True)
        # Shorten long ticket type names
        df['ticket_type'] = df['ticket_type'].replace({
            'CrowdStrike Falcon Detection': 'Crowdstrike Detection',
            'CrowdStrike Falcon Incident': 'Crowdstrike Incident',
            'Prisma Cloud Runtime Alert': 'Prisma Runtime',
            'Prisma Cloud Compute Runtime Alert': 'Prisma Compute',
            'Splunk Alert': 'Splunk Alert',
            'UEBA Prisma Cloud': 'UEBA Prisma'
        })
        return df.groupby(['ticket_type', 'severity']).size().reset_index(name='count')

    @staticmethod
    def process_tickets_for_period(tickets: List[Dict[str, Any]]) -> Tuple[pd.DataFrame, List[Any]]:
        """Process tickets for period analysis."""
        df = pd.DataFrame(tickets)
        df['created_date'] = pd.to_datetime(df['created'], format='ISO8601', errors='coerce').dt.date
        df['impact'] = df['CustomFields'].apply(lambda x: x.get('impact', 'Unknown'))
        df['impact'] = df['impact'].fillna('Unknown').replace('', 'Unknown')

        # Ensure impacts follow predefined order
        df['impact'] = df['impact'].apply(
            lambda x: x if x in ColorSchemes.IMPACT_ORDER else 'Unknown'
        )

        unique_dates = sorted(df['created_date'].unique())
        date_impact_counts = df.groupby(['created_date', 'impact']).size().reset_index(name='count')

        return date_impact_counts, unique_dates


class StackedBarChart:
    """Creates stacked bar charts."""

    def __init__(self, styler: ChartStyler):
        self.styler = styler

    def create_inflow_chart(self, df: pd.DataFrame, title: str) -> plt.Figure:
        """Create inflow stacked bar chart."""
        fig, ax = plt.subplots(figsize=self.styler.config.figure_size)
        self.styler.apply_base_styling(fig, ax)

        df_pivot = df.pivot_table(index='ticket_type', columns='severity', values='count', fill_value=0)
        colors = [ColorSchemes.get_severity_color(sev) for sev in df_pivot.columns]

        df_pivot.plot(kind='bar', stacked=True, ax=ax, color=colors,
                      width=0.6, edgecolor="white", linewidth=1.5, alpha=0.95)

        self._add_value_labels(ax)
        self._configure_axes(ax, "Ticket Type", "Number of Alerts", title)
        self._add_legend(ax, 'Severity')

        max_value = df_pivot.sum(axis=1).max()
        ax.set_ylim(0, max_value + 3)
        ax.yaxis.set_major_locator(plt.MaxNLocator(integer=True))

        return fig

    def _add_value_labels(self, ax) -> None:
        """Add value labels to bars."""
        for container in ax.containers:
            for bar in container:
                height = bar.get_height()
                if height > 0:
                    ax.text(bar.get_x() + bar.get_width() / 2,
                            bar.get_y() + height / 2,
                            f'{int(height)}', ha='center', va='center',
                            color='white', fontsize=14, fontweight='bold',
                            bbox=dict(boxstyle="circle,pad=0.2", facecolor='black',
                                      alpha=0.8, edgecolor='white', linewidth=1))

    def _configure_axes(self, ax, xlabel: str, ylabel: str, title: str) -> None:
        """Configure axes labels and title."""
        ax.set_xlabel(xlabel, fontweight='bold', fontsize=12,
                      color=self.styler.config.border_color, labelpad=10)
        ax.set_ylabel(ylabel, fontweight='bold', fontsize=12,
                      color=self.styler.config.border_color)
        ax.set_title(title, fontweight='bold', fontsize=20,
                     color=self.styler.config.border_color, pad=20)

        ax.set_xticklabels(ax.get_xticklabels(), rotation=45, ha='right',
                           fontsize=10, color=self.styler.config.border_color)
        ax.tick_params(axis='y', labelsize=10, colors=self.styler.config.border_color)
        ax.tick_params(axis='x', pad=5)

    def _add_legend(self, ax, title: str) -> None:
        """Add styled legend."""
        legend = ax.legend(title=title, loc='upper left', bbox_to_anchor=(1.01, 1), frameon=True,
                           fancybox=True, shadow=True, title_fontsize=12, fontsize=10)
        legend.get_frame().set_facecolor('white')
        legend.get_frame().set_alpha(0.95)
        legend.get_frame().set_edgecolor(self.styler.config.border_color)
        legend.get_frame().set_linewidth(2)


class PeriodChart:
    """Creates period-based charts."""

    def __init__(self, styler: ChartStyler):
        self.styler = styler

    def create_period_chart(self, date_impact_counts: pd.DataFrame,
                            unique_dates: List[Any], tickets: List[Dict[str, Any]], title: str) -> plt.Figure:
        """Create period chart with impact analysis."""
        fig, ax = plt.subplots(figsize=(20, 12), facecolor='#f8f9fa')
        fig.patch.set_facecolor('#f8f9fa')
        self.styler.apply_base_styling(fig, ax)

        dates = [date.strftime('%m/%d') for date in unique_dates]
        pivot_data = self._create_pivot_data(date_impact_counts, unique_dates)
        daily_totals = self._calculate_daily_totals(pivot_data)

        self._plot_stacked_bars(ax, dates, pivot_data, daily_totals)
        self._add_average_line(ax, daily_totals)
        self._configure_period_axes(ax, dates, daily_totals, title, len(tickets))

        # Add enhanced border
        from matplotlib.patches import FancyBboxPatch
        border_width = 4
        fig.patch.set_edgecolor('none')
        fig.patch.set_linewidth(0)

        fancy_box = FancyBboxPatch(
            (0, 0), width=1.0, height=1.0,
            boxstyle="round,pad=0,rounding_size=0.01",
            edgecolor='#1A237E',
            facecolor='none',
            linewidth=border_width,
            transform=fig.transFigure,
            zorder=1000,
            clip_on=False
        )
        fig.patches.append(fancy_box)

        # Add final layout adjustments
        plt.tight_layout()
        plt.subplots_adjust(top=0.85, bottom=0.15, left=0.08, right=0.85)

        return fig

    def _create_pivot_data(self, date_impact_counts: pd.DataFrame, unique_dates: List[Any]) -> Dict[str, np.ndarray]:
        """Create pivot data structure for plotting."""
        pivot_data = {impact: np.zeros(len(unique_dates)) for impact in ColorSchemes.IMPACT_ORDER}

        for _, row in date_impact_counts.iterrows():
            if row['created_date'] in unique_dates:
                date_idx = unique_dates.index(row['created_date'])
                pivot_data[row['impact']][date_idx] += row['count']

        return pivot_data

    def _calculate_daily_totals(self, pivot_data: Dict[str, np.ndarray]) -> np.ndarray:
        """Calculate daily totals from pivot data."""
        return sum(pivot_data.values())

    def _plot_stacked_bars(self, ax, dates: List[str], pivot_data: Dict[str, np.ndarray], daily_totals: np.ndarray) -> None:
        """Plot stacked bars for each impact category."""
        x = np.arange(len(dates))
        bottom = np.zeros(len(dates))

        for impact in ColorSchemes.VISUAL_ORDER:
            values = pivot_data[impact]
            if values.sum() > 0:  # Only plot if there are values
                ax.bar(x, values, bottom=bottom, label=impact, width=0.8,
                       color=ColorSchemes.IMPACT_COLORS.get(impact, '#000000'),
                       edgecolor='white', linewidth=0.5, alpha=0.9)
                bottom += values

        # Enhanced total labels
        for i, total in enumerate(daily_totals):
            if total > 0:
                ax.text(x[i], total + max(daily_totals) * 0.02, f'{int(total)}',
                        ha='center', va='bottom', fontsize=10, fontweight='bold',
                        color='#1A237E',
                        bbox=dict(boxstyle="round,pad=0.3", facecolor='white', alpha=0.95,
                                  edgecolor='#1A237E', linewidth=1.5))

    def _add_average_line(self, ax, daily_totals: np.ndarray) -> None:
        """Add daily average line."""
        daily_average = daily_totals.mean()
        ax.axhline(daily_average, color='blue', linestyle='--', linewidth=2.5,
                   label=f'Daily Average ({int(daily_average)})', alpha=0.8)

    def _configure_period_axes(self, ax, dates: List[str], daily_totals: np.ndarray,
                               title: str, ticket_count: int) -> None:
        """Configure axes for period chart."""
        x = np.arange(len(dates))
        ax.set_xticks(x)
        ax.set_ylim(0, daily_totals.max() * 1.15)

        # Show every 5th label to prevent crowding
        date_labels = [dates[i] if i % 5 == 0 else "" for i in range(len(dates))]
        ax.set_xticklabels(date_labels, rotation=45, ha='right', fontsize=10, fontweight='bold')
        ax.tick_params(axis='y', colors='#1A237E', labelsize=12, width=1.5)
        ax.tick_params(axis='x', colors='#1A237E', labelsize=10, width=1.5, pad=10)

        ax.set_xlabel("Created Date", fontweight='bold', fontsize=14, labelpad=15, color='#1A237E')
        ax.set_ylabel("Number of Tickets", fontweight='bold', fontsize=14, color='#1A237E')

        # Enhanced titles
        plt.suptitle(title, fontweight='bold', fontsize=24, color='#1A237E', y=0.95)
        ax.set_title(f"Total: {ticket_count} tickets", fontsize=16, color='#3F51B5', pad=20, fontweight='bold')

        # Enhanced legend with consistent order (MTP at top)
        legend = ax.legend(title='Impact',
                           title_fontproperties={'weight': 'bold', 'size': 14},
                           loc='upper left', bbox_to_anchor=(1.01, 1), fontsize=11,
                           frameon=True, fancybox=True, shadow=True)
        legend.get_frame().set_facecolor('white')
        legend.get_frame().set_alpha(0.95)
        legend.get_frame().set_edgecolor('#1A237E')
        legend.get_frame().set_linewidth(2)


class TicketChartGenerator:
    """Main class for generating ticket charts."""

    def __init__(self):
        self.config = get_config()
        self.chart_config = ChartConfig()
        self.styler = ChartStyler(self.chart_config)
        self.stacked_chart = StackedBarChart(self.styler)
        self.period_chart = PeriodChart(self.styler)
        self.ticket_handler = TicketHandler()
        self.eastern = pytz.timezone('US/Eastern')

        # Setup output directory
        self.root_directory = Path(__file__).parent.parent.parent
        today_date = datetime.now().strftime('%m-%d-%Y')
        self.output_dir = self.root_directory / "web" / "static" / "charts" / today_date
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_yesterday_chart(self) -> float:
        """Generate yesterday's inflow chart."""
        start_time = time.time()

        yesterday_start, yesterday_end = self._get_yesterday_range()
        query = f'type:{self.config.team_name} -owner:"" created:>={yesterday_start} created:<{yesterday_end}'
        tickets = self.ticket_handler.get_tickets(query=query)

        if not tickets:
            print('No tickets found for yesterday')
            return time.time() - start_time

        # Determine title and filename based on day of week
        is_monday = datetime.now(self.eastern).weekday() == 0
        period_label = "Weekend" if is_monday else "Yesterday"

        processed_data = DataProcessor.process_tickets_for_inflow(tickets)
        fig = self.stacked_chart.create_inflow_chart(
            processed_data, f"Inflow {period_label} ({len(tickets)})"
        )

        self._finalize_and_save_chart(fig, f"Inflow {period_label}.png")
        return time.time() - start_time

    def generate_60_day_chart(self) -> float:
        """Generate past 60 days chart using explicit timestamps."""
        start_time = time.time()

        # Calculate exact 60-day window
        end_date = datetime.now(self.eastern).replace(hour=23, minute=59, second=59, microsecond=999999)
        start_date = end_date - timedelta(days=60)
        start_date = start_date.replace(hour=0, minute=0, second=0, microsecond=0)

        start_str = start_date.astimezone(pytz.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        end_str = end_date.astimezone(pytz.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

        query = f'type:{self.config.team_name} -owner:"" created:>={start_str} created:<={end_str}'
        tickets = self.ticket_handler.get_tickets(query=query)

        if not tickets:
            print("No tickets found for Past 60 Days.")
            return time.time() - start_time

        date_impact_counts, unique_dates = DataProcessor.process_tickets_for_period(tickets)
        fig = self.period_chart.create_period_chart(date_impact_counts, unique_dates, tickets, "Inflow Over the Past 60 Days")

        self._finalize_and_save_chart(fig, "Inflow Past 60 Days.png")
        return time.time() - start_time

    def generate_12_month_chart(self) -> float:
        """Generate past 12 months impact chart using explicit timestamps."""
        start_time = time.time()

        # Calculate exact 12-month window
        end_date = datetime.now(self.eastern).replace(hour=23, minute=59, second=59, microsecond=999999)
        start_date = end_date - timedelta(days=365)
        start_date = start_date.replace(hour=0, minute=0, second=0, microsecond=0)

        start_str = start_date.astimezone(pytz.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        end_str = end_date.astimezone(pytz.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

        query = f'type:{self.config.team_name} -owner:"" created:>={start_str} created:<={end_str}'
        tickets = self.ticket_handler.get_tickets(query=query, size=20000)

        if not tickets:
            print("No tickets found for Past 12 Months.")
            return time.time() - start_time

        df = pd.DataFrame(tickets)
        df['created_dt'] = pd.to_datetime(df['created'], format='ISO8601', errors='coerce').dt.tz_convert('UTC')
        df['created_month'] = df['created_dt'].dt.tz_localize(None).dt.to_period('M')
        df['impact'] = df['CustomFields'].apply(lambda x: x.get('impact', 'Unknown'))
        df['impact'] = df['impact'].fillna('Unknown').replace('', 'Unknown')
        df['impact'] = df['impact'].apply(
            lambda x: x if x in ColorSchemes.IMPACT_ORDER else 'Unknown'
        )

        expected_months = self._get_expected_months()
        month_labels = [month.strftime('%b %Y') for month in expected_months]
        month_impact_counts = df.groupby(['created_month', 'impact']).size().reset_index(name='count')

        fig = self._create_monthly_impact_chart(
            expected_months, month_labels, month_impact_counts, tickets
        )

        self._finalize_and_save_chart(fig, "Inflow Past 12 Months - Impact Only.png")
        return time.time() - start_time

    def _get_yesterday_range(self) -> Tuple[str, str]:
        """Get yesterday's date range in UTC. On Mondays, includes both Saturday and Sunday."""
        now = datetime.now(self.eastern).replace(hour=0, minute=0, second=0, microsecond=0)

        # If today is Monday (weekday 0), include both Saturday and Sunday
        if now.weekday() == 0:
            # Saturday is 2 days ago, Sunday is 1 day ago
            period_start = now - timedelta(days=2)
            period_end = now  # End at Monday 00:00
        else:
            # Regular case: just yesterday
            period_start = now - timedelta(days=1)
            period_end = now

        return (period_start.astimezone(pytz.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                period_end.astimezone(pytz.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))

    def _get_expected_months(self) -> List[Any]:
        """Get list of expected months for the past 12 months."""
        current_month = pd.Period(datetime.now(), freq='M')
        return [current_month - i for i in range(11, -1, -1)]

    def _create_monthly_impact_chart(self, expected_months: List[Any], month_labels: List[str],
                                     month_impact_counts: pd.DataFrame, tickets: List[Dict[str, Any]]) -> plt.Figure:
        """Create monthly impact distribution chart."""
        fig, ax = plt.subplots(figsize=(20, 12), facecolor='#f8f9fa')
        fig.patch.set_facecolor('#f8f9fa')
        self.styler.apply_base_styling(fig, ax)

        # Create pivot data
        impact_pivot_data = {impact: np.zeros(len(expected_months)) for impact in ColorSchemes.IMPACT_ORDER}
        monthly_totals = np.zeros(len(expected_months))

        for _, row in month_impact_counts.iterrows():
            if row['created_month'] in expected_months:
                month_idx = expected_months.index(row['created_month'])
                impact_pivot_data[row['impact']][month_idx] += row['count']
                monthly_totals[month_idx] += row['count']

        # Plot bars
        x_pos = np.arange(len(month_labels))
        impact_bottom = np.zeros(len(expected_months))

        for impact in ColorSchemes.VISUAL_ORDER:
            values = impact_pivot_data[impact]
            if values.sum() > 0:
                ax.bar(x_pos, values, bottom=impact_bottom, width=0.4,
                       label=impact, color=ColorSchemes.IMPACT_COLORS[impact])
                impact_bottom += values

        # Add average line and trend
        monthly_average = monthly_totals.mean()
        ax.axhline(monthly_average, color='blue', linestyle='--', linewidth=2,
                   label=f'Monthly Average ({int(monthly_average)})')
        ax.plot(x_pos, monthly_totals, color='red', marker='o', markersize=8,
                linewidth=2.5, label='Monthly Volume', zorder=10)

        # Enhanced count labels with better styling
        for i, total in enumerate(monthly_totals):
            if total > 0:
                ax.text(x_pos[i], total + 20, f'{int(total)}',
                        ha='center', va='bottom', fontsize=12, fontweight='bold',
                        color='#1A237E',
                        bbox=dict(boxstyle="round,pad=0.3", facecolor='white', alpha=0.95,
                                  edgecolor='#1A237E', linewidth=1.5))

        # Configure axes with enhanced styling
        ax.set_xticks(x_pos)
        ax.set_ylim(0, impact_bottom.max() * 1.15)
        ax.set_xticklabels(month_labels, rotation=45, ha='right', fontsize=12, fontweight='bold')
        ax.tick_params(axis='y', colors=self.chart_config.border_color, labelsize=12, width=1.5)
        ax.tick_params(axis='x', colors=self.chart_config.border_color, labelsize=12, width=1.5, pad=10)

        # Enhanced titles and subtitle
        fig.suptitle('Impact Distribution Over the Past 12 Months',
                     fontweight='bold', fontsize=24, color=self.chart_config.border_color, y=0.95)
        ax.set_title(f"Total: {len(tickets)} tickets", fontsize=16,
                     color='#3F51B5', pad=20, fontweight='bold')
        ax.set_ylabel("Number of Tickets", fontweight='bold', fontsize=14,
                      color=self.chart_config.border_color, labelpad=15)

        # Enhanced legend with counts and better positioning
        handles, labels = ax.get_legend_handles_labels()
        impact_totals = {impact: impact_pivot_data[impact].sum() for impact in ColorSchemes.IMPACT_ORDER}
        custom_labels = []
        for label in labels:
            if label in ColorSchemes.IMPACT_ORDER:
                custom_labels.append(f"{label} ({int(impact_totals[label])})")
            else:
                custom_labels.append(label)

        legend = ax.legend(handles, custom_labels, title="Impact",
                           title_fontproperties={'weight': 'bold', 'size': 14},
                           loc='upper left', bbox_to_anchor=(1.01, 1), fontsize=11,
                           frameon=True, fancybox=True, shadow=True)
        legend.get_frame().set_facecolor('white')
        legend.get_frame().set_alpha(0.95)
        legend.get_frame().set_edgecolor(self.chart_config.border_color)
        legend.get_frame().set_linewidth(2)

        return fig

    def _finalize_and_save_chart(self, fig: plt.Figure, filename: str) -> None:
        """Apply final styling and save chart."""
        # Enhanced border with rounded corners
        from matplotlib.patches import FancyBboxPatch
        border_width = 2
        fig.patch.set_edgecolor('none')
        fig.patch.set_linewidth(0)

        fancy_box = FancyBboxPatch(
            (0, 0), width=1.0, height=1.0,
            boxstyle="round,pad=0,rounding_size=0.01",
            edgecolor='#1A237E',
            facecolor='none',
            linewidth=border_width,
            transform=fig.transFigure,
            zorder=1000,
            clip_on=False
        )
        fig.patches.append(fancy_box)

        self.styler.add_timestamp(fig)
        self.styler.add_watermark(fig)

        plt.tight_layout()
        plt.subplots_adjust(top=0.88, bottom=0.23, left=0.08, right=0.85)
        output_path = self.output_dir / filename
        plt.savefig(output_path, format='png', bbox_inches=None, pad_inches=0.0, dpi=300, facecolor='#f8f9fa')
        plt.close(fig)

    def generate_all_charts(self) -> None:
        """Generate all charts."""
        try:
            self.generate_yesterday_chart()
            self.generate_60_day_chart()
            self.generate_12_month_chart()
            print("All charts generated successfully")
        except Exception as e:
            print(f"Error generating charts: {e}")


def make_chart() -> None:
    """Main entry point for chart generation."""
    generator = TicketChartGenerator()
    generator.generate_all_charts()


if __name__ == '__main__':
    make_chart()
