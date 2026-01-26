"""
Tipper Novelty Analyzer

Analyzes new threat tippers against historical data to determine novelty
and provide actionable intelligence to threat hunters.

Usage:
    # Analyze a tipper by ID
    python -m src.components.tipper_analyzer 12345

    # Analyze raw threat text
    python -m src.components.tipper_analyzer --text "APT group using Cobalt Strike..."

Example programmatic usage:
    from src.components.tipper_analyzer import TipperAnalyzer

    analyzer = TipperAnalyzer()
    analysis = analyzer.analyze_tipper(tipper_id='12345')
    print(analyzer.format_analysis_for_display(analysis))
"""

# Re-export main classes and functions for backward compatibility
from .models import NoveltyAnalysis, ToolHuntResult, IOCHuntResult
from .analyzer import TipperAnalyzer
from .cli import analyze_from_cli, analyze_recent_tippers
from .formatters import (
    format_analysis_for_display,
    format_analysis_for_azdo,
    format_hunt_results_for_azdo,
)

__all__ = [
    # Main class
    'TipperAnalyzer',
    # Models
    'NoveltyAnalysis',
    'ToolHuntResult',
    'IOCHuntResult',
    # CLI functions
    'analyze_from_cli',
    'analyze_recent_tippers',
    # Formatters
    'format_analysis_for_display',
    'format_analysis_for_azdo',
    'format_hunt_results_for_azdo',
]
