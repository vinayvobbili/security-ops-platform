"""CVE → installed-software exposure correlator.

Given a list of CVE IDs from a CTI tipper, resolves each to affected
products via NVD, scans Tanium's Installed Applications sensor for
matching software, and emits per-asset exposure records with a
confirmed/potential confidence label.
"""

from src.components.cve_exposure.correlator import (
    correlate_cves,
    ExposureRecord,
    CorrelationResult,
)

__all__ = ["correlate_cves", "ExposureRecord", "CorrelationResult"]
