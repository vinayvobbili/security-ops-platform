"""
Cribl Edge Node Diagnostics

Reads the Cribl edge nodes CSV export, identifies disconnected nodes, pings them
to determine if the host is down or just the Cribl agent, and optionally enriches
with ServiceNow CMDB data to flag decommissioned hosts.

Usage:
    python -m src.components.cribl_edge_diagnostics [options]

    --input  / -i   Path to CSV (default: data/transient/cribl/Cribl edgeNodes.csv)
    --output / -o   Output Excel path (auto-generated if omitted)
    --enrich        Enrich with ServiceNow CMDB data (~2 min extra)
    --skip-ping     Skip ICMP pings (SNOW-only diagnosis)
    --fleet         Filter by fleet (e.g., "US_Windows")
    --limit         Process only N hosts (for testing)
"""
import argparse
import logging
import platform
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

import pandas as pd
from rich.progress import track

logger = logging.getLogger(__name__)

ROOT_DIR = Path(__file__).parent.parent.parent
DEFAULT_CSV = ROOT_DIR / "data" / "transient" / "cribl" / "edgenodes.csv"
DEFAULT_OUTPUT_DIR = ROOT_DIR / "data" / "transient" / "cribl"

MAX_WORKERS_PING = 100
MAX_WORKERS_SNOW = 30
PING_DOMAIN_SUFFIX = ".internal.local"

DECOMMISSIONED_STATUSES = {"retired", "decommissioned", "disposed"}


@dataclass
class DisconnectedNode:
    hostname: str
    guid: str
    fleet: str
    disconnected_at: str
    last_heartbeat: str
    days_disconnected: int
    edge_version: str
    # Ping
    ping_reachable: Optional[bool] = None
    ping_latency_ms: Optional[float] = None
    ping_target: str = ""
    # SNOW (only populated with --enrich)
    snow_status: str = ""
    snow_lifecycle_status: str = ""
    snow_environment: str = ""
    snow_ci_class: str = ""
    snow_os: str = ""
    snow_country: str = ""
    # Result
    diagnosis: str = ""


class CriblEdgeDiagnosticsProcessor:
    """Processes disconnected Cribl edge nodes and diagnoses root cause."""

    # ── Configuration — edit these for easy PyCharm runs ──────────
    CSV_PATH: Path = DEFAULT_CSV
    OUTPUT_PATH: Optional[Path] = None  # None = auto-generate
    ENRICH: bool = True  # ServiceNow CMDB enrichment
    SKIP_PING: bool = False  # Skip ICMP pings
    FLEET_FILTER: Optional[str] = None  # e.g., "US_Windows"
    LIMIT: Optional[int] = None  # e.g., 5 for testing

    # ─────────────────────────────────────────────────────────────

    def __init__(self):
        self.root_dir = ROOT_DIR

    # ── Step 1: Parse CSV ────────────────────────────────────────────

    @staticmethod
    def parse_csv(csv_path: Path, fleet_filter: Optional[str] = None,
                  limit: Optional[int] = None) -> tuple:
        """Returns (nodes, original_df) preserving input row and column order.

        The CSV is a connection history log — a host can appear multiple times
        (each connect/disconnect cycle is a separate row).  We deduplicate by
        keeping only the **most recent row** per host (highest 'Connected at'
        epoch).  If that row is 'Connected', the host is currently online and
        is excluded.  Only hosts whose latest row is 'Disconnected' are
        diagnosed.
        """
        logger.info(f"Reading CSV: {csv_path}")
        df = pd.read_csv(csv_path)
        logger.info(f"Total rows in CSV: {len(df)}")

        # Deduplicate: keep only the most recent row per host
        df = df.sort_values("Connected at", ascending=False)
        df = df.drop_duplicates(subset="Host", keep="first")
        total_unique_hosts = len(df)
        logger.info(f"Unique hosts after dedup: {total_unique_hosts}")

        # Now filter to disconnected only (hosts whose *latest* state is Disconnected)
        connected_count = (df["Connection"] == "Connected").sum()
        df = df[df["Connection"] == "Disconnected"].copy()
        logger.info(f"Currently connected (excluded): {connected_count}")
        logger.info(f"Truly disconnected hosts: {len(df)}")

        if fleet_filter:
            df = df[df["Fleet"].str.contains(fleet_filter, case=False, na=False)]
            logger.info(f"After fleet filter '{fleet_filter}': {len(df)}")

        # Preserve original columns before adding computed ones
        original_columns = df.columns.tolist()

        # Convert epoch-ms timestamps
        now = datetime.now(timezone.utc)

        def epoch_ms_to_str(val):
            try:
                return datetime.fromtimestamp(int(val) / 1000, tz=timezone.utc).strftime(
                    "%Y-%m-%d %H:%M:%S UTC"
                )
            except (ValueError, TypeError, OSError):
                return ""

        df["disconnected_at_str"] = df["Disconnected at"].apply(epoch_ms_to_str)
        df["last_heartbeat_str"] = df["Last Heartbeat"].apply(epoch_ms_to_str)

        # Calculate days disconnected from the Disconnected at epoch
        def calc_days(val):
            try:
                dt = datetime.fromtimestamp(int(val) / 1000, tz=timezone.utc)
                return (now - dt).days
            except (ValueError, TypeError, OSError):
                return 0

        df["days_disconnected"] = df["Disconnected at"].apply(calc_days)

        if limit and limit > 0:
            df = df.head(limit)
            logger.info(f"Test mode: limiting to {limit} hosts")

        nodes = []
        for _, row in df.iterrows():
            nodes.append(DisconnectedNode(
                hostname=str(row.get("Host", "")).strip(),
                guid=str(row.get("GUID", "")),
                fleet=str(row.get("Fleet", "")),
                disconnected_at=row.get("disconnected_at_str", ""),
                last_heartbeat=row.get("last_heartbeat_str", ""),
                days_disconnected=int(row.get("days_disconnected", 0)),
                edge_version=str(row.get("Edge Version", "")),
            ))

        logger.info(f"Parsed {len(nodes)} disconnected nodes (1 row per host)")
        return nodes, df[original_columns].reset_index(drop=True), total_unique_hosts

    # ── Step 2: Ping hosts ───────────────────────────────────────────

    @staticmethod
    def ping_hosts(nodes: List[DisconnectedNode]) -> List[DisconnectedNode]:
        logger.info(f"Pinging {len(nodes)} hosts (max_workers={MAX_WORKERS_PING})...")

        is_mac = platform.system() == "Darwin"
        timeout_flag = "-t" if is_mac else "-W"

        def ping_one(node: DisconnectedNode) -> DisconnectedNode:
            node.ping_target = node.hostname if node.hostname.endswith(PING_DOMAIN_SUFFIX) else node.hostname + PING_DOMAIN_SUFFIX
            try:
                result = subprocess.run(
                    ["ping", "-c", "1", timeout_flag, "2", node.ping_target],
                    capture_output=True, text=True, timeout=5,
                )
                if result.returncode == 0:
                    node.ping_reachable = True
                    # Try to extract latency from output
                    for line in result.stdout.splitlines():
                        if "time=" in line:
                            try:
                                ms = float(line.split("time=")[1].split()[0].rstrip("ms"))
                                node.ping_latency_ms = ms
                            except (ValueError, IndexError):
                                pass
                            break
                else:
                    node.ping_reachable = False
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                node.ping_reachable = False
            return node

        # Deduplicate: only ping each unique hostname once
        unique_hostnames = {}
        for node in nodes:
            if node.hostname not in unique_hostnames:
                unique_hostnames[node.hostname] = node

        unique_nodes = list(unique_hostnames.values())
        logger.info(f"Unique hostnames to ping: {len(unique_nodes)} (out of {len(nodes)} total rows)")

        with ThreadPoolExecutor(max_workers=MAX_WORKERS_PING) as executor:
            futures = {executor.submit(ping_one, n): n for n in unique_nodes}
            for future in track(as_completed(futures), total=len(futures),
                                description="Pinging hosts"):
                future.result()

        # Apply ping results to all nodes with the same hostname
        ping_results = {n.hostname: (n.ping_reachable, n.ping_latency_ms, n.ping_target) for n in unique_nodes}
        for node in nodes:
            reachable, latency, target = ping_results[node.hostname]
            node.ping_reachable = reachable
            node.ping_latency_ms = latency
            node.ping_target = target

        reachable = sum(1 for n in unique_nodes if n.ping_reachable)
        logger.info(f"Ping complete: {reachable} reachable, {len(unique_nodes) - reachable} unreachable")
        return nodes

    # ── Step 3: SNOW enrichment ──────────────────────────────────────

    @staticmethod
    def enrich_with_servicenow(nodes: List[DisconnectedNode]) -> List[DisconnectedNode]:
        logger.info(f"Enriching {len(nodes)} hosts with ServiceNow CMDB data...")

        from services.service_now import ServiceNowClient
        snow_client = ServiceNowClient(requests_per_second=30)

        def enrich_one(node: DisconnectedNode) -> DisconnectedNode:
            try:
                details = snow_client.get_host_details(node.hostname)
                if details.get("status") == "Not Found":
                    node.snow_status = "Not Found"
                elif details.get("status") == "ServiceNow API Error":
                    node.snow_status = f"Error: {details.get('error', 'Unknown')}"
                else:
                    node.snow_status = "Found"
                    node.snow_lifecycle_status = details.get("lifecycleStatus", "")
                    node.snow_environment = details.get("environment", "")
                    node.snow_ci_class = details.get("ciClass", "")
                    node.snow_os = details.get("operatingSystem", "")
                    node.snow_country = details.get("country", "")
            except Exception as e:
                node.snow_status = f"Error: {e}"
                logger.warning(f"Error enriching {node.hostname} with SNOW: {e}")
            return node

        # Deduplicate: only query SNOW once per unique hostname
        unique_hostnames = {}
        for node in nodes:
            if node.hostname not in unique_hostnames:
                unique_hostnames[node.hostname] = node

        unique_nodes = list(unique_hostnames.values())
        logger.info(f"Unique hostnames to enrich: {len(unique_nodes)} (out of {len(nodes)} total rows)")

        with ThreadPoolExecutor(max_workers=MAX_WORKERS_SNOW) as executor:
            futures = {executor.submit(enrich_one, n): n for n in unique_nodes}
            for future in track(as_completed(futures), total=len(futures),
                                description="Enriching with ServiceNow"):
                future.result()

        # Apply SNOW results to all nodes with the same hostname
        snow_results = {
            n.hostname: (n.snow_status, n.snow_lifecycle_status, n.snow_environment,
                         n.snow_ci_class, n.snow_os, n.snow_country)
            for n in unique_nodes
        }
        for node in nodes:
            status, lifecycle, env, ci_class, os_val, country = snow_results[node.hostname]
            node.snow_status = status
            node.snow_lifecycle_status = lifecycle
            node.snow_environment = env
            node.snow_ci_class = ci_class
            node.snow_os = os_val
            node.snow_country = country

        found = sum(1 for n in unique_nodes if n.snow_status == "Found")
        logger.info(f"ServiceNow enrichment complete: {found} found out of {len(unique_nodes)}")
        return nodes

    # ── Step 4: Diagnose ─────────────────────────────────────────────

    @staticmethod
    def diagnose(nodes: List[DisconnectedNode]) -> List[DisconnectedNode]:
        for node in nodes:
            lifecycle = node.snow_lifecycle_status.lower().strip()
            if lifecycle in DECOMMISSIONED_STATUSES:
                node.diagnosis = "Decommissioned"
            elif node.ping_reachable:
                node.diagnosis = "Agent Down (Host Reachable)"
            elif node.ping_reachable is False:
                node.diagnosis = "Host Down"
            else:
                node.diagnosis = "Unknown"
        return nodes

    # ── Step 5: Export to Excel ──────────────────────────────────────

    @staticmethod
    def export_to_excel(nodes: List[DisconnectedNode],
                        original_df: pd.DataFrame,
                        output_path: Optional[Path] = None,
                        include_ping: bool = True,
                        include_snow: bool = False) -> str:
        if output_path is None:
            today = datetime.now().strftime("%m-%d-%Y")
            output_dir = DEFAULT_OUTPUT_DIR / today
            output_dir.mkdir(parents=True, exist_ok=True)
            output_path = output_dir / "Cribl_Edge_Diagnostics.xlsx"
        else:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)

        # Start with original CSV data (preserves input column order and row order)
        df = original_df.copy()

        # Append enrichment columns
        df["Days Disconnected"] = [n.days_disconnected for n in nodes]
        df["Diagnosis"] = [n.diagnosis for n in nodes]

        if include_ping:
            df["Ping Target"] = [n.ping_target or "" for n in nodes]
            df["Ping Reachable"] = [
                ("Yes" if n.ping_reachable else "No") if n.ping_reachable is not None else ""
                for n in nodes
            ]
            df["Ping Latency (ms)"] = [n.ping_latency_ms if n.ping_latency_ms else "" for n in nodes]

        if include_snow:
            df["SNOW Status"] = [n.snow_status for n in nodes]
            df["SNOW Lifecycle"] = [n.snow_lifecycle_status for n in nodes]
            df["SNOW Environment"] = [n.snow_environment for n in nodes]
            df["SNOW CI Class"] = [n.snow_ci_class for n in nodes]
            df["SNOW OS"] = [n.snow_os for n in nodes]
            df["SNOW Country"] = [n.snow_country for n in nodes]

        df.to_excel(output_path, index=False, engine="openpyxl")

        # Apply professional formatting
        from src.utils.excel_formatting import apply_professional_formatting

        column_widths = {
            "days disconnected": 18,
            "diagnosis": 28,
            "ping target": 40,
            "ping reachable": 14,
            "ping latency (ms)": 16,
            "snow status": 14,
            "snow lifecycle": 16,
            "snow environment": 16,
            "snow ci class": 14,
            "snow os": 20,
            "snow country": 14,
        }
        apply_professional_formatting(output_path, column_widths=column_widths)

        logger.info(f"Exported {len(nodes)} nodes to {output_path}")
        return str(output_path)

    # ── Pipeline ─────────────────────────────────────────────────────

    def process(self) -> str:
        csv_path = self.CSV_PATH
        output_path = self.OUTPUT_PATH
        enrich = self.ENRICH
        skip_ping = self.SKIP_PING
        fleet_filter = self.FLEET_FILTER
        limit = self.LIMIT

        # Step 1: Parse CSV
        nodes, original_df, total_hosts = self.parse_csv(csv_path, fleet_filter=fleet_filter, limit=limit)
        if not nodes:
            print("No disconnected nodes found.")
            return ""

        # Step 2: Ping
        if not skip_ping:
            nodes = self.ping_hosts(nodes)

        # Step 3: SNOW enrichment (optional)
        if enrich:
            nodes = self.enrich_with_servicenow(nodes)

        # Step 4: Diagnose
        nodes = self.diagnose(nodes)

        # Step 5: Export
        report_path = self.export_to_excel(
            nodes, original_df, output_path=output_path,
            include_ping=not skip_ping, include_snow=enrich,
        )

        # Console summary
        agent_down = sum(1 for n in nodes if n.diagnosis == "Agent Down (Host Reachable)")
        host_down = sum(1 for n in nodes if n.diagnosis == "Host Down")
        decommissioned = sum(1 for n in nodes if n.diagnosis == "Decommissioned")
        unknown = sum(1 for n in nodes if n.diagnosis == "Unknown")

        print()
        print("=" * 50)
        print(" CRIBL EDGE NODE DIAGNOSTICS")
        print("=" * 50)
        print(f"  Total unique hosts:      {total_hosts:,}")
        print(f"  Currently connected:     {total_hosts - len(nodes):,}")
        print(f"  Truly disconnected:      {len(nodes):,}")
        print(f"  ── Breakdown ──")
        print(f"  Agent Down (Reachable):  {agent_down:,}")
        print(f"  Host Down:               {host_down:,}")
        if enrich:
            print(f"  Decommissioned (SNOW):   {decommissioned:,}")
        if unknown:
            print(f"  Unknown:                 {unknown:,}")
        print(f"  Report: {report_path}")
        print("=" * 50)

        return report_path


def main():
    parser = argparse.ArgumentParser(
        description="Cribl Edge Node Diagnostics — diagnose disconnected edge nodes"
    )
    parser.add_argument("-i", "--input", type=str, default=None,
                        help="Path to Cribl edge nodes CSV export")
    parser.add_argument("-o", "--output", type=str, default=None,
                        help="Output Excel path (auto-generated if omitted)")
    parser.add_argument("--enrich", action="store_true",
                        help="Enrich with ServiceNow CMDB data")
    parser.add_argument("--skip-ping", action="store_true",
                        help="Skip ICMP pings")
    parser.add_argument("--fleet", type=str, default=None,
                        help="Filter by fleet (e.g., 'US_Windows')")
    parser.add_argument("--limit", type=int, default=None,
                        help="Process only N hosts (for testing)")

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    processor = CriblEdgeDiagnosticsProcessor()

    # CLI args override class-level defaults
    if args.input:
        processor.CSV_PATH = Path(args.input)
    if args.output:
        processor.OUTPUT_PATH = Path(args.output)
    if args.enrich:
        processor.ENRICH = True
    if args.skip_ping:
        processor.SKIP_PING = True
    if args.fleet:
        processor.FLEET_FILTER = args.fleet
    if args.limit:
        processor.LIMIT = args.limit

    processor.process()


if __name__ == "__main__":
    main()
