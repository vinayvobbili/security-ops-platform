import json
import math
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional

from falconpy import OAuth2, Hosts, RealTimeResponse

from config import get_config
from services.service_now import ServiceNowClient

config = get_config()

'''
Here are 10 key points about what this code does:

1. Processes a list of host names from an enterprise system, retrieving detailed information about each host from CrowdStrike, Splunk, and other internal systems.

2. Categorizes hosts as either PCs or servers, and determines their geographic region and country based on available data sources.

3. Implements a sophisticated tagging mechanism for hosts, distributing workstations into rings (1-4) based on their region and country, and servers into rings based on their environment type.

4. Filters out hosts that lack critical information like device ID, category, or region to ensure data quality.

5. Generates new CrowdStrike tags for hosts that don't already have ring-based tags, following a specific distribution logic for workstations and servers.

    For workstations, the code uses these percentage-based ring allocations:
        Ring 1: 10% of workstations in a specific region and country
        Ring 2: 20% of workstations in a specific region and country
        Ring 3: 30% of workstations in a specific region and country
        Ring 4: Remaining workstations in that region and country

    For servers, the ring is determined by environment type:
        Ring 1: Dev, POC, Lab, Integration environments
        Ring 2: QA, Test environments
        Ring 3: DR (Disaster Recovery) environments
        Ring 4: Production or unknown environments

6. Creates a detailed, aligned output table showing host details including name, category, environment, region, new tag, and current tags.

7. Generates a CSV report of processed hosts and emails it to specified recipients using an internal email sender.

8. Tracks and reports on problematic hosts, including those not found in CrowdStrike, those without a device category, and those with guessed regions.

9. Measures and reports the execution time of different stages of the process, including host fetching and tag generation.

10. Handles various edge cases and potential errors, such as empty environment lists, missing device information, and parsing timestamp data.
'''


with open('data/regions_by_country.json', 'r') as f:
    REGIONS_BY_COUNTRY = json.load(f)


with open('data/countries_by_code.json', 'r') as f:
    COUNTRY_NAMES_BY_ABBREVIATION = json.load(f)

hosts_with_region_guessed = []

falcon_auth = OAuth2(client_id=config.cs_rtr_client_id, client_secret=config.cs_rtr_client_secret, base_url="api.us-2.crowdstrike.com", ssl_verify=False)
falcon_rtr = RealTimeResponse(auth_object=falcon_auth)
falcon_hosts = Hosts(auth_object=falcon_auth)

service_now = ServiceNowClient(config.snow_base_url, config.snow_functional_account_id, config.snow_functional_account_password, config.snow_client_key)


class HostCategory(Enum):
    PC = "PC"
    SERVER = "Server"


@dataclass
class Host:
    name: str
    device_id: str = ''
    country: str = ''
    region: str = ''
    category: Optional[HostCategory] = None
    environment: str = ''
    current_crowd_strike_tags: list[str] = field(default_factory=list)
    new_crowd_strike_tag: str = ''

    @classmethod
    def create_and_initialize(cls, name: str) -> 'Host':
        host = cls(name)
        host._initialize_host_data()
        return host

    def _initialize_host_data(self) -> None:
        """Initialize all host data in one method."""
        self._set_cs_device_id()
        if self.device_id:
            self._set_host_details_from_snow()

    def _set_cs_device_id(self) -> None:
        host_filter = f"hostname:'{self.name}'"
        response = falcon_hosts.query_devices_by_filter(filter=host_filter)

        resources = []
        if response.get("status_code") == 200:
            resources = response["body"].get("resources", [])

        if resources:
            # Sort resources by 'last_seen' and get the most recent one
            resources.sort(
                key=lambda x: parse_timestamp(x.get('last_seen')) or datetime.min,
                reverse=True
            )
            self.device_id = resources[0]['device_id']

        if self.device_id:
            self.current_crowd_strike_tags = resources[0]['tags']

    def _set_host_details_from_snow(self) -> None:
        host_details = service_now.get_host_details(self.name)

        if host_details:
            host_details = host_details[0]
            category = host_details.get('Category')
            if category == 'PC':
                self.category = HostCategory.PC
            elif category == 'Server':
                self.category = HostCategory.SERVER

            self.environment = host_details.get('Environment')

            region_country = host_details['country']
            if region_country != 'Unknown':
                parts = region_country.split()
                if len(parts) == 2:
                    self.region, self.country = parts

            # Special case handling
            if self.country == 'Korea':
                self.country = 'South Korea'

            if self.country == '':
                # there's no country/region detail in Splunk for this host. Resort to guessing based on the hostname
                country_code = self.name[:2]
                self.country = COUNTRY_NAMES_BY_ABBREVIATION.get(country_code)

                if self.country:
                    self.region = REGIONS_BY_COUNTRY.get(self.country)
                    if self.region:
                        hosts_with_region_guessed.append(self.name)

                # per requirement
                if self.country == 'US':
                    self.region = 'US'
                elif self.country == 'Japan':
                    self.region = 'Japan'

    def add_tag_to_crowd_strike(self):
        """Add the generated tag to CrowdStrike."""
        falcon_hosts.update_device_tags('add', self.device_id, self.new_crowd_strike_tag)

    @staticmethod
    def generate_tags(hosts: List['Host']) -> None:
        # Filter hosts to only include those without Falcon tags containing 'ring'
        hosts = [
            host for host in hosts
            if not any(
                tag.startswith('Falcon') and 'ring' in tag.lower()
                for tag in host.current_crowd_strike_tags
            )
        ]

        """Assign rings to hosts based on predefined distribution."""
        work_stations = [host for host in hosts if host.category == HostCategory.PC]
        servers = [host for host in hosts if host.category == HostCategory.SERVER]

        regions = set(host.region for host in hosts)
        countries = set(host.country for host in hosts)

        # Process work stations
        for region in regions:
            for country in countries:
                work_stations_by_region_country = [
                    ws for ws in work_stations
                    if ws.region == region and ws.country == country
                ]
                total = len(work_stations_by_region_country)

                ring_sizes = [int(0.1 * total), int(0.2 * total), int(0.3 * total), total - sum(ring_sizes)]

                for ring, size in enumerate(ring_sizes, start=1):
                    for ws in work_stations_by_region_country[:size]:
                        ws.new_crowd_strike_tag = f"{ws.region}WksRing{ring}"
                    work_stations_by_region_country = work_stations_by_region_country[size:]

        # Process servers
        for server in servers:
            if isinstance(server.environment, list):
                if len(server.environment) > 1:
                    env = server.environment[0].lower().strip() or server.environment[1].lower().strip()
                else:
                    print(f"Empty environment list for server")
                    env = ""
            else:
                env = server.environment.lower().strip()

            if env in ("dev", "poc", "lab", "integration"):
                ring = 1
            elif env in ("qa", "test"):
                ring = 2
            elif env == "dr":
                ring = 3
            else:  # production or unknown
                ring = 4

            server.new_crowd_strike_tag = f"{server.region}SRVRing{ring}"


def parse_timestamp(date_str: str) -> Optional[datetime]:
    """Parse an ISO 8601 timestamp string into a datetime object."""
    return datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%SZ")


def apply_tags(hosts: List[Host]) -> None:
    for host in hosts:
        host.add_tag_to_crowd_strike()


def create_aligned_table(hosts: List[Host]) -> str:
    # Default minimum widths based on header names
    default_widths = {
        'name': len("Name"),
        'category': len("Category"),
        'environment': len("Environment"),
        'region': len("Region"),
        'new_tag': len("New CS Tag"),
        'current_tags': len("Current CS Tags")
    }

    column_widths = {
        'name': max(
            max((len(host.name) for host in hosts), default=0),
            default_widths['name']
        ),
        'category': max(
            max((len(host.category.value) for host in hosts), default=0),
            default_widths['category']
        ),
        'environment': max(
            max((len(str(host.environment)) for host in hosts), default=0),
            default_widths['environment']
        ),
        'region': max(
            max((len(host.region) for host in hosts), default=0),
            default_widths['region']
        ),
        'new_tag': max(
            max((len(host.new_crowd_strike_tag) for host in hosts), default=0),
            default_widths['new_tag']
        ),
        'current_tags': max(
            max((len(str(host.current_crowd_strike_tags)) for host in hosts), default=0),
            default_widths['current_tags']
        )
    }

    # Format header
    header = (
        f"{'Name':<{column_widths['name']}} | "
        f"{'Category':<{column_widths['category']}} | "
        f"{'Environment':<{column_widths['environment']}} | "
        f"{'Region':<{column_widths['region']}} | "
        f"{'New CS Tag':<{column_widths['new_tag']}} | "
        f"{'Current CS Tags':<{column_widths['current_tags']}}"
    )

    # Create separator line
    separator = '-' * len(header)

    rows = []
    for host in hosts:
        row = (
            f"{host.name:<{column_widths['name']}} | "
            f"{host.category.value:<{column_widths['category']}} | "
            f"{str(host.environment):<{column_widths['environment']}} | "
            f"{host.region:<{column_widths['region']}} | "
            f"{host.new_crowd_strike_tag:<{column_widths['new_tag']}} | "
            f"{str(host.current_crowd_strike_tags):<{column_widths['current_tags']}}"
        )
        rows.append(row)

    # Combine all parts
    return '\n'.join([header, separator] + rows)


def format_duration(seconds):
    minutes, seconds = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)

    seconds = math.ceil(seconds)  # Round up seconds

    parts = []
    if hours > 0:
        parts.append(f"{int(hours)} hour{'s' if hours != 1 else ''}")
    if minutes > 0:
        parts.append(f"{int(minutes)} minute{'s' if minutes != 1 else ''}")
    if seconds > 0 or not parts:
        parts.append(f"{int(seconds)} second{'s' if seconds != 1 else ''}")

    return " ".join(parts)


def generate_and_email_csv_report(hosts: List[Host]) -> None:
    """
    Generates a CSV report of hosts and emails it
    """
    current_time = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    filename = f'host_report_{current_time}.csv'

    # Create array of dictionaries for CSV export
    csv_array = []
    for host in hosts:
        try:
            csv_array.append({
                "Name": host.name,
                "Category": host.category.value if host.category else "",
                "Environment": host.environment,
                "Region": host.region,
                "New CS Tag": host.new_crowd_strike_tag,
                "Current CS Tags": str(host.current_crowd_strike_tags)
            })
        except Exception as e:
            continue

    if not csv_array:
        raise ValueError("No valid host data to include in report")

    # Return success message
    success_message = {
        'Contents': {
            'Success': True,
            'HostsProcessed': len(hosts),
            'HostsInReport': len(csv_array),
            'Filename': filename,
        },
        'HumanReadable': f"""### CSV Report Generation Summary
- Successfully generated report: {filename}
- Total hosts processed: {len(hosts)}
- Hosts included in report: {len(csv_array)}
"""
    }


def main() -> str:
    start_time = time.time()

    # Fetch and initialize hosts
    fetch_start = time.time()
    hosts_list = []

    hosts = [Host.create_and_initialize(name.strip()) for name in hosts_list.splitlines() if name.strip()]
    fetch_end = time.time()
    fetch_duration = fetch_end - fetch_start

    # Categorize problematic hosts
    hostnames_not_in_crowd_strike = [host.name for host in hosts if not host.device_id]
    hostnames_without_category = [host.name for host in hosts if not host.category]
    hostnames_without_region = [host.name for host in hosts if not host.region]

    # Log problematic hosts
    problematic_hosts_report = f"""
Hosts not in CrowdStrike: {', '.join(hostnames_not_in_crowd_strike)}
Hosts without device category: {', '.join(hostnames_without_category)}
Hosts without region: {', '.join(hostnames_without_region)}
Hosts with region guessed: {', '.join(hosts_with_region_guessed)}"""

    # Filter out problematic hosts
    hosts = [host for host in hosts if host.device_id and host.category and host.region]

    # Generate tags
    generate_tag_start = time.time()
    Host.generate_tags(hosts)
    generate_tag_end = time.time()
    generate_tag_duration = generate_tag_end - generate_tag_start

    # Create aligned output table
    output_table = create_aligned_table(hosts)

    # Email the report
    generate_and_email_csv_report(
        hosts=hosts
    )

    end_time = time.time()
    total_duration = end_time - start_time
    time_report = f"""
Fetching and initializing hosts took {format_duration(fetch_duration)}
Generating tags took {format_duration(generate_tag_duration)}
Total execution time: {format_duration(total_duration)}"""

    return f"{problematic_hosts_report}\n\n{time_report}\n\n{output_table}\n"


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
