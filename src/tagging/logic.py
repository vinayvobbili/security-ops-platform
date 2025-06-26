from typing import List
from openpyxl import Workbook
from collections import defaultdict
from datetime import datetime
from pathlib import Path

def process_workstations(workstations, ring_percents, get_region_from_country, append_status):
    region_country_groups = defaultdict(list)
    for ws in workstations:
        region = getattr(ws, "region")
        country = getattr(ws, "country")
        if region == "Unknown Region":
            region = get_region_from_country(country)
            if not region:
                append_status(ws, "Skipping tag generation due to unknown region")
                continue
            append_status(ws, f"Using derived region '{region}' for tagging")
        region_country_key = (region, country)
        region_country_groups[region_country_key].append(ws)
    for (region, country), ws_group in region_country_groups.items():
        total = len(ws_group)
        if total == 0:
            continue
        ring_1_size = max(1, int(ring_percents[0] * total)) if total >= 10 else 0
        ring_2_size = max(1, int(ring_percents[1] * total)) if total >= 5 else 0
        ring_3_size = max(1, int(ring_percents[2] * total)) if total >= 3 else 0
        ring_4_size = total - ring_1_size - ring_2_size - ring_3_size
        ring_sizes = [ring_1_size, ring_2_size, ring_3_size, ring_4_size]
        ws_group.sort(key=lambda c: (c.eidLastSeen is None, c.eidLastSeen))
        current_index = 0
        for ring, size in enumerate(ring_sizes, start=1):
            if size <= 0:
                continue
            for i in range(size):
                if current_index < len(ws_group):
                    setattr(ws_group[current_index], "new_tag", f"{region}WksRing{ring}")
                    current_index += 1

def process_servers(servers, env_map, get_env, append_status):
    for server in servers:
        env = get_env(getattr(server, "environment"))
        if env in env_map[1]:
            ring = 1
        elif env in env_map[2]:
            ring = 2
        elif env in env_map[3]:
            ring = 3
        else:
            ring = 4
        region = getattr(server, "region")
        setattr(server, "new_tag", f"{region}SRVRing{ring}")

