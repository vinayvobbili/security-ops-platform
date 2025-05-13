from datetime import datetime, timedelta
from pathlib import Path

import pandas

ROOT_DIRECTORY = Path(__file__).parent.parent.parent
today_date = datetime.now().strftime('%m-%d-%Y')
yesterday_date = (datetime.now() - timedelta(days=1)).strftime('%m-%d-%Y')

hosts_today_without_ring_tag = pandas.read_excel(ROOT_DIRECTORY / "data" / "transient" / "epp_device_tagging" / today_date / "unique_hosts_without_ring_tag.xlsx")['hostname'].tolist()
hosts_yesterday_without_ring_tag = pandas.read_excel(ROOT_DIRECTORY / "data" / "transient" / "epp_device_tagging" / yesterday_date / "unique_hosts_without_ring_tag.xlsx")['hostname'].tolist()

hosts_losing_ring_tag = set(hosts_today_without_ring_tag) - set(hosts_yesterday_without_ring_tag)

print(f"Hosts that lost their ring tag overnight: {hosts_losing_ring_tag}")
print(f"Total hosts that lost their ring tag overnight: {len(hosts_losing_ring_tag)}")