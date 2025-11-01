import logging
from datetime import datetime, timedelta
from pathlib import Path

import pytz

import my_config as config
from services.xsoar import TicketHandler, XsoarEnvironment

config = config.get_config()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

eastern = pytz.timezone('US/Eastern')

root_directory = Path(__file__).parent.parent.parent


def get_details():
    try:
        # Get year-to-date tickets using explicit timestamps
        now = datetime.now(eastern)
        start_of_year = datetime(now.year, 1, 1, 0, 0, 0)
        start_of_year_eastern = eastern.localize(start_of_year)
        end_date = now.replace(hour=23, minute=59, second=59, microsecond=999999)

        # Convert to UTC for API query
        start_str = start_of_year_eastern.astimezone(pytz.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        end_str = end_date.astimezone(pytz.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

        query = f'-category:job reimagerequired:Yes created:>={start_str} created:<={end_str}'
        tickets = TicketHandler(XsoarEnvironment.PROD).get_tickets(query=query)
        result = []
        tuc_seconds_list = []
        for t in tickets:
            created = t.get("created")
            if created:
                try:
                    # Try to parse and format date
                    import pandas as pd
                    created = pd.to_datetime(created, errors='coerce')
                    if pd.notnull(created):
                        created = created.strftime('%m/%d/%Y')
                    else:
                        created = None
                except Exception:
                    pass
            hostname = None
            tuc = 'Unknown'
            custom_fields = t.get("CustomFields", {})
            if isinstance(custom_fields, dict):
                hostname = custom_fields.get("hostname")
                tuc_field = custom_fields.get("timeundercontainment")
                if isinstance(tuc_field, dict):
                    tuc_secs = tuc_field.get("totalDuration")
                    if tuc_secs:
                        try:
                            tuc_secs = int(tuc_secs)
                            if tuc_secs > 0:
                                tuc_seconds_list.append(tuc_secs)
                            days = tuc_secs // 86400
                            hours = (tuc_secs % 86400) // 3600
                            mins = (tuc_secs % 3600) // 60
                            tuc = f"{int(days)}d {int(hours)}h {int(mins)}m"
                        except Exception:
                            tuc = None
            result.append({
                "id": t.get("id"),
                "name": t.get("name"),
                "hostname": hostname,
                "created": created,
                "TUC": tuc,
                "count": custom_fields.get("reimagecount")
            })
        # Calculate mean TUC in seconds, then convert to d/h/m
        mtuc = None
        if tuc_seconds_list:
            mean_secs = int(sum(tuc_seconds_list) / len(tuc_seconds_list))
            days = mean_secs // 86400
            hours = (mean_secs % 86400) // 3600
            mins = (mean_secs % 3600) // 60
            mtuc = f"{int(days)}d {int(hours)}h {int(mins)}m"
        return {"tickets": result, "MTUC": mtuc}
    except Exception as e:
        logger.error(f"Error sending report: {e}")
        return {"error": str(e)}


def main():
    from tabulate import tabulate
    details = get_details()
    if "tickets" in details:
        print(tabulate(details["tickets"], headers="keys", tablefmt="grid"))
        print(f"MTUC: {details.get('MTUC')}")
    else:
        print(details)


if __name__ == "__main__":
    main()
