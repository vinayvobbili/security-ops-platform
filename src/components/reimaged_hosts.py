import logging
from pathlib import Path

import pytz

import config
from services.xsoar import TicketHandler

config = config.get_config()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

eastern = pytz.timezone('US/Eastern')

root_directory = Path(__file__).parent.parent.parent


def get_details():
    try:
        query = ' -category:job reimagerequired:Yes'
        period = {"byFrom": "ytd", "fromValue": 0}
        tickets = TicketHandler().get_tickets(query=query, period=period)
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
            tuc = 0
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
                "TUC": tuc
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
    print(get_details())


if __name__ == "__main__":
    main()
