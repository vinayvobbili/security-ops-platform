import schedule
import time
import pytz

import aging_tickets

# run once
# aging_tickets.send_report()

# schedule
schedule.every().day.at("08:00", pytz.timezone('US/Eastern')).do(aging_tickets.send_report)

while True:
    schedule.run_pending()
    time.sleep(60)
