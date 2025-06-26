import multiprocessing
import os
import signal
import sys
import time

import pytz
import schedule

from config import get_config
from src import helper_methods
from src.charts import mttr_mttc, outflow, lifespan, heatmap, sla_breaches, aging_tickets, inflow, qradar_rule_efficacy, de_stories, days_since_incident, re_stories, threatcon_level, vectra_volume, \
    crowdstrike_volume, threat_tippers, crowdstrike_efficacy
from src.utils.fs_utils import make_dir_for_todays_charts

config = get_config()
eastern = pytz.timezone('US/Eastern')

# Create a PID file path in the project directory
PID_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scheduler.pid")


def scheduler_process():
    """
    Scheduler process that runs daily jobs and writes its PID to a file.
    """
    # Write PID to file so we can check if it's running
    with open(PID_FILE, 'w') as f:
        f.write(str(os.getpid()))

    print(f"Scheduler started with PID {os.getpid()}")
    print(f"PID file written to {PID_FILE}")

    # schedule
    print("Starting the scheduler...")

    schedule.every().day.at("00:01", eastern).do(lambda: (
        make_dir_for_todays_charts(helper_methods.CHARTS_DIR_PATH),
        aging_tickets.make_chart(),
        days_since_incident.make_chart(),
        crowdstrike_volume.make_chart(),
        crowdstrike_efficacy.make_chart(),
        vectra_volume.make_chart(),
        de_stories.make_chart(),
        heatmap.create_choropleth_map(),
        inflow.make_chart(),
        lifespan.make_chart(),
        mttr_mttc.make_chart(),
        outflow.make_chart(),
        re_stories.make_chart(),
        sla_breaches.make_chart(),
        threatcon_level.make_chart(),
        qradar_rule_efficacy.make_chart(),
        vectra_volume.make_chart(),
        crowdstrike_volume.make_chart(),
        threat_tippers.make_chart(),
        # crowdstrike.update_unique_hosts_from_cs()
    ))

    try:
        while True:
            schedule.run_pending()
            time.sleep(60)
    except KeyboardInterrupt:
        print("Scheduler shutting down...")
    finally:
        # Clean up PID file on exit
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)


def is_scheduler_running():
    """Check if the scheduler process is running by checking the PID file."""
    if not os.path.exists(PID_FILE):
        return False

    # Read the PID from file
    with open(PID_FILE, 'r') as f:
        try:
            pid = int(f.read().strip())
        except (ValueError, IOError):
            return False

    # Check if process with this PID exists
    try:
        # Sending signal 0 checks if process exists without affecting it
        os.kill(pid, 0)
        return True
    except OSError:
        # Process doesn't exist
        return False


def stop_scheduler():
    """Stop the scheduler process if it is running."""
    if not os.path.exists(PID_FILE):
        print("Scheduler is not running.")
        return

    with open(PID_FILE, 'r') as f:
        try:
            pid = int(f.read().strip())
        except (ValueError, IOError):
            print("Invalid PID file.")
            return

    try:
        os.kill(pid, signal.SIGTERM)
        print(f"Sent termination signal to scheduler process (PID: {pid})")
    except OSError:
        print("Failed to stop scheduler process - it may not be running.")

    # Clean up PID file
    if os.path.exists(PID_FILE):
        os.remove(PID_FILE)


def main():
    """Entry point for running the scheduler from the command line."""
    if len(sys.argv) > 1:
        if sys.argv[1] == 'stop':
            stop_scheduler()
            return
        elif sys.argv[1] == 'status':
            if is_scheduler_running():
                print("Scheduler is running.")
            else:
                print("Scheduler is not running.")
            return

    # Check if already running
    if is_scheduler_running():
        print("Scheduler is already running. Use 'stop' command to stop it first.")
        return

    # Start as a separate process
    process = multiprocessing.Process(target=scheduler_process)
    process.daemon = True  # This allows the process to continue running when script exits
    process.start()
    print(f"Started scheduler process with PID {process.pid}")

    # Keep the main process running to allow the daemon process to continue
    try:
        process.join()
    except KeyboardInterrupt:
        print("Exiting main process, scheduler will continue running in background.")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
