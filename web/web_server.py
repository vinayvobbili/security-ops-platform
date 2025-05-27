import ipaddress
import os
from datetime import date
from datetime import datetime
from typing import List

import pytz
from flask import Flask, request, abort
from flask import jsonify
from flask import render_template

from config import get_config
from services import xsoar
from services.xsoar import ListHandler, TicketHandler
from src.helper_methods import log_web_activity

app = Flask(__name__, static_folder='static', static_url_path='/static', template_folder='templates')
eastern = pytz.timezone('US/Eastern')
CONFIG = get_config()

# Supported image extensions
IMAGE_EXTENSIONS = (".jpg", ".jpeg", ".png", ".gif", ".svg")
blocked_ip_ranges = []  # ["10.49.70.0/24", "10.50.70.0/24"]

list_handler = ListHandler()
incident_handler = TicketHandler()


@app.before_request
def block_ip():
    if any(ipaddress.ip_network(request.remote_addr).subnet_of(ipaddress.ip_network(blocked_ip_range)) for blocked_ip_range in blocked_ip_ranges):
        abort(403)  # Forbidden


def get_image_files() -> List[str]:
    """Retrieves a list of image files from the static and charts directories."""
    today_date = datetime.now().strftime('%m-%d-%Y')
    IMAGE_ORDER = [
        "images/Company Logo.png",
        "images/DnR Welcome.png",
        f"charts/{today_date}/Threatcon Level.png",
        f"charts/{today_date}/Days Since Last Incident.png",
        "images/DnR Metrics by Peanuts.jpg",
        f"charts/{today_date}/Aging Tickets.png",
        f"charts/{today_date}/Inflow Yesterday.png",
        f"charts/{today_date}/Inflow Past 60 Days.png",
        f"charts/{today_date}/Inflow Past 12 Months - Impact Only.png",
        f"charts/{today_date}/Inflow Past 12 Months - Ticket Type Only.png",
        f"charts/{today_date}/Inflow Past 12 Months.png",
        f"charts/{today_date}/Outflow.png",
        f"charts/{today_date}/SLA Breaches.png",
        f"charts/{today_date}/MTTR MTTC.png",
        f"charts/{today_date}/Heat Map.png",
        f"charts/{today_date}/CrowdStrike Detection Efficacy-Quarter.png",
        f"charts/{today_date}/CrowdStrike Detection Efficacy-Month.png",
        f"charts/{today_date}/CrowdStrike Detection Efficacy-Week.png",
        f"charts/{today_date}/QR Rule Efficacy-Quarter.png",
        f"charts/{today_date}/QR Rule Efficacy-Month.png",
        f"charts/{today_date}/QR Rule Efficacy-Week.png",
        f"charts/{today_date}/Vectra Volume.png",
        f"charts/{today_date}/CrowdStrike Volume.png",
        f"charts/{today_date}/Lifespan.png",
        "images/Threat Hunting Intro.png",
        f"charts/{today_date}/Threat Tippers.png",
        f"charts/{today_date}/DE Stories.png",
        f"charts/{today_date}/RE Stories.png",
        "images/End of presentation.jpg",
        "images/Feedback Email.png",
        "images/Thanks.png"
    ]
    image_files = []
    # fetch files per that image order
    for image_path in IMAGE_ORDER:
        full_path = os.path.join(app.static_folder, image_path)
        if os.path.exists(full_path):
            image_files.append(image_path)
        else:
            full_path = os.path.join(app.config['CHARTS_DIR'], image_path.split('/')[-1])
            if os.path.exists(full_path):
                image_files.append(image_path)
            else:
                print(f"File not found: {full_path}")

    return image_files


@app.route("/")
@log_web_activity
def get_ir_dashboard_slide_show():
    """Renders the HTML template with the ordered list of image files."""
    image_files = get_image_files()
    return render_template("slide-show.html", image_files=image_files)


@app.route("/msoc-form")
@log_web_activity
def display_msoc_form():
    """Displays the MSOC form."""
    return render_template("msoc_form.html")


@app.route("/submit-msoc-form", methods=['POST'])
@log_web_activity
def handle_msoc_form_submission():
    """Handles MSOC form submissions and processes the data."""
    form = request.form.to_dict()
    form['type'] = 'MSOC Site Security Device Management'
    response = incident_handler.create_in_dev(form)
    # Return a JSON response
    return jsonify({
        'status': 'success',
        'new_incident_id': response['id'],
        'new_incident_link': f"{CONFIG.xsoar_dev_ui_base_url}/Custom/caseinfoid/{response['id']}"
    })


@app.route("/speak-up-form")
@log_web_activity
def display_speak_up_form():
    """Displays the Speak Up form."""
    return render_template("speak_up_form.html")


@log_web_activity
@app.route("/submit-speak-up-form", methods=['POST'])
def handle_speak_up_form_submission():
    """Handles the Speak Up form submissions and processes the data."""
    form = request.form.to_dict()

    # Format the date from yyyy-mm-dd to mm/dd/yyyy
    date_occurred = form.get('dateOccurred', '')
    if date_occurred:
        try:
            # Parse the date string from the form (likely in yyyy-mm-dd format)
            year, month, day = date_occurred.split('-')
            # Format it as mm/dd/yyyy
            formatted_date = f"{month}/{day}/{year}"
        except ValueError:
            # If there's an error parsing, use the original value
            formatted_date = date_occurred
    else:
        formatted_date = ""

    form['name'] = 'Speak Up Report'
    form['type'] = f'{CONFIG.team_name} Employee Reported Incident'
    form['details'] = (
        f"Date Occurred: {formatted_date} \n"
        f"Issue Type: {form.get('issueType')} \n"
        f"Description: {form.get('description')} \n"
    )
    response = incident_handler.create(form)
    # Return a JSON response
    return jsonify({
        'status': 'success',
        'new_incident_id': response['id'],
        'new_incident_link': f"{CONFIG.xsoar_dev_ui_base_url}/Custom/caseinfoid/{response['id']}"
    })


@app.route('/xsoar-ticket-import-form', methods=['GET'])
@log_web_activity
def xsoar_ticket_import_form():
    return render_template('xsoar-ticket-import-form.html')


@app.route("/import-xsoar-ticket", methods=['POST'])
@log_web_activity
def import_xsoar_ticket():
    source_ticket_number = request.form.get('source_ticket_number')
    destination_ticket_number, destination_ticket_link = xsoar.import_ticket(source_ticket_number)
    return jsonify({
        'source_ticket_number': source_ticket_number,
        'destination_ticket_number': destination_ticket_number,
        'destination_ticket_link': destination_ticket_link
    })


@app.route("/get-approved-testing-entries", methods=['GET'])
@log_web_activity
def get_approved_testing_entries():
    """Fetches approved testing records and displays them in separate HTML tables."""
    approved_testing_records = list_handler.get_list_data_by_name(f'{CONFIG.team_name}_Approved_Testing')

    if not approved_testing_records:
        return "<h2>No Approved Testing Records Found</h2>"

    # Organize data for the template
    endpoints = approved_testing_records.get("ENDPOINTS", [])
    usernames = approved_testing_records.get("USERNAMES", [])
    ip_addresses = approved_testing_records.get("IP_ADDRESSES", [])

    # Render the template with the data
    return render_template(
        'approved_testing.html',
        ENDPOINTS=endpoints,
        USERNAMES=usernames,
        IP_ADDRESSES=ip_addresses
    )


def parse_date(date_str):
    """Parses a date string in multiple formats and returns a datetime object."""
    for fmt in ('%Y-%m-%d', '%m/%d/%Y'):
        try:
            return datetime.strptime(date_str, fmt)
        except ValueError:
            continue
    raise ValueError(f"Date format not recognized: {date_str}")


@app.route("/get-current-upcoming-travel-records", methods=['GET'])
@log_web_activity
def get_upcoming_travel():
    """Fetches upcoming travel records and displays them."""
    upcoming_travel_records = [
        record for record in list_handler.get_list_data_by_name('DnR_Upcoming_Travel')
        if parse_date(record['vacation_end_date']) >= datetime.now()
    ]

    return render_template(
        'upcoming_travel.html',
        travel_records=upcoming_travel_records
    )


@app.route("/travel-form")
@log_web_activity
def display_travel_form():
    """Displays the Upcoming Travel Notification form."""
    today = date.today().isoformat()  # Get today's date in 'YYYY-MM-DD' format
    return render_template("upcoming_travel_notification_form.html", today=today)


@app.route("/submit-travel-form", methods=['POST'])
@log_web_activity
def handle_travel_form_submission():
    """Handles the Upcoming Travel Notification form submissions and processes the data."""
    form = request.form.to_dict()

    # Submit to list_handler instead of incident_handler
    response = list_handler.add_item_to_list('DnR_Upcoming_Travel', {
        "traveller_email_address": form.get('traveller_email_address'),
        "work_location": form.get('work_location'),
        "vacation_location": form.get('vacation_location'),
        "vacation_start_date": form.get('vacation_start_date'),
        "vacation_end_date": form.get('vacation_end_date'),
        "is_working_during_vacation": form.get('will_work_during_vacation'),
        "comments": form.get('comments'),
        "submitted_at": datetime.now(eastern).strftime("%m/%d/%Y %I:%M %p %Z"),
        "submitted_by_ip_address": request.remote_addr
    })

    return jsonify({
        'status': 'success'
    })


@app.route('/favicon.ico')
def favicon():
    return app.send_static_file('icons/favicon.ico')


def main():
    charts_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../charts'))
    app.config['CHARTS_DIR'] = charts_dir
    app.run(debug=True, host='0.0.0.0', port=80, threaded=True)


if __name__ == "__main__":
    main()
