import csv
import ipaddress
import os
from datetime import datetime
from functools import wraps
from typing import List

import pytz
from flask import Flask, render_template, request, abort
from flask import jsonify

from config import get_config
from services import xsoar

app = Flask(__name__, static_folder='static', static_url_path='/static', template_folder='templates')
eastern = pytz.timezone('US/Eastern')
CONFIG = get_config()

# Supported image extensions
IMAGE_EXTENSIONS = (".jpg", ".jpeg", ".png", ".gif", ".svg")
blocked_ip_ranges = ["10.49.70.0/24", "10.50.70.0/24"]


@app.before_request
def block_ip():
    if any(ipaddress.ip_network(request.remote_addr).subnet_of(ipaddress.ip_network(blocked_ip_range)) for blocked_ip_range in blocked_ip_ranges):
        abort(403)  # Forbidden


def get_image_files() -> List[str]:
    """Retrieves a list of image files from the static and charts directories."""
    IMAGE_ORDER = [
        "images/Company Logo.png",
        "images/DnR Welcome.png",
        "charts/Threatcon Level.png",
        "charts/Days Since Last Incident.png",
        "images/DnR Metrics by Peanuts.jpg",
        "charts/Aging Tickets.png",
        "charts/Inflow.png",
        "charts/Outflow.png",
        "charts/SLA Breaches.png",
        "charts/MTTR MTTC.png",
        "charts/Heat Map.png",
        "charts/QR Rule Efficacy-Quarter.png",
        "charts/QR Rule Efficacy-Month.png",
        "charts/QR Rule Efficacy-Week.png",
        "images/Threat Hunting Intro.png",
        "charts/DE Stories.png",
        "charts/RE Stories.png",
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


def log_web_activity(func):
    """Logs web activity to a CSV file."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        if request:
            client_ip = request.remote_addr
            if client_ip not in ['192.168.1.100', '127.0.0.1', '192.168.1.102']:  # don't log the activity for my IP address
                now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M:%S %p %Z')
                with open('../data/transient/logs/web_server_activity_log.csv', 'a', newline='\n') as csvfile:
                    csv.writer(csvfile).writerow([request.path, client_ip, now_eastern])
        return func(*args, **kwargs)

    return wrapper


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
    form['type'] = 'METCIRT Employee Reported Incident'
    form['details'] = (
        f"Date Occurred: {formatted_date} \n"
        f"Issue Type: {form.get('issueType')} \n"
        f"Description: {form.get('description')} \n"
    )
    response = xsoar.create_incident(CONFIG.xsoar_dev_api_base_url, form, CONFIG.xsoar_dev_auth_id, CONFIG.xsoar_dev_auth_token)
    # Return a JSON response
    return jsonify({
        'status': 'success',
        'new_incident_id': response['id'],
        'new_incident_link': f"{CONFIG.xsoar_dev_ui_base_url}/Custom/caseinfoid/{response['id']}"
    })


@app.route("/submit-msoc-form", methods=['POST'])
@log_web_activity
def handle_msoc_form_submission():
    """Handles MSOC form submissions and processes the data."""
    form = request.form.to_dict()
    form['type'] = 'MSOC Site Security Device Management'
    response = xsoar.create_incident(CONFIG.xsoar_dev_api_base_url, form, CONFIG.xsoar_dev_auth_id, CONFIG.xsoar_dev_auth_token)
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


@app.route('/favicon.ico')
def favicon():
    return app.send_static_file('icons/favicon.ico')


def main():
    charts_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../charts'))
    app.config['CHARTS_DIR'] = charts_dir
    app.run(debug=True, host='0.0.0.0', port=8000, threaded=True)


if __name__ == "__main__":
    main()
