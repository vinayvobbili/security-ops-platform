import csv
import os
from datetime import datetime
from functools import wraps
from typing import List

import pytz
from flask import Flask, render_template, request
from flask import jsonify

import xsoar
from config import get_config

app = Flask(__name__, static_folder='static', static_url_path='/static', template_folder='templates')
eastern = pytz.timezone('US/Eastern')
config = get_config()

# Supported image extensions
IMAGE_EXTENSIONS = (".jpg", ".jpeg", ".png", ".gif", ".svg")


def get_image_files() -> List[str]:
    """Retrieves a list of image files from the static and charts directories."""
    IMAGE_ORDER = [
        "images/Company Logo.png",
        "images/DnR Welcome.png",
        "charts/Threatcon Level.png",
        "charts/Days Since Last Incident.jpg",
        "images/IR Dashboard.png",
        "charts/Aging Tickets.png",
        "charts/Inflow.png",
        "charts/Outflow.png",
        "charts/SLA Breaches.png",
        "charts/MTTR MTTC.png",
        "charts/Lifespan.png",
        "charts/Heat Map.png",
        "charts/QR Rule Efficacy.png",
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
                with open('../data/transient/web_server_activity_log.csv', 'a', newline='\n') as csvfile:
                    csv.writer(csvfile).writerow([request.path, client_ip, now_eastern])
        return func(*args, **kwargs)

    return wrapper


@app.route("/full-slide-show")
@log_web_activity
def get_ir_dashboard_slide_show():
    """Renders the HTML template with the ordered list of image files."""
    image_files = get_image_files()
    return render_template("slide-show.html", image_files=image_files)


@app.route("/msoc-form")
@log_web_activity
def display_form():
    """Displays the MSOC form."""
    return render_template("msoc_form.html")


@app.route("/submit-msoc-form", methods=['POST'])
@log_web_activity
def handle_msoc_form_submission():
    """Handles MSOC form submissions and processes the data."""

    # Process the submitted data
    form = request.form.to_dict()
    form['type'] = 'MSOC Site Security Device Management'
    response = xsoar.create_incident(config.xsoar_dev_api_base_url, form, config.xsoar_dev_auth_id, config.xsoar_dev_auth_token)
    # Return a JSON response
    return jsonify({
        'status': 'success',
        'new_incident_id': response['id'],
        'new_incident_link': f"{config.xsoar_dev_ui_base_url}/Custom/caseinfoid/{response['id']}"
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
