import os
from typing import List

from flask import Flask, render_template, request

from services import transfer_ticket

app = Flask(__name__, static_folder='static', static_url_path='/static', template_folder='templates')

# Supported image extensions
IMAGE_EXTENSIONS = (".jpg", ".jpeg", ".png", ".gif", ".svg")


def get_image_files() -> List[str]:
    """Retrieves a list of image files from the static and charts directories."""
    IMAGE_ORDER = [
        "images/Company Logo.jpg",
        "images/DnR Welcome.png",
        "images/IR_Metrics.jpeg",
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
        "charts/Vectra Detections by Rule.png",
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


@app.route("/full-slide-show")
def get_ir_dashboard_slide_show():
    """Renders the HTML template with the ordered list of image files."""
    image_files = get_image_files()
    return render_template("index.html", image_files=image_files)


@app.route("/msoc-form")
def display_form():
    """Displays the MSOC form."""
    return render_template("msoc_form.html")


@app.route("/submit-msoc-form", methods=['POST'])
def handle_msoc_form_submission():
    """Handles MSOC form submissions and processes the data."""

    # Process the submitted data.  For example, print it:
    site = request.form.get('site')
    server = request.form.get('server')

    print(f"Site: {site}")
    print(f"Server: {server}")

    # You can then redirect to a success page, return a response, or process the data further
    return render_template("msoc_success.html", site=site, server=server)


@app.route('/xsoar-ticket-import-form', methods=['GET', 'POST'])
def xsoar_ticket_import_form():
    if request.method == 'POST':
        source_ticket_number = request.form.get('source_ticket_number')
        if source_ticket_number:  # Check if the field is not empty
            destination_ticket_number, destination_ticket_link = transfer_ticket.import_ticket(source_ticket_number)
            return render_template('xsoar-ticket-import-response.html',
                                   source_ticket_number=source_ticket_number,
                                   destination_ticket_number=destination_ticket_number,
                                   destination_ticket_link=destination_ticket_link)
    return render_template('xsoar-ticket-import-form.html')


@app.route("/import-xsoar-ticket", methods=['POST'])
def import_xsoar_ticket():
    """Handles MSOC form submissions and processes the data."""
    source_ticket_number = request.form.get('source_ticket_number')
    destination_ticket_number, destination_ticket_link = transfer_ticket.import_ticket(source_ticket_number)
    return render_template("xsoar-ticket-import-response.html",
                           source_ticket_number=source_ticket_number,
                           destination_ticket_number=destination_ticket_number,
                           destination_ticket_link=destination_ticket_link)


if __name__ == "__main__":
    charts_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../charts'))
    app.config['CHARTS_DIR'] = charts_dir
    app.run(debug=True, host='0.0.0.0', port=8000, threaded=True)
