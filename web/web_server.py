import asyncio
import http.client
import http.server
import ipaddress
import os
import random
import select
import socket
import socketserver
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timedelta
from typing import List, Dict
from urllib.parse import urlsplit

import pytz
import requests
from flask import Flask, request, abort, jsonify, render_template, send_from_directory

from my_config import get_config
from services import xsoar
from services.approved_testing_utils import add_approved_testing_entry
from src.components import apt_names_fetcher
from src.utils.logging_utils import log_web_activity, is_scanner_request

# Define the proxy port
PROXY_PORT = 8080
# Optimize buffer size for better performance (increase from default 4096)
BUFFER_SIZE = 16384
# Number of worker threads for processing connections
NUM_WORKERS = 10
# Connection pool size
MAX_CONNECTIONS = 100

app = Flask(__name__, static_folder='static', static_url_path='/static', template_folder='templates')
eastern = pytz.timezone('US/Eastern')
CONFIG = get_config()

# Connection pool for HTTP requests
http_pool = ThreadPoolExecutor(max_workers=NUM_WORKERS)

# Supported image extensions
IMAGE_EXTENSIONS = (".jpg", ".jpeg", ".png", ".gif", ".svg")
blocked_ip_ranges = []  # ["10.49.70.0/24", "10.50.70.0/24"]

list_handler = xsoar.ListHandler()
incident_handler = xsoar.TicketHandler()


@app.before_request
def block_ip():
    if any(ipaddress.ip_network(request.remote_addr).subnet_of(ipaddress.ip_network(blocked_ip_range)) for blocked_ip_range in blocked_ip_ranges):
        abort(403)  # Forbidden

    # Check for scanner patterns to quickly return 404 for scanner probes
    if is_scanner_request():
        # Return a very minimal 404 response without logging to reduce overhead
        # This will bypass the normal Flask request handling
        return abort(404)


def get_image_files() -> List[str]:
    """Retrieves a list of image files from the static and charts directories."""
    today_date = datetime.now().strftime('%m-%d-%Y')
    image_order = [
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
    for image_path in image_order:
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
    return render_template("slide-show.html", image_files=image_files, show_burger=True)


@app.route("/msoc-form")
@log_web_activity
def display_msoc_form():
    """Displays the MSOC form."""
    return render_template("msoc_form.html", show_burger=False)


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
    formatted_date = ""
    if date_occurred:
        try:
            # Parse the date string from the form (likely in yyyy-mm-dd format)
            year, month, day = date_occurred.split('-')
            # Format it as mm/dd/yyyy
            formatted_date = f"{month}/{day}/{year}"
        except ValueError:
            # If there's an error parsing, use the original value
            formatted_date = date_occurred

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
    cidr_blocks = approved_testing_records.get("CIDR_BLOCKS", [])

    # Render the template with the data
    return render_template(
        'approved_testing.html',
        ENDPOINTS=endpoints,
        USERNAMES=usernames,
        IP_ADDRESSES=ip_addresses,
        CIDR_BLOCKS=cidr_blocks
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
        'status': 'success',
        'response': response
    })


@app.route("/red-team-testing-form")
@log_web_activity
def display_red_team_testing_form():
    """Displays the Red Team Testing form."""
    tomorrow = (datetime.now() + timedelta(days=1)).strftime('%Y-%m-%d')
    return render_template("red_team_testing_form.html", tomorrow=tomorrow)


@app.route("/submit-red-team-testing-form", methods=['POST'])
@log_web_activity
def handle_red_team_testing_form_submission():
    """Handles the Red Team Testing form submissions and processes the data."""
    form = request.form.to_dict()

    usernames = form.get('usernames', '').strip()
    tester_hosts = form.get('tester_hosts', '').strip()
    targets = form.get('targets', '').strip()
    description = form.get('description', '').strip()
    notes_scope = form.get('notes_scope', '').strip()
    keep_until = form.get('keep_until', '')
    submitter_ip_address = request.remote_addr
    submitter_email_address = form.get('email_local', '') + '@company.com'
    submit_date = datetime.now(eastern).strftime("%m/%d/%Y")

    approved_testing_list_name = f"{CONFIG.team_name}_Approved_Testing"
    approved_testing_master_list_name = f"{CONFIG.team_name}_Approved_Testing_MASTER"
    try:
        add_approved_testing_entry(
            list_handler,
            approved_testing_list_name,
            approved_testing_master_list_name,
            usernames,
            tester_hosts,
            targets,
            description,
            notes_scope,
            submitter_email_address,
            keep_until,
            submit_date,
            submitter_ip_address
        )
    except ValueError as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }, 400)

    return jsonify({
        'status': 'success'
    })


@app.route('/favicon.ico')
def favicon():
    return app.send_static_file('icons/favicon.ico')


# HTTP connection pool for reusing connections
class ConnectionPool:
    def __init__(self, max_connections=100):
        self.pool: Dict[str, List[http.client.HTTPConnection]] = {}
        self.max_connections = max_connections
        self.lock = threading.RLock()

    def get_connection(self, host):
        with self.lock:
            if host not in self.pool:
                self.pool[host] = []

            if self.pool[host]:
                return self.pool[host].pop()
            else:
                return http.client.HTTPConnection(host)

    def release_connection(self, host, conn):
        with self.lock:
            if host not in self.pool:
                self.pool[host] = []

            if len(self.pool[host]) < self.max_connections:
                self.pool[host].append(conn)
            else:
                conn.close()


# Create a global connection pool
connection_pool = ConnectionPool(max_connections=MAX_CONNECTIONS)


# Optimized proxy class with async support
def _relay_sockets(client, target):
    """Simple synchronous socket relay that avoids HTTP processing"""
    sockets = [client, target]

    # Keep transferring data between client and target
    while True:
        # Wait until a socket is ready to be read
        readable, _, exceptional = select.select(sockets, [], sockets, 60)

        if exceptional:
            break

        if not readable:
            continue  # Timeout, try again

        for sock in readable:
            # Determine the destination socket
            dest = target if sock is client else client

            try:
                data = sock.recv(BUFFER_SIZE)
                if not data:
                    return  # Connection closed
                dest.sendall(data)
            except (socket.error, ConnectionResetError, BrokenPipeError):
                return  # Any socket error means we're done


async def _async_select(client_sock, target_sock):
    """Async-compatible version of select operation"""
    loop = asyncio.get_event_loop()
    readable = []
    for sock in [client_sock, target_sock]:
        try:
            if await loop.sock_recv(sock, 1):
                readable.append(sock)
        except:
            pass
    return readable


def relay_data_async(client_sock, target_sock):
    """Efficiently relays data bidirectionally between client_sock and target_sock."""
    try:
        # Use two separate buffers for better performance
        client_to_target = bytearray(BUFFER_SIZE)
        target_to_client = bytearray(BUFFER_SIZE)

        while True:
            # Select with a timeout to prevent high CPU usage
            r, _, _ = asyncio.get_event_loop().run_until_complete(
                asyncio.wait_for(
                    _async_select(client_sock, target_sock),
                    timeout=2.0
                )
            )

            if not r:
                # Check if connections are still alive
                if client_sock.fileno() == -1 or target_sock.fileno() == -1:
                    break

            if client_sock in r:
                # Use memory view for zero-copy slicing
                view = memoryview(client_to_target)
                bytes_read = client_sock.recv_into(view)
                if not bytes_read:
                    break
                target_sock.sendall(view[:bytes_read])

            if target_sock in r:
                view = memoryview(target_to_client)
                bytes_read = target_sock.recv_into(view)
                if not bytes_read:
                    break
                client_sock.sendall(view[:bytes_read])
    except Exception as e:
        print(f"Error during relay: {e}")
    finally:
        for sock in [client_sock, target_sock]:
            try:
                sock.close()
            except:
                pass


class OptimizedProxy(http.server.SimpleHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'  # Enable keep-alive

    def do_GET(self):
        self.proxy_http_request()

    def do_POST(self):
        self.proxy_http_request()

    def do_PUT(self):
        self.proxy_http_request()

    def do_DELETE(self):
        self.proxy_http_request()

    def do_HEAD(self):
        self.proxy_http_request()

    def do_CONNECT(self):
        # Parse target address
        target_host, target_port = self.path.split(':', 1)
        target_port = int(target_port)

        timestamp = datetime.now(eastern).strftime('%Y-%m-%d %H:%M:%S %Z')
        client_ip = self.client_address[0] if hasattr(self, 'client_address') else 'Unknown'
        print(f"[{timestamp}] CONNECT request from {client_ip} to {target_host}:{target_port}")

        try:
            # Connect to target server
            target_sock = socket.create_connection((target_host, target_port), timeout=60)

            # Send 200 Connection Established response
            self.wfile.write(b"HTTP/1.1 200 Connection established\r\n\r\n")

            # Create connection pipes
            client_socket = self.connection

            # Set reasonable timeouts
            client_socket.settimeout(60)
            target_sock.settimeout(60)

            # Start bidirectional relay
            _relay_sockets(client_socket, target_sock)

            return

        except Exception as e:
            print(f"CONNECT error: {e}")
            self.send_error(502, f"Cannot connect to {target_host}:{target_port}")
            return

    def proxy_http_request(self):
        # This part handles regular HTTP requests (not HTTPS via CONNECT)
        url = self.path

        if url.startswith('https://'):
            print(f"Warning: Client tried to send HTTPS directly. Use CONNECT for HTTPS tunneling")
            self.send_error(501, "HTTPS GET/POST proxy not implemented (use CONNECT)")
            return

        try:
            parts = urlsplit(url)
            netloc = parts.netloc
            path = parts.path
            query = parts.query
            fragment = parts.fragment

            full_path = path
            if query:
                full_path += '?' + query
            if fragment:
                full_path += '#' + fragment

            # Check if client accepts gzip encoding
            accept_encoding = self.headers.get('Accept-Encoding', '')
            supports_gzip = 'gzip' in accept_encoding.lower()

            headers = {}
            for h in self.headers:
                if h.lower() not in ['proxy-connection', 'transfer-encoding', 'connection']:
                    headers[h] = self.headers[h]

            # Add support for gzip if client accepts it
            if supports_gzip and 'Accept-Encoding' not in headers:
                headers['Accept-Encoding'] = 'gzip'

            # Use connection pool
            conn = connection_pool.get_connection(netloc)

            if self.command == 'GET':
                conn.request(self.command, full_path, headers=headers)
            else:
                content_length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_length) if content_length > 0 else None
                conn.request(self.command, full_path, body=body, headers=headers)

            response = conn.getresponse()

            self.send_response(response.status)

            # Prepare for potential gzip compression
            for h, v in response.getheaders():
                if h.lower() not in ['transfer-encoding', 'connection']:
                    self.send_header(h, v)

            self.end_headers()

            # Read response content in larger chunks for better performance
            content = b''
            while True:
                chunk = response.read(BUFFER_SIZE)
                if not chunk:
                    break
                content += chunk

            # Return the connection to the pool
            connection_pool.release_connection(netloc, conn)

            # Send response data to client
            self.wfile.write(content)

        except Exception as e:
            print(f"Error during HTTP proxy request: {e}")
            self.send_error(502, "Bad Gateway")


# Add a function to start the optimized proxy server
def start_proxy_server():
    handler = OptimizedProxy
    print(f"Starting optimized proxy on port {PROXY_PORT}")
    try:
        # Enable address reuse to avoid "address already in use" errors
        socketserver.TCPServer.allow_reuse_address = True
        with socketserver.ThreadingTCPServer(("", PROXY_PORT), handler) as httpd:  # type: ignore[arg-type]
            httpd.serve_forever()
    except Exception as e:
        print(f"Failed to start proxy: {e}")
        print("This often means the port is in use or you need Administrator privileges to bind to it.")


def main():
    charts_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../charts'))
    app.config['CHARTS_DIR'] = charts_dir

    # Start proxy server in a separate thread
    proxy_thread = threading.Thread(target=start_proxy_server, daemon=True)
    proxy_thread.start()
    print(f"High-performance proxy server thread started on port {PROXY_PORT}")

    # Start Flask server in main thread
    port = 80  # Changed from port 80 to avoid "Address already in use" errors
    print(f"Starting web server on port {port}")
    app.run(debug=True, host='0.0.0.0', port=port, threaded=True)


@app.route("/api/apt-names", methods=["GET"])
@log_web_activity
def api_apt_names():
    """API endpoint to get APT workbook summary (region sheets only)."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(base_dir, '../data/transient/de/APTAKAcleaned.xlsx')
    file_path = os.path.abspath(file_path)
    info = apt_names_fetcher.get_workbook_info(file_path)
    return jsonify(info)


@app.route("/api/apt-other-names", methods=["GET"])
@log_web_activity
def api_apt_other_names():
    """API endpoint to get other names for a given APT common name."""
    common_name = request.args.get("common_name")
    app.logger.info(f"[APT API] Received common_name: '{common_name}' from request")
    if not common_name:
        return jsonify({"error": "Missing required parameter: common_name"}), 400
    should_include_metadata = request.args.get("should_include_metadata")
    if should_include_metadata is not None:
        should_include_metadata = should_include_metadata.lower() == "true"
    else:
        should_include_metadata = False
    # Support both 'format' and 'response_format' query parameters
    response_format = request.args.get("response_format")
    if not response_format:
        response_format = request.args.get("format", "html")
    response_format = response_format.lower()
    base_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(base_dir, '../data/transient/de/APTAKAcleaned.xlsx')
    file_path = os.path.abspath(file_path)
    app.logger.info(f"[APT API] Calling get_other_names_for_common_name with common_name: '{common_name}', file_path: '{file_path}', should_include_metadata: {should_include_metadata}")
    results = apt_names_fetcher.get_other_names_for_common_name(common_name, file_path, should_include_metadata)
    app.logger.info(f"[APT API] Results returned: {results}")
    if response_format == "json":
        return jsonify(results)
    else:
        return render_template("apt_other_names_results.html", common_name=common_name, results=results, should_include_metadata=should_include_metadata)


@app.route("/apt-other-names-search", methods=["GET"])
@log_web_activity
def apt_other_names_search():
    """Render the APT Other Names search form page."""
    # Get all APT names for dropdown
    base_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(base_dir, '../data/transient/de/APTAKAcleaned.xlsx')
    file_path = os.path.abspath(file_path)

    try:
        apt_names = apt_names_fetcher.get_all_apt_names(file_path)
        app.logger.info(f"[APT Search] Loaded {len(apt_names)} APT names for dropdown")
    except Exception as e:
        app.logger.error(f"[APT Search] Error loading APT names: {str(e)}")
        apt_names = []

    return render_template("apt_other_names_search.html", apt_names=apt_names)


@app.route('/api/random-audio', methods=['GET'])
def random_audio():
    """Return a random mp3 filename from the static/audio directory."""
    audio_dir = os.path.join(os.path.dirname(__file__), 'static', 'audio')
    files = [f for f in os.listdir(audio_dir) if f.endswith('.mp3')]
    if not files:
        return jsonify({'error': 'No audio files found'}), 404
    return jsonify({'filename': random.choice(files)})


@app.route('/xsoar')
@log_web_activity
def xsoar_dashboard():
    """XSOAR incident dashboard"""
    return render_template('xsoar_dashboard.html')


@app.route('/api/xsoar/incidents')
@log_web_activity
def api_xsoar_incidents():
    """API to get XSOAR incidents with search and pagination"""
    query = request.args.get('query', '')
    period = request.args.get('period')
    size = int(request.args.get('size', 50))
    
    try:
        incidents = incident_handler.get_tickets(query, period, size)
        return jsonify({'success': True, 'incidents': incidents})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/xsoar/incident/<incident_id>')
@log_web_activity  
def api_xsoar_incident_detail(incident_id):
    """API to get XSOAR incident details"""
    try:
        incident = xsoar.get_incident(incident_id)
        entries = incident_handler.get_entries(incident_id)
        return jsonify({'success': True, 'incident': incident, 'entries': entries})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/xsoar/incident/<incident_id>')
@log_web_activity
def xsoar_incident_detail(incident_id):
    """XSOAR incident detail view"""
    try:
        incident = xsoar.get_incident(incident_id)
        entries = incident_handler.get_entries(incident_id)
        return render_template('xsoar_incident_detail.html', 
                             incident=incident, entries=entries)
    except requests.exceptions.HTTPError as e:
        return f"XSOAR API Error for incident {incident_id}: HTTP {e.response.status_code} - {e.response.text}", 500
    except requests.exceptions.ConnectionError as e:
        return f"Connection Error for incident {incident_id}: {str(e)}", 500
    except ValueError as e:
        return f"Invalid JSON response for incident {incident_id}: {str(e)}", 500
    except Exception as e:
        return f"Error loading incident {incident_id}: {str(e)}", 500


@app.route('/api/xsoar/incident/<incident_id>/entries')
@log_web_activity  
def api_xsoar_incident_entries(incident_id):
    """API to get incident entries/comments"""
    try:
        entries = incident_handler.get_entries(incident_id)
        return jsonify({'success': True, 'entries': entries})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/xsoar/incident/<incident_id>/link', methods=['POST'])
@log_web_activity
def api_xsoar_link_incident(incident_id):
    """API to link incidents"""
    link_incident_id = request.json.get('link_incident_id')
    try:
        result = incident_handler.link_tickets(incident_id, link_incident_id)
        return jsonify({'success': True, 'result': result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/xsoar/incident/<incident_id>/participant', methods=['POST'])
@log_web_activity
def api_xsoar_add_participant(incident_id):
    """API to add participant to incident"""
    email = request.json.get('email')
    try:
        result = incident_handler.add_participant(incident_id, email)
        return jsonify({'success': True, 'result': result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


if __name__ == "__main__":
    main()
