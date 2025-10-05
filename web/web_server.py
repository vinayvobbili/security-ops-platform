import argparse
import asyncio
import http.client
import http.server
import ipaddress
import json
import logging
import os
import random
import select
import socket
import socketserver
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timedelta, timezone
from typing import List, Dict
from urllib.parse import urlsplit

import pytz
import requests
from flask import Flask, request, abort, jsonify, render_template

from my_config import get_config
from services import xsoar
from services.approved_testing_utils import add_approved_testing_entry
from src import secops
from src.components import apt_names_fetcher
from src.utils.logging_utils import log_web_activity, is_scanner_request

SHOULD_START_PROXY = False
USE_DEBUG_MODE = True  # Set to False to use Waitress production server
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

# Configure logging to suppress werkzeug INFO logs for PAC files and other noise
logging.getLogger('werkzeug').setLevel(logging.WARNING)
logging.getLogger('waitress').setLevel(logging.WARNING)

# Connection pool for HTTP requests
http_pool = ThreadPoolExecutor(max_workers=NUM_WORKERS)

# Supported image extensions
IMAGE_EXTENSIONS = (".jpg", ".jpeg", ".png", ".gif", ".svg")
blocked_ip_ranges = []  # ["10.49.70.0/24", "10.50.70.0/24"]

list_handler = xsoar.ListHandler()
incident_handler = xsoar.TicketHandler()

# Add module logger (was missing previously)
logger = logging.getLogger(__name__)


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
            print(f"File not found: {full_path}")

    return image_files


@app.route("/")
@log_web_activity
def get_ir_dashboard_slide_show():
    """Renders the HTML template with the ordered list of image files."""
    image_files = get_image_files()
    return render_template("slide-show.html", image_files=image_files, show_burger=True)


@app.route("/<path:filename>.pac")
def proxy_pac_file(filename):
    """Handle PAC file requests to reduce log clutter."""
    # Return empty PAC file content for any PAC file request
    pac_content = """function FindProxyForURL(url, host) {
    return "DIRECT";
}"""
    return pac_content, 200, {'Content-Type': 'application/x-ns-proxy-autoconfig'}


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
    try:
        # Set non-blocking mode to handle disconnections gracefully
        client.settimeout(1.0)
        target.settimeout(1.0)

        sockets = [client, target]

        # Keep transferring data between client and target
        while True:
            try:
                # Check if sockets are still valid before select
                if client.fileno() == -1 or target.fileno() == -1:
                    break

                # Wait until a socket is ready to be read
                readable, _, exceptional = select.select(sockets, [], sockets, 1.0)

                if exceptional:
                    break

                if not readable:
                    continue  # Timeout, try again

                for sock in readable:
                    # Check socket validity again
                    if sock.fileno() == -1:
                        continue

                    # Determine the destination socket
                    dest = target if sock is client else client

                    # Check destination socket validity
                    if dest.fileno() == -1:
                        return

                    try:
                        data = sock.recv(BUFFER_SIZE)
                        if not data:
                            return  # Connection closed
                        dest.sendall(data)
                    except (socket.error, ConnectionResetError, BrokenPipeError, OSError) as e:
                        if e.errno == 9:  # Bad file descriptor
                            return
                        return  # Any socket error means we're done
            except (OSError, ValueError) as e:
                # Handle select errors gracefully
                if hasattr(e, 'errno') and e.errno == 9:  # Bad file descriptor
                    break
                return
    except Exception:
        # Catch any other unexpected errors
        pass
    finally:
        # Ensure sockets are properly closed
        for sock in [client, target]:
            try:
                if sock and sock.fileno() != -1:
                    sock.close()
            except (OSError, AttributeError):
                pass


async def _async_select(client_sock, target_sock):
    """Async-compatible version of select operation using running loop (Python 3.13 safe)."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        # Fallback: no running loop (shouldn't generally happen here)
        loop = asyncio.get_event_loop_policy().new_event_loop()
    readable = []
    for sock in [client_sock, target_sock]:
        try:
            if await loop.sock_recv(sock, 1):
                readable.append(sock)
        except (ConnectionError, OSError, asyncio.CancelledError):
            pass
    return readable


def relay_data_async(client_sock, target_sock):
    """Efficiently relays data bidirectionally between client_sock and target_sock.
    Uses a dedicated event loop to avoid deprecated get_event_loop() patterns.
    """
    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        # Use two separate buffers for better performance
        client_to_target = bytearray(BUFFER_SIZE)
        target_to_client = bytearray(BUFFER_SIZE)

        while True:
            try:
                r = loop.run_until_complete(
                    asyncio.wait_for(_async_select(client_sock, target_sock), timeout=2.0)
                )
            except asyncio.TimeoutError:
                r = []
            except Exception:
                break

            if not r:
                # Check if connections are still alive
                if client_sock.fileno() == -1 or target_sock.fileno() == -1:
                    break

            if client_sock in r:
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
        try:
            loop.close()
        except Exception:
            pass
        for sock in [client_sock, target_sock]:
            try:
                sock.close()
            except (OSError, AttributeError):
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
        target_host = "unknown"
        target_port = "unknown"

        try:
            # Parse target address
            target_host, target_port = self.path.split(':', 1)
            target_port = int(target_port)

            timestamp = datetime.now(eastern).strftime('%Y-%m-%d %H:%M:%S %Z')
            client_ip = self.client_address[0] if hasattr(self, 'client_address') else 'Unknown'
            print(f"[{timestamp}] CONNECT request from {client_ip} to {target_host}:{target_port}")

            # Connect to target server
            target_sock = socket.create_connection((target_host, target_port), timeout=30)

            # Send 200 Connection Established response
            try:
                self.wfile.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                target_sock.close()
                return

            # Create connection pipes
            client_socket = self.connection

            # Set reasonable timeouts
            try:
                client_socket.settimeout(30)
                target_sock.settimeout(30)
            except (OSError, AttributeError):
                target_sock.close()
                return

            # Start bidirectional relay
            _relay_sockets(client_socket, target_sock)

        except ValueError:
            # Invalid target address format
            try:
                self.send_error(400, "Bad Request: Invalid target address")
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
        except (socket.timeout, socket.gaierror):
            # Connection timeout or DNS resolution error
            try:
                self.send_error(502, f"Cannot connect to {target_host}:{target_port}")
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
        except (ConnectionRefusedError, OSError) as e:
            # Connection refused or other OS-level errors
            try:
                if hasattr(e, 'errno') and e.errno == 9:  # Bad file descriptor
                    return  # Client already disconnected
                self.send_error(502, f"Cannot connect to {target_host}:{target_port}")
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
        except Exception as e:
            # Catch any other unexpected errors
            try:
                print(f"CONNECT error: {e}")
                self.send_error(502, f"Cannot connect to {target_host}:{target_port}")
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass

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

        except (BrokenPipeError, ConnectionResetError, OSError) as e:
            if hasattr(e, 'errno') and e.errno == 9:  # Bad file descriptor
                return  # Client already disconnected, no need to respond
            print(f"Connection error during HTTP proxy request: {e}")
            try:
                self.send_error(502, "Bad Gateway")
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
        except Exception as e:
            print(f"Error during HTTP proxy request: {e}")
            try:
                self.send_error(502, "Bad Gateway")
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass


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


@app.route('/shift-performance')
@log_web_activity
def shift_performance_dashboard():
    """Display shift performance page - loads instantly with empty structure"""
    return render_template('shift_performance.html', xsoar_prod_ui_base=getattr(CONFIG, 'xsoar_prod_ui_base_url', 'https://msoar.crtx.us.paloaltonetworks.com'))


def _shift_has_passed(shift_name, current_shift):
    """Check if a shift has already passed based on current shift"""
    shift_order = ['morning', 'afternoon', 'night']
    try:
        shift_index = shift_order.index(shift_name)
        current_index = shift_order.index(current_shift)
        return shift_index < current_index
    except ValueError:
        return False


# Simple in-memory cache for inflow queries (query -> (timestamp, tickets))
SHIFT_INFLOW_CACHE = {}
SHIFT_INFLOW_CACHE_TTL_SECONDS = 300  # 5 minutes


def _get_cached_inflow(query: str):
    now = datetime.now(timezone.utc).timestamp()
    entry = SHIFT_INFLOW_CACHE.get(query)
    if entry:
        ts, tickets = entry
        if now - ts < SHIFT_INFLOW_CACHE_TTL_SECONDS:
            return tickets
        else:
            SHIFT_INFLOW_CACHE.pop(query, None)
    return None


def _set_cached_inflow(query: str, tickets):
    SHIFT_INFLOW_CACHE[query] = (datetime.now(timezone.utc).timestamp(), tickets)


def _compute_shift_window(date_obj: datetime, shift_name: str):
    """Return (start_dt_eastern, end_dt_eastern, start_str, end_str) for a shift date+name."""
    if shift_name.lower() == 'morning':
        shift_start_hour = 4.5
    elif shift_name.lower() == 'afternoon':
        shift_start_hour = 12.5
    else:
        shift_start_hour = 20.5
    start_hour_int = int(shift_start_hour)
    start_minute = int((shift_start_hour % 1) * 60)
    start_dt_naive = datetime(date_obj.year, date_obj.month, date_obj.day, start_hour_int, start_minute)
    start_dt = eastern.localize(start_dt_naive)
    end_dt = start_dt + timedelta(hours=8)
    time_format = '%Y-%m-%dT%H:%M:%S %z'
    return start_dt, end_dt, start_dt.strftime(time_format), end_dt.strftime(time_format)


def _fetch_inflow_for_window(date_obj: datetime, shift_name: str):
    start_dt, end_dt, start_str, end_str = _compute_shift_window(date_obj, shift_name)
    time_filter = f'created:>="{start_str}" created:<="{end_str}"'
    inflow_query = f'{secops.BASE_QUERY} {time_filter}'
    cached = _get_cached_inflow(inflow_query)
    if cached is not None:
        return inflow_query, cached, (start_dt, end_dt)
    tickets = incident_handler.get_tickets(query=inflow_query)
    _set_cached_inflow(inflow_query, tickets)
    return inflow_query, tickets, (start_dt, end_dt)


@app.route('/api/shift-list')
@log_web_activity
def get_shift_list():
    """Single source of truth for shift performance data.

    Returns comprehensive shift data for the past week including:
    - Ticket counts (inflow/outflow)
    - Full ticket details (inflow_tickets, outflow_tickets arrays)
    - Metrics (MTTR, MTTC, SLA breaches)
    - Staffing info
    - Performance scores

    Architecture:
    - Frontend loads this data ONCE on page load
    - Frontend stores data in globalShiftData
    - Table displays summary counts from this data
    - Details modal slices/dices the SAME data (no additional API calls)
    - All counts derived from actual ticket arrays for consistency
    """
    status = 'unknown'
    try:
        shift_data = []
        shifts = ['morning', 'afternoon', 'night']
        for days_back in range(7):
            target_date = datetime.now(eastern) - timedelta(days=days_back)
            day_name = target_date.strftime('%A')
            date_str = target_date.strftime('%Y-%m-%d')
            for shift_name in shifts:
                try:
                    staffing = secops.get_staffing_data(day_name, shift_name)
                    total_staff = sum(len(staff) for team, staff in staffing.items() if team != 'On-Call' and staff != ['N/A (Excel file missing)'])
                    shift_id = f"{date_str}_{shift_name}"
                    current_shift = secops.get_current_shift()
                    if days_back > 0:
                        status = 'completed'
                        show_shift = True
                    elif days_back == 0:
                        if shift_name.lower() == current_shift:
                            status = 'active'
                            show_shift = True
                        elif _shift_has_passed(shift_name.lower(), current_shift):
                            status = 'completed'
                            show_shift = True
                        else:
                            show_shift = False
                    else:
                        show_shift = False
                    if show_shift:
                        shift_hour_map = {'morning': 4.5, 'afternoon': 12.5, 'night': 20.5}
                        shift_start_hour = shift_hour_map.get(shift_name.lower(), 4.5)
                        security_actions = secops.get_shift_security_actions(days_back, shift_start_hour)

                        # Get staffing details
                        detailed_staffing = secops.get_staffing_data(day_name, shift_name)
                        basic_staffing = secops.get_basic_shift_staffing(day_name, shift_name.lower())

                        # Determine shift lead (prefer first SA)
                        sa_list = detailed_staffing.get('SA') or detailed_staffing.get('senior_analysts') or []
                        shift_lead = None
                        if isinstance(sa_list, list) and sa_list:
                            first_sa = sa_list[0]
                            if first_sa and 'N/A' not in str(first_sa):
                                shift_lead = str(first_sa)
                        if not shift_lead:
                            shift_lead = secops.get_shift_lead(day_name, shift_name)
                        if not shift_lead or 'N/A' in str(shift_lead):
                            shift_lead = 'N/A'

                        # Inflow via cached helper
                        base_date = datetime(target_date.year, target_date.month, target_date.day)
                        _, inflow_tickets, (start_dt, end_dt) = _fetch_inflow_for_window(base_date, shift_name)
                        mtp_ids = [t.get('id') for t in inflow_tickets if t.get('CustomFields', {}).get('impact') == 'Malicious True Positive']
                        sla_metrics = _extract_sla_metrics(inflow_tickets)

                        # Fetch outflow tickets
                        time_format = '%Y-%m-%dT%H:%M:%S %z'
                        start_str = start_dt.strftime(time_format)
                        end_str = end_dt.strftime(time_format)
                        time_filter = f'created:>="{start_str}" created:<="{end_str}"'
                        outflow_query = f'{secops.BASE_QUERY} {time_filter} status:closed'
                        outflow_tickets = incident_handler.get_tickets(query=outflow_query)

                        # Serialize inflow tickets
                        inflow_list = []
                        for ticket in inflow_tickets:
                            custom_fields = ticket.get('CustomFields', {})
                            ttr_minutes = None
                            ttc_minutes = None
                            if 'timetorespond' in custom_fields and custom_fields['timetorespond']:
                                ttr_minutes = round(custom_fields['timetorespond'].get('totalDuration', 0) / 60, 2)
                            if 'timetocontain' in custom_fields and custom_fields['timetocontain']:
                                ttc_minutes = round(custom_fields['timetocontain'].get('totalDuration', 0) / 60, 2)

                            created_str = ticket.get('created', '')
                            created_et = ''
                            if created_str:
                                try:
                                    created_dt = datetime.fromisoformat(created_str.replace('Z', '+00:00'))
                                    created_et = created_dt.astimezone(eastern).strftime('%Y-%m-%d %H:%M:%S %Z')
                                except:
                                    created_et = created_str

                            inflow_list.append({
                                'id': ticket.get('id', ''),
                                'name': ticket.get('name', ''),
                                'type': ticket.get('type', ''),
                                'owner': ticket.get('owner', ''),
                                'ttr': ttr_minutes,
                                'ttc': ttc_minutes,
                                'created': created_et
                            })

                        # Serialize outflow tickets
                        outflow_list = []
                        for ticket in outflow_tickets:
                            custom_fields = ticket.get('CustomFields', {})
                            closed_str = ticket.get('closed', '')
                            closed_et = ''
                            if closed_str:
                                try:
                                    closed_dt = datetime.fromisoformat(closed_str.replace('Z', '+00:00'))
                                    closed_et = closed_dt.astimezone(eastern).strftime('%Y-%m-%d %H:%M:%S %Z')
                                except:
                                    closed_et = closed_str

                            impact = custom_fields.get('impact', {}).get('simple', 'Unknown') if isinstance(custom_fields.get('impact'), dict) else custom_fields.get('impact', 'Unknown')

                            outflow_list.append({
                                'id': ticket.get('id', ''),
                                'name': ticket.get('name', ''),
                                'type': ticket.get('type', ''),
                                'owner': ticket.get('owner', ''),
                                'closed': closed_et,
                                'impact': impact
                            })

                        # Calculate actual staff from distinct owners in inflow tickets
                        distinct_owners = set()
                        for ticket in inflow_tickets:
                            owner = ticket.get('owner', '').strip()
                            if owner and owner.lower() not in ['', 'unassigned', 'admin']:
                                distinct_owners.add(owner)
                        actual_staff = len(distinct_owners)

                        # Calculate performance score (1-10 scale)
                        # Only measures what analysts control: closed tickets, response/containment times, SLA compliance
                        staff_count = max(actual_staff, 1)  # Avoid division by zero

                        score = 0

                        # Use actual ticket counts from inflow/outflow lists
                        tickets_inflow_count = len(inflow_list)
                        tickets_closed_count = len(outflow_list)

                        # 1. Tickets Closed Productivity (up to 20 points)
                        # Analysts control how efficiently they close tickets
                        tickets_closed_per_analyst = tickets_closed_count / staff_count
                        score += min(tickets_closed_per_analyst * 10, 20)

                        # 2. Backlog Clearing (+10 bonus or -10 penalty)
                        # Analysts control whether they clear backlog by closing >= acknowledged
                        # Low-volume shifts SHOULD use the opportunity to clear backlog
                        if tickets_closed_count >= tickets_inflow_count:
                            score += 10  # Cleared backlog or kept up
                        else:
                            score -= 10  # Failed to keep up or didn't use low volume to clear backlog

                        # 3. Response Time Quality (up to 25 points)
                        avg_response = sla_metrics['avg_response']
                        if avg_response <= 5:  # Excellent: under 5 min
                            score += 25
                        elif avg_response <= 15:  # Good: under 15 min
                            score += 18
                        elif avg_response <= 30:  # Acceptable: under 30 min
                            score += 10
                        # Bad: >30 min gets 0 points

                        # 4. Containment Time Quality (up to 25 points)
                        avg_containment = sla_metrics['avg_containment']
                        if avg_containment <= 30:  # Excellent: under 30 min
                            score += 25
                        elif avg_containment <= 60:  # Good: under 60 min
                            score += 18
                        elif avg_containment <= 120:  # Acceptable: under 2 hours
                            score += 10
                        # Bad: >2 hours gets 0 points

                        # 5. Response SLA Compliance (up to 10 points, -2pts per breach)
                        response_sla_score = 10 - (sla_metrics['response_breaches'] * 2)
                        score += max(0, response_sla_score)

                        # 6. Containment SLA Compliance (up to 10 points, -2pts per breach)
                        containment_sla_score = 10 - (sla_metrics['containment_breaches'] * 2)
                        score += max(0, containment_sla_score)

                        # Cap score between 0 and 100, then convert to 1-10 scale
                        score = max(0, min(100, score))
                        score = max(1, min(10, int(round(score / 10))))

                        shift_data.append({
                            'id': shift_id,
                            'date': date_str,
                            'day': day_name,
                            'shift': shift_name.title(),
                            'total_staff': total_staff,
                            'actual_staff': actual_staff,
                            'status': status,
                            'tickets_inflow': len(inflow_list),  # Use actual inflow ticket count
                            'tickets_closed': len(outflow_list),  # Use actual outflow ticket count
                            # Override with derived averages (minutes already)
                            'response_time_minutes': sla_metrics['avg_response'],
                            'contain_time_minutes': sla_metrics['avg_containment'],
                            'response_sla_breaches': sla_metrics['response_breaches'],
                            'containment_sla_breaches': sla_metrics['containment_breaches'],
                            'security_actions': security_actions,
                            'mtp_ticket_ids': ', '.join(map(str, mtp_ids)),
                            'inflow_tickets': inflow_list,
                            'outflow_tickets': outflow_list,
                            # Staffing details for modal
                            'shift_lead': shift_lead,
                            'basic_staffing': basic_staffing,
                            'detailed_staffing': detailed_staffing,
                            # Performance score
                            'score': score
                        })
                except Exception as e:
                    print(f"Error getting staffing or metrics for {day_name} {shift_name}: {e}")
                    current_shift = secops.get_current_shift()
                    if days_back > 0:
                        show_shift = True
                        status = 'error'
                    elif days_back == 0:
                        if shift_name.lower() == current_shift:
                            show_shift = True
                            status = 'error'
                        elif _shift_has_passed(shift_name.lower(), current_shift):
                            show_shift = True
                            status = 'error'
                        else:
                            show_shift = False
                    else:
                        show_shift = False
                    if show_shift:
                        shift_id = f"{date_str}_{shift_name}"
                        shift_data.append({
                            'id': shift_id,
                            'date': date_str,
                            'day': day_name,
                            'shift': shift_name.title(),
                            'total_staff': 0,
                            'actual_staff': 0,
                            'status': status,
                            'tickets_inflow': 0,
                            'tickets_closed': 0,
                            'response_time_minutes': 0,
                            'contain_time_minutes': 0,
                            'response_sla_breaches': 0,
                            'containment_sla_breaches': 0,
                            'mtp_ticket_ids': '',
                            'inflow_tickets': [],
                            'outflow_tickets': [],
                            'shift_lead': 'N/A',
                            'basic_staffing': {'total_staff': 0, 'teams': {}},
                            'detailed_staffing': {},
                            'security_actions': {'iocs_blocked': 0, 'domains_blocked': 0, 'malicious_true_positives': 0},
                            'score': 0
                        })
        result = {'success': True, 'data': shift_data}
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/clear-cache', methods=['POST'])
@log_web_activity
def clear_shift_cache():
    """No-op endpoint for compatibility with frontend cache clearing.
    Backend caching has been removed - only frontend localStorage cache exists."""
    return jsonify({'success': True, 'message': 'No backend cache (frontend-only caching)'})




# Helper to robustly extract SLA metrics from inflow tickets
# Adaptive: totalDuration could be minutes, seconds, or milliseconds.
# Heuristic conversion order:
#   >= 3,600,000 -> treat as milliseconds (divide by 60,000)
#   >= 600       -> treat as seconds (divide by 60)
#   else         -> treat as minutes already
# Breach detection only checks breachTriggered.
def _extract_sla_metrics(tickets):
    """Compute SLA metrics (MTTR / MTTC averages & breach counts) from tickets.

    Fixes prior incorrect heuristic that treated small second-based durations as minutes.
    Assumptions:
      - totalDuration fields are primarily in SECONDS (as evidenced by typical small values like 57)
      - Some edge cases may surface durations in milliseconds (large numbers > 3_600_000 and divisible by 1000)
    We normalize:
      seconds -> minutes via /60
      milliseconds -> minutes via /1000/60
    We log per-ticket debug information for diagnostics.
    """

    def _duration_to_minutes(raw):
        if not isinstance(raw, (int, float)) or raw <= 0:
            return None, None
        # Detect millisecond values (very large and divisible by 1000) to avoid inflating minutes incorrectly
        if raw >= 3_600_000 and raw % 1000 == 0:  # >= 1 hour expressed in ms
            minutes = raw / 1000.0 / 60.0
            unit = 'ms'
        else:
            minutes = raw / 60.0  # treat as seconds
            unit = 's'
        return minutes, unit

    response_total_min = 0.0
    response_count = 0
    response_breaches = 0
    contain_total_min = 0.0
    contain_count = 0
    contain_breaches = 0

    for t in tickets:
        cf = t.get('CustomFields', {}) or {}
        ticket_id = t.get('id', 'UNKNOWN')

        # Prefer explicit timetorespond but allow legacy responsesla fallback
        resp_obj = cf.get('timetorespond') or cf.get('responsesla')
        cont_obj = None
        # Only evaluate containment for host-based tickets
        if cf.get('hostname'):
            cont_obj = cf.get('timetocontain') or cf.get('containmentsla')

        raw_resp = raw_cont = None
        resp_min = cont_min = None
        resp_unit = cont_unit = None

        if isinstance(resp_obj, dict):
            raw_resp = resp_obj.get('totalDuration')
            resp_min, resp_unit = _duration_to_minutes(raw_resp)
            if resp_min is not None:
                response_total_min += resp_min
                response_count += 1
            if str(resp_obj.get('breachTriggered')).lower() == 'true':
                response_breaches += 1

        if isinstance(cont_obj, dict):
            raw_cont = cont_obj.get('totalDuration')
            cont_min, cont_unit = _duration_to_minutes(raw_cont)
            if cont_min is not None:
                contain_total_min += cont_min
                contain_count += 1
            if str(cont_obj.get('breachTriggered')).lower() == 'true':
                contain_breaches += 1

        # Debug logging per ticket
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                "SLA_METRICS ticket=%s resp_raw=%s%s resp_min=%.3f cont_raw=%s%s cont_min=%.3f has_hostname=%s resp_breach=%s cont_breach=%s",
                ticket_id,
                raw_resp if raw_resp is not None else '-',
                f"{resp_unit}" if resp_unit else '',
                resp_min if resp_min is not None else -1,
                raw_cont if raw_cont is not None else '-',
                f"{cont_unit}" if cont_unit else '',
                cont_min if cont_min is not None else -1,
                bool(cf.get('hostname')),
                str(resp_obj.get('breachTriggered')) if isinstance(resp_obj, dict) else '-',
                str(cont_obj.get('breachTriggered')) if isinstance(cont_obj, dict) else '-'
            )

    avg_response = round(response_total_min / response_count, 2) if response_count else 0.0
    avg_contain = round(contain_total_min / contain_count, 2) if contain_count else 0.0

    # Final aggregate debug summary
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(
            "SLA_METRICS_SUMMARY resp_count=%d resp_total_min=%.3f avg_resp=%.2f cont_count=%d cont_total_min=%.3f avg_cont=%.2f resp_breaches=%d cont_breaches=%d",
            response_count, response_total_min, avg_response,
            contain_count, contain_total_min, avg_contain,
            response_breaches, contain_breaches
        )

    return {
        'avg_response': avg_response,  # MTTR in minutes
        'avg_containment': avg_contain,  # MTTC in minutes
        'response_breaches': response_breaches,
        'containment_breaches': contain_breaches
    }


@app.route('/meaningful-metrics')
@log_web_activity
def meaningful_metrics():
    """Meaningful Metrics Dashboard"""
    return render_template('meaningful_metrics.html')


@app.route('/api/meaningful-metrics/data')
@log_web_activity
def api_meaningful_metrics_data():
    """API to get cached security incident data for dashboard"""
    import json
    from pathlib import Path

    try:
        # Load cached data
        today_date = datetime.now().strftime('%m-%d-%Y')
        root_directory = Path(__file__).parent.parent
        cache_file = root_directory / "web" / "static" / "charts" / today_date / "past_90_days_tickets.json"

        if not cache_file.exists():
            return jsonify({'success': False, 'error': 'Cache file not found'}), 404

        with open(cache_file, 'r') as f:
            cached_data = json.load(f)

        # Check if data is in new format (with metadata) or old format (just array)
        if isinstance(cached_data, dict) and 'data' in cached_data:
            # New format: already has metadata including data_generated_at
            return jsonify({
                'success': True,
                'data': cached_data['data'],
                'total_count': cached_data.get('total_count', len(cached_data['data'])),
                'data_generated_at': cached_data.get('data_generated_at')
            })
        else:
            # Old format: just the array of tickets (fallback)
            return jsonify({
                'success': True,
                'data': cached_data,
                'total_count': len(cached_data),
                'data_generated_at': None  # Will use fallback in frontend
            })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route("/healthz")
def healthz():
    """Lightweight health probe endpoint for load balancers / monitoring."""
    try:
        # Use timezone-aware UTC datetime (portable across Python versions)
        ts = datetime.now(timezone.utc)
        # Represent in RFC3339 style with trailing Z
        timestamp = ts.isoformat().replace('+00:00', 'Z')
        return jsonify({
            "status": "ok",
            "timestamp": timestamp,
            "team": getattr(CONFIG, 'team_name', 'unknown'),
            "service": "ir_web_server"
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


def main():
    """Entry point for launching the web server.

    Supports configuration via CLI args or environment variables:
      --host / WEB_HOST (default 0.0.0.0 for LAN access)
      --port / WEB_PORT (default 8080)
      --proxy flag enables internal proxy (default disabled)
    """
    parser = argparse.ArgumentParser(description="IR Web Server")
    parser.add_argument("--host", default=os.environ.get("WEB_HOST", "0.0.0.0"), help="Host/IP to bind (default 0.0.0.0 for network access)")
    parser.add_argument("--port", type=int, default=int(os.environ.get("WEB_PORT", "8080")), help="Port to bind (default 8080)")
    parser.add_argument("--proxy", action="store_true", help="Enable internal proxy component")
    args = parser.parse_args()

    charts_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'static/charts'))
    app.config['CHARTS_DIR'] = charts_dir

    # Decide if proxy should start
    start_proxy = args.proxy or (os.environ.get("START_PROXY", "false").lower() == "true")

    # Only start proxy server in main process (not in reloader child process) and if enabled
    if start_proxy and os.environ.get('WERKZEUG_RUN_MAIN') != 'true':
        proxy_thread = threading.Thread(target=start_proxy_server, daemon=True)
        proxy_thread.start()
        print(f"High-performance proxy server thread started on port {PROXY_PORT}")
    elif not start_proxy:
        print(f"Proxy server disabled (pass --proxy to enable)")

    port = args.port
    host = args.host

    print(f"Attempting to start web server on http://{host}:{port}")

    if USE_DEBUG_MODE:
        print("Using Flask dev server with auto-reload (debug mode)")
        try:
            app.run(debug=True, host=host, port=port, threaded=True, use_reloader=True)
        except OSError as e:
            if port < 1024 and e.errno == 13:
                fallback_port = 8080
                print(f"Permission denied binding to port {port}. Falling back to {fallback_port}. (Run with sudo or grant capability to use {port}).")
                app.run(debug=True, host=host, port=fallback_port, threaded=True, use_reloader=True)
            else:
                raise
    else:
        try:
            from waitress import serve
            print("Using Waitress WSGI server for production deployment")
            try:
                serve(app, host=host, port=port, threads=20, channel_timeout=120)
            except OSError as e:
                # Permission denied for privileged port without sudo/capability
                if port < 1024 and e.errno == 13:  # Permission denied
                    fallback_port = 8080
                    print(f"Permission denied binding to port {port}. Falling back to {fallback_port}. (Run with sudo or grant cap_net_bind_service to use {port}).")
                    serve(app, host=host, port=fallback_port, threads=20, channel_timeout=120)
                else:
                    raise
        except ImportError:
            print("Waitress not available, falling back to Flask dev server")
            try:
                app.run(debug=True, host=host, port=port, threaded=True, use_reloader=True)
            except OSError as e:
                if port < 1024 and e.errno == 13:
                    fallback_port = 8080
                    print(f"Permission denied binding to port {port}. Falling back to {fallback_port}. (Run with sudo or grant capability to use {port}).")
                    app.run(debug=True, host=host, port=fallback_port, threaded=True, use_reloader=True)
                else:
                    raise


if __name__ == "__main__":
    main()
