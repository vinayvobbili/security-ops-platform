#!/usr/bin/python3

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

from my_bot.core.my_model import ask, ask_stream
from my_bot.core.state_manager import get_state_manager
from my_config import get_config
from services import xsoar
from services.approved_testing_utils import add_approved_testing_entry
from src import secops
from src.components import apt_names_fetcher, secops_shift_metrics
from src.utils.logging_utils import log_web_activity, is_scanner_request

CONFIG = get_config()

SHOULD_START_PROXY = False
USE_DEBUG_MODE = CONFIG.web_server_debug_mode_on
PROXY_PORT = 9000
WEB_SERVER_PORT = 80
BUFFER_SIZE = 16384
NUM_WORKERS = 10
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
        # f"charts/{today_date}/Inflow Past 60 Days.png",
        f"charts/{today_date}/Inflow Past 12 Months - Impact Only.png",
        f"charts/{today_date}/Inflow Past 12 Months - Ticket Type Only.png",
        f"charts/{today_date}/Outflow.png",
        f"charts/{today_date}/SLA Breaches.png",
        f"charts/{today_date}/MTTR MTTC.png",
        f"charts/{today_date}/Heat Map.png",
        # f"charts/{today_date}/CrowdStrike Detection Efficacy-Quarter.png",
        # f"charts/{today_date}/CrowdStrike Detection Efficacy-Month.png",
        f"charts/{today_date}/CrowdStrike Detection Efficacy-Week.png",
        # f"charts/{today_date}/QR Rule Efficacy-Quarter.png",
        # f"charts/{today_date}/QR Rule Efficacy-Month.png",
        f"charts/{today_date}/QR Rule Efficacy-Week.png",
        f"charts/{today_date}/Vectra Volume.png",
        # f"charts/{today_date}/CrowdStrike Volume.png",
        # f"charts/{today_date}/Lifespan.png",
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


@app.route('/pokedex-chat')
@log_web_activity
def pokedex_chat():
    """Pokedex AI chat interface"""
    return render_template('pokedex_chat.html')


@app.route('/api/pokedex-status')
def api_pokedex_status():
    """Health check endpoint for Pokédex chat availability"""
    try:

        state_manager = get_state_manager()

        if not state_manager or not state_manager.is_initialized:
            return jsonify({
                'ready': False,
                'status': 'not_initialized',
                'message': 'Pokedex chat is not available. Please ensure all components are initialized.',
                'instructions': [
                    'Restart the web server with ENABLE_POKEDEX_CHAT = True'
                ]
            })

        # Perform health check
        health = state_manager.health_check()
        components = health.get('components', {})

        # Check if core LLM components are working (LLM and embeddings)
        # RAG is optional - chat works fine without it
        core_ready = components.get('llm', False) and components.get('embeddings', False)

        if health.get('status') == 'initialized':
            return jsonify({
                'ready': True,
                'status': 'healthy',
                'message': 'Pokedex chat is ready',
                'components': components
            })
        elif core_ready:
            # LLM works, but RAG might be missing - still usable!
            return jsonify({
                'ready': True,
                'status': 'partial',
                'message': 'Pokedex chat is ready (without document search)',
                'components': components
            })
        else:
            return jsonify({
                'ready': False,
                'status': 'partial',
                'message': 'Pokedex chat core components not ready',
                'components': components
            })

    except Exception as e:
        logger.error(f"Error checking Pokedex status: {e}")
        return jsonify({
            'ready': False,
            'status': 'error',
            'message': 'Error checking chat status',
            'error': str(e)
        })


@app.route('/api/pokedex-chat', methods=['POST'])
@log_web_activity
def api_pokedex_chat():
    """API endpoint for Pokedex chat messages"""
    try:
        data = request.get_json()
        user_message = data.get('message', '').strip()
        session_id = data.get('session_id', '')

        if not user_message:
            return jsonify({'success': False, 'error': 'Message is required'}), 400

        if not session_id:
            return jsonify({'success': False, 'error': 'Session ID is required'}), 400

        # Use IP address + session ID as identifier for context management
        # This mimics how Webex bot uses person_id + room_id
        user_ip = request.remote_addr
        user_identifier = f"web_{user_ip}_{session_id}"

        # Use the ask function to get LLM response
        # The ask function handles conversation context via session management
        try:
            response_text = ask(
                user_message,
                user_id=user_identifier,
                room_id="web_chat"  # Use a common room_id for web chats
            )
        except Exception as e:
            logger.error(f"Error getting LLM response: {e}", exc_info=True)
            return jsonify({
                'success': False,
                'error': 'Failed to get response from AI. Please try again.'
            }), 500

        return jsonify({
            'success': True,
            'response': response_text
        })

    except Exception as e:
        logger.error(f"Error in Pokedex chat API: {e}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'An unexpected error occurred. Please try again.'
        }), 500


@app.route('/api/pokedex-chat-stream', methods=['POST'])
@log_web_activity
def api_pokedex_chat_stream():
    """Streaming API endpoint for Pokédex chat messages using Server-Sent Events"""
    try:
        data = request.get_json()
        user_message = data.get('message', '').strip()
        session_id = data.get('session_id', '')

        if not user_message:
            return jsonify({'success': False, 'error': 'Message is required'}), 400

        if not session_id:
            return jsonify({'success': False, 'error': 'Session ID is required'}), 400

        # Use IP address + session ID as identifier
        user_ip = request.remote_addr
        user_identifier = f"web_{user_ip}_{session_id}"

        def generate():
            """Generator function for Server-Sent Events"""
            try:
                for token in ask_stream(
                        user_message,
                        user_id=user_identifier,
                        room_id="web_chat"
                ):
                    # Format as Server-Sent Event
                    yield f"data: {json.dumps({'token': token})}\n\n"

                # Send completion event
                yield f"data: {json.dumps({'done': True})}\n\n"

            except Exception as e:
                logger.error(f"Error in streaming response: {e}", exc_info=True)
                yield f"data: {json.dumps({'error': 'Streaming error occurred'})}\n\n"

        # Return SSE response
        return app.response_class(
            generate(),
            mimetype='text/event-stream',
            headers={
                'Cache-Control': 'no-cache',
                'X-Accel-Buffering': 'no',  # Disable buffering in nginx
                'Connection': 'keep-alive'
            }
        )

    except Exception as e:
        logger.error(f"Error in Pokedex streaming chat API: {e}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'An unexpected error occurred. Please try again.'
        }), 500


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
                        # Get staffing and security actions
                        shift_hour_map = {'morning': 4.5, 'afternoon': 12.5, 'night': 20.5}
                        shift_start_hour = shift_hour_map.get(shift_name.lower(), 4.5)
                        security_actions = secops.get_shift_security_actions(days_back, shift_start_hour)

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

                        # Calculate all shift metrics using the component
                        base_date = datetime(target_date.year, target_date.month, target_date.day)
                        metrics = secops_shift_metrics.get_shift_metrics(
                            date_obj=base_date,
                            shift_name=shift_name,
                            ticket_handler=incident_handler,
                            day_name=day_name,
                            total_staff=total_staff,
                            security_actions=security_actions,
                            shift_lead=shift_lead,
                            basic_staffing=basic_staffing,
                            detailed_staffing=detailed_staffing
                        )

                        # Build shift data entry
                        shift_data.append({
                            'id': shift_id,
                            'date': date_str,
                            'day': metrics['day'],
                            'shift': shift_name.title(),
                            'total_staff': metrics['total_staff'],
                            'actual_staff': metrics['actual_staff'],
                            'status': status,
                            'tickets_acknowledged': metrics['tickets_acknowledged'],
                            'tickets_closed': metrics['tickets_closed'],
                            'response_time_minutes': metrics['response_time_minutes'],
                            'contain_time_minutes': metrics['contain_time_minutes'],
                            'response_sla_breaches': metrics['response_sla_breaches'],
                            'containment_sla_breaches': metrics['containment_sla_breaches'],
                            'security_actions': metrics['security_actions'],
                            'mtp_ticket_ids': metrics['mtp_ticket_ids'],
                            'inflow_tickets': metrics['inflow_tickets'],
                            'outflow_tickets': metrics['outflow_tickets'],
                            'shift_lead': metrics['shift_lead'],
                            'basic_staffing': metrics['basic_staffing'],
                            'detailed_staffing': metrics['detailed_staffing'],
                            'score': metrics['score']
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
                            'tickets_acknowledged': 0,
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

    # Initialize Pokédex bot components
    try:
        print("🤖 Initializing Pokedex chat components...")
        from my_bot.core.my_model import initialize_model_and_agent
        if initialize_model_and_agent():
            print("✅ Pokedex chat components initialized!")

            # Warm up the model to preload it into memory
            print("🔥 Warming up LLM (this will load the model into memory)...")
            state_manager = get_state_manager()
            if state_manager.fast_warmup():
                print("✅ LLM warmed up and ready! Model is now loaded in memory.")
            else:
                print("⚠️ LLM warmup failed - model will load on first request")
        else:
            print("⚠️ Pokedex chat initialization failed - chat endpoint will return errors")
    except Exception as e:
        print(f"⚠️ Failed to initialize Pokedex chat: {e}")
        print("   Chat endpoint will be available but may return errors")

    charts_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'static/charts'))
    app.config['CHARTS_DIR'] = charts_dir

    host = '0.0.0.0'
    port = WEB_SERVER_PORT

    # Only start proxy server in main process (not in reloader child process) and if enabled
    if SHOULD_START_PROXY and os.environ.get('WERKZEUG_RUN_MAIN') != 'true':
        proxy_thread = threading.Thread(target=start_proxy_server, daemon=True)
        proxy_thread.start()
        print(f"High-performance proxy server thread started on port {PROXY_PORT}")
    elif not SHOULD_START_PROXY:
        print(f"Proxy server disabled (pass --proxy to enable)")

    print(f"Attempting to start web server on http://{host}:{WEB_SERVER_PORT}")

    if USE_DEBUG_MODE:
        print("Using Flask dev server with auto-reload (debug mode)")
        try:
            app.run(debug=True, host=host, port=WEB_SERVER_PORT, threaded=True, use_reloader=True)
        except OSError as e:
            if WEB_SERVER_PORT < 1024 and e.errno == 13:
                fallback_port = 8080
                print(f"Permission denied binding to port {WEB_SERVER_PORT}. Falling back to {fallback_port}. (Run with sudo or grant capability to use {WEB_SERVER_PORT}).")
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
