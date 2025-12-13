#!/usr/bin/env python3
"""
Simple web-based log viewer with real-time streaming.
Displays logs in full like 'tail -f' with color-coded log levels.
"""

import os
import sys
import argparse
import subprocess
import threading
import queue
import logging
from collections import deque
from functools import wraps
from typing import Optional
from flask import Flask, Response, render_template_string, request

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Global variables
log_queue: queue.Queue = queue.Queue(maxsize=1000)
recent_lines: deque = deque(maxlen=300)  # Buffer of last 300 lines for new connections
recent_lines_lock = threading.Lock()  # Protect the recent_lines buffer
log_source_cmd: Optional[list[str]] = None
auth_password: str = "metcirt"
viewer_title: str = "Log Viewer"

# HTML template with inline CSS
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Monaco', 'Menlo', 'Consolas', monospace;
            background: #1e1e1e;
            color: #d4d4d4;
            overflow: hidden;
        }

        .header {
            background: #252526;
            padding: 12px 20px;
            border-bottom: 1px solid #3e3e42;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .header h1 {
            font-size: 18px;
            color: #cccccc;
            font-weight: 500;
        }

        .header .info {
            font-size: 12px;
            color: #858585;
        }

        .log-container {
            height: calc(100vh - 49px);
            overflow-y: auto;
            padding: 16px;
            font-size: 13px;
            line-height: 1.6;
        }

        .log-line {
            white-space: pre-wrap;
            word-wrap: break-word;
            padding: 2px 0;
            border-bottom: 1px solid transparent;
        }

        .log-line:hover {
            background: #2a2d2e;
            border-bottom: 1px solid #3e3e42;
        }

        /* Log level color coding */
        .log-error {
            color: #f48771;
            background: rgba(244, 135, 113, 0.1);
        }

        .log-warning {
            color: #dcdcaa;
            background: rgba(220, 220, 170, 0.1);
        }

        .log-info {
            color: #4ec9b0;
        }

        .log-debug {
            color: #858585;
        }

        .log-trace {
            color: #6a6a6a;
        }

        /* Scrollbar styling */
        .log-container::-webkit-scrollbar {
            width: 10px;
        }

        .log-container::-webkit-scrollbar-track {
            background: #1e1e1e;
        }

        .log-container::-webkit-scrollbar-thumb {
            background: #424242;
            border-radius: 5px;
        }

        .log-container::-webkit-scrollbar-thumb:hover {
            background: #4e4e4e;
        }

        /* Connection status */
        .status {
            position: fixed;
            top: 60px;
            right: 20px;
            padding: 8px 16px;
            border-radius: 4px;
            font-size: 12px;
            background: #1e1e1e;
            border: 1px solid #3e3e42;
            z-index: 1000;
        }

        .status.connected {
            color: #4ec9b0;
        }

        .status.disconnected {
            color: #f48771;
        }

        .status.connecting {
            color: #dcdcaa;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{ title }}</h1>
        <div class="info">Press Ctrl+F to search | Auto-scrolling enabled</div>
    </div>
    <div id="status" class="status connecting">Connecting...</div>
    <div class="log-container" id="logContainer"></div>

    <script>
        const logContainer = document.getElementById('logContainer');
        const statusEl = document.getElementById('status');
        let autoScroll = true;
        let eventSource;

        // Check if user is scrolling manually
        logContainer.addEventListener('scroll', () => {
            const { scrollTop, scrollHeight, clientHeight } = logContainer;
            autoScroll = (scrollTop + clientHeight >= scrollHeight - 50);
        });

        // Color-code log line based on content
        function colorCodeLine(line) {
            const upper = line.toUpperCase();
            if (upper.includes('ERROR') || upper.includes('CRITICAL') || upper.includes('FATAL')) {
                return 'log-error';
            } else if (upper.includes('WARNING') || upper.includes('WARN')) {
                return 'log-warning';
            } else if (upper.includes('INFO')) {
                return 'log-info';
            } else if (upper.includes('DEBUG')) {
                return 'log-debug';
            } else if (upper.includes('TRACE')) {
                return 'log-trace';
            }
            return '';
        }

        // Add log line to display
        function addLogLine(line) {
            if (!line || line.trim() === '') return;

            const logLine = document.createElement('div');
            logLine.className = 'log-line ' + colorCodeLine(line);
            logLine.textContent = line;
            logContainer.appendChild(logLine);

            // Keep only last 5000 lines to prevent memory issues
            const lines = logContainer.children;
            if (lines.length > 5000) {
                logContainer.removeChild(lines[0]);
            }

            // Auto-scroll if enabled
            if (autoScroll) {
                logContainer.scrollTop = logContainer.scrollHeight;
            }
        }

        // Connect to SSE stream
        function connect() {
            statusEl.textContent = 'Connecting...';
            statusEl.className = 'status connecting';

            eventSource = new EventSource('/stream');

            eventSource.onopen = () => {
                statusEl.textContent = 'Connected - Live';
                statusEl.className = 'status connected';
                console.log('Connected to log stream');
            };

            eventSource.onmessage = (event) => {
                addLogLine(event.data);
            };

            eventSource.onerror = (error) => {
                statusEl.textContent = 'Disconnected - Reconnecting...';
                statusEl.className = 'status disconnected';
                console.error('Connection error:', error);
                eventSource.close();

                // Reconnect after 3 seconds
                setTimeout(connect, 3000);
            };
        }

        // Start connection
        connect();

        // Cleanup on page unload
        window.addEventListener('beforeunload', () => {
            if (eventSource) {
                eventSource.close();
            }
        });
    </script>
</body>
</html>
"""


def check_auth(username, password):
    """Check if username/password combination is valid."""
    return username == "metcirt" and password == auth_password


def authenticate():
    """Send 401 response for authentication."""
    return Response(
        'Authentication required',
        401,
        {'WWW-Authenticate': 'Basic realm="IR Logs"'}
    )


def requires_auth(f):
    """Decorator to require HTTP Basic Auth."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated


def read_log_stream():
    """
    Start subprocess to tail logs and feed into queue.
    Runs in background thread.
    """
    if log_source_cmd is None:
        logger.error("log_source_cmd is not set")
        return

    try:
        logger.info(f"Starting log stream: {' '.join(log_source_cmd)}")

        # Start subprocess with line buffering
        process = subprocess.Popen(
            log_source_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=1,
            universal_newlines=True
        )

        # Read lines and put into queue and recent_lines buffer
        for line in iter(process.stdout.readline, ''):
            if line:
                stripped_line = line.rstrip('\n')

                # Add to recent lines buffer (for new connections)
                with recent_lines_lock:
                    recent_lines.append(stripped_line)

                # Add to queue (for active streaming connections)
                try:
                    log_queue.put(stripped_line, block=False)
                except queue.Full:
                    # Drop the oldest line if queue is full
                    try:
                        log_queue.get_nowait()
                        log_queue.put(stripped_line, block=False)
                    except:
                        pass

        process.stdout.close()
        process.wait()

    except Exception as e:
        logger.error(f"Error in log stream: {e}")


@app.route('/')
@requires_auth
def index():
    """Serve the log viewer page."""
    return render_template_string(HTML_TEMPLATE, title=viewer_title)


@app.route('/stream')
@requires_auth
def stream():
    """Server-Sent Events endpoint for log streaming."""
    def generate():
        """Generator function for SSE."""
        # Send initial connection message
        yield f"data: === Connected to {viewer_title} ===\n\n"

        # Send buffered recent lines first (so new connections see history)
        with recent_lines_lock:
            buffered_lines = list(recent_lines)

        for line in buffered_lines:
            yield f"data: {line}\n\n"

        # Now stream new log lines in real-time
        while True:
            try:
                line = log_queue.get(timeout=1)
                yield f"data: {line}\n\n"
            except queue.Empty:
                # Send keepalive comment every second
                yield ": keepalive\n\n"
            except Exception as e:
                logger.error(f"Error streaming logs: {e}")
                break

    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no'
        }
    )


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Simple web-based log viewer')

    parser.add_argument(
        '--port',
        type=int,
        required=True,
        help='Port to run the web server on'
    )

    parser.add_argument(
        '--title',
        type=str,
        required=True,
        help='Title for the log viewer page'
    )

    parser.add_argument(
        '--password',
        type=str,
        default='metcirt',
        help='Password for HTTP Basic Auth (default: metcirt)'
    )

    # Log source options - must specify one
    source_group = parser.add_mutually_exclusive_group(required=True)

    source_group.add_argument(
        '--file',
        type=str,
        help='Path to log file to tail'
    )

    source_group.add_argument(
        '--journalctl',
        type=str,
        help='Journalctl unit pattern (e.g., "ir-*" for all IR services)'
    )

    return parser.parse_args()


def main():
    """Main entry point."""
    global log_source_cmd, auth_password, viewer_title

    args = parse_args()

    # Set global config
    auth_password = args.password
    viewer_title = args.title

    # Build log source command
    if args.file:
        if not os.path.exists(args.file):
            logger.error(f"Log file does not exist: {args.file}")
            sys.exit(1)
        # Use -F to follow file even if it's recreated/truncated, increased buffer to 200
        log_source_cmd = ['tail', '-F', '-n', '200', args.file]
        logger.info(f"Tailing log file: {args.file}")

    elif args.journalctl:
        log_source_cmd = [
            'journalctl',
            '-u', args.journalctl,
            '-f',
            '--no-hostname',
            '--output=short',
            '-n', '100'
        ]
        logger.info(f"Tailing journalctl for: {args.journalctl}")

    # Start log reader thread
    log_thread = threading.Thread(target=read_log_stream, daemon=True)
    log_thread.start()

    # Start Flask app
    logger.info(f"Starting log viewer on http://0.0.0.0:{args.port}")
    logger.info(f"Title: {viewer_title}")
    logger.info(f"Auth: username=metcirt, password={auth_password}")

    try:
        # Use Flask's built-in server (fine for internal use with 7 viewers)
        app.run(
            host='0.0.0.0',
            port=args.port,
            debug=False,
            threaded=True
        )
    except KeyboardInterrupt:
        logger.info("Shutting down log viewer")
    except Exception as e:
        logger.error(f"Error running web server: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
