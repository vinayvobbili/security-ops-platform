import subprocess
import sys


def run_in_new_window(module_name):
    """Runs the specified module in a new terminal window."""
    if sys.platform == 'darwin':  # macOS
        command = ['osascript', '-e', f'tell application "Terminal" to do script "python -m {module_name}"']
    elif sys.platform == 'linux':
        command = ['gnome-terminal', '--', 'python', '-m', module_name]
    elif sys.platform == 'win32':
        command = ['start', 'cmd', '/k', 'python', '-m', module_name]
    else:
        raise OSError(f"Unsupported operating system: {sys.platform}")
    subprocess.Popen(command)


run_in_new_window('web.web_server')
run_in_new_window('scheduled_jobs')
run_in_new_window('money_ball')
