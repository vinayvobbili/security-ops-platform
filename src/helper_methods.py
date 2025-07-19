from pathlib import Path

from pytz import timezone

from config import get_config

eastern = timezone('US/Eastern')

config = get_config()

root_directory = Path(__file__).parent.parent
LOG_FILE_DIR = root_directory / 'data' / 'transient' / 'logs'
CHARTS_DIR_PATH = root_directory / 'web' / 'static' / 'charts'

# The following helpers have been moved to src/utils/logging_utils.py and src/utils/fs_utils.py
# from src.utils.logging_utils import log_activity
# from src.utils.fs_utils import make_dir_for_todays_charts

# You can import and re-export or just update all usages in the codebase to use the new modules.
