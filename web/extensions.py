"""
Shared Flask extensions.

Instantiated here (without an app) so they can be imported by both
app.py and individual route blueprints. Bound to the app via
``limiter.init_app(app)`` in app.py.
"""

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(key_func=get_remote_address, default_limits=[])
