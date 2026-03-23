"""Captive Portal Blueprint for NETSCOPE Wi-Fi probe."""

from flask import Blueprint

captive_bp = Blueprint(
    'captive',
    __name__,
    template_folder='templates'
)

from app.blueprints.captive import routes  # noqa: E402, F401
from app.blueprints.captive import captive_manager  # noqa: E402, F401
