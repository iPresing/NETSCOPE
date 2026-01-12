"""API Blueprint for NETSCOPE REST endpoints."""

from flask import Blueprint

api_bp = Blueprint('api', __name__)

from app.blueprints.api import routes  # noqa: E402, F401
from app.blueprints.api import network  # noqa: E402, F401
