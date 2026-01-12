"""Admin Blueprint for NETSCOPE administration interface."""

from flask import Blueprint

admin_bp = Blueprint('admin', __name__)

from app.blueprints.admin import routes  # noqa: E402, F401
