"""API Blueprint for NETSCOPE REST endpoints."""

from flask import Blueprint

api_bp = Blueprint('api', __name__)

from app.blueprints.api import routes  # noqa: E402, F401
from app.blueprints.api import network  # noqa: E402, F401
from app.blueprints.api import captures  # noqa: E402, F401
from app.blueprints.api import blacklists  # noqa: E402, F401
from app.blueprints.api import anomalies  # noqa: E402, F401
from app.blueprints.api import analysis  # noqa: E402, F401
from app.blueprints.api import health  # noqa: E402, F401  # Story 3.2
from app.blueprints.api import whitelist  # noqa: E402, F401  # Story 3.6
from app.blueprints.api import jobs  # noqa: E402, F401  # Story 4.1
from app.blueprints.api import packets  # noqa: E402, F401  # Story 4.4
from app.blueprints.api import system  # noqa: E402, F401  # Story 4.7
from app.blueprints.api import captive  # noqa: E402, F401  # Story 4b.1
from app.blueprints.api import exports  # noqa: E402, F401  # Story 5.1
