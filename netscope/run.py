"""WSGI entry point for NETSCOPE application."""

import os
from app import create_app

# Use NETSCOPE_CONFIG for configuration selection (FLASK_ENV is deprecated in Flask 3.x)
config_name = os.environ.get('NETSCOPE_CONFIG', 'development')
app = create_app(config_name)

if __name__ == '__main__':
    # Development server - use gunicorn in production
    debug = os.environ.get('FLASK_DEBUG', '0') == '1'
    app.run(host='0.0.0.0', port=5000, debug=debug)
