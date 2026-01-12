"""Gunicorn configuration for NETSCOPE production deployment."""

# Server socket
bind = '0.0.0.0:80'

# Worker processes
workers = 2
worker_class = 'sync'

# Timeout
timeout = 120

# Logging
accesslog = '-'
errorlog = '-'
loglevel = 'info'
