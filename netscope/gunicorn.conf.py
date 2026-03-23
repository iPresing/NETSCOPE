"""Gunicorn configuration for NETSCOPE production deployment."""

# Server socket
bind = '0.0.0.0:80'

# Worker processes
# Un seul worker : le CaptiveManager est un singleton en mémoire,
# plusieurs workers = états désynchronisés (release perdu entre processus).
# Un Pi n'a pas besoin de plus — gthread permet le parallélisme léger.
workers = 1
threads = 2
worker_class = 'gthread'

# Timeout
timeout = 120

# Logging
accesslog = '-'
errorlog = '-'
loglevel = 'info'
