"""Captive portal routes for NETSCOPE.

Intercepts HTTP requests from unreleased captive clients,
handles OS-specific captive portal detection URLs, and serves
the captive portal page.
"""

import logging

from flask import Response, redirect, render_template, request, url_for

from . import captive_bp
from .captive_manager import get_captive_manager

logger = logging.getLogger(__name__)

# Captive portal detection hostnames (used for released client responses)
_ANDROID_HOSTS = frozenset({
    'connectivitycheck.gstatic.com',
    'clients3.google.com',
})
_APPLE_HOSTS = frozenset({'captive.apple.com'})
_WINDOWS_HOSTS = frozenset({
    'www.msftconnecttest.com',
    'msftconnecttest.com',
})
_FIREFOX_HOSTS = frozenset({'detectportal.firefox.com'})


@captive_bp.before_app_request
def captive_intercept():
    """Intercept requests from unreleased captive clients.

    Runs before every request. Checks if captive mode is active
    and if the client has been released. Unreleased clients are
    redirected to the captive portal page. Released clients get
    OS-native "no portal" responses on captive check URLs.
    """
    manager = get_captive_manager()
    client_ip = request.remote_addr
    path = request.path

    # Skip captive and API captive endpoints (avoid redirect loop)
    if path.startswith('/captive/') or path.startswith('/api/captive/'):
        return None

    # Skip static files
    if path.startswith('/static/'):
        return None

    # Released client — always return OS-native success on captive check
    # URLs, even after captive is globally disabled (OS re-verifies)
    if manager.is_released(client_ip):
        response = _released_captive_response()
        if response is not None:
            return response
        return None

    # If captive mode is globally inactive, no interception needed
    if not manager.is_captive_active():
        return None

    # Never redirect localhost to portal (tests, local access)
    if client_ip in ('127.0.0.1', '::1'):
        return None

    # Unreleased client — redirect to portal
    logger.info(
        'Captive intercept: redirecting %s to portal (path=%s)',
        client_ip,
        path,
    )
    return redirect(url_for('captive.portal'), code=302)


def _released_captive_response():
    """Return OS-native 'no portal' response for released clients.

    Returns:
        A response tuple if the request is a captive check URL,
        None otherwise (let Flask handle normally).
    """
    host = request.host.split(':')[0].lower()
    path = request.path.lower()

    # Android: expects HTTP 204 No Content
    if host in _ANDROID_HOSTS or path == '/generate_204':
        return Response('', status=204)

    # Apple: expects specific HTML body with "Success"
    if host in _APPLE_HOSTS or path == '/hotspot-detect.html':
        return Response(
            '<HTML><HEAD><TITLE>Success</TITLE></HEAD>'
            '<BODY>Success</BODY></HTML>',
            status=200,
            content_type='text/html',
        )

    # Windows: expects body "Microsoft Connect Test" as plain text
    if host in _WINDOWS_HOSTS or path == '/connecttest.txt':
        return Response(
            'Microsoft Connect Test',
            status=200,
            content_type='text/plain',
        )

    # Firefox: expects body containing "success"
    if host in _FIREFOX_HOSTS or path == '/canonical.html':
        return Response(
            '<meta http-equiv="refresh" content="0;url='
            'https://support.mozilla.org/kb/captive-portal"/>',
            status=200,
            content_type='text/html',
        )

    return None


@captive_bp.route('/portal')
def portal():
    """Serve the captive portal welcome page.

    Shows NETSCOPE branding and a "Continue to Internet" button.
    Released clients are redirected to the main dashboard.
    """
    client_ip = request.remote_addr
    manager = get_captive_manager()

    if manager.is_released(client_ip):
        return redirect(url_for('dashboard.index'))

    return render_template('portal.html', client_ip=client_ip)
