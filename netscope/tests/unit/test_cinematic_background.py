"""Unit tests for cinematic background system (Story 4.8).

Tests video element, overlay elements, glassmorphism tokens,
and fallback behavior in base.html template rendering.
"""

import pytest


class TestVideoBackgroundElement:
    """Tests for video background presence in rendered HTML (AC1)."""

    def test_render_contains_video_element(self, client):
        """Test that rendered page contains <video> element (AC1)."""
        response = client.get('/')
        html = response.data.decode('utf-8')
        assert '<video' in html
        assert 'class="video-bg"' in html

    def test_video_has_autoplay_muted_loop(self, client):
        """Test that video has autoplay, muted, loop, playsinline attributes (AC1)."""
        response = client.get('/')
        html = response.data.decode('utf-8')
        assert 'autoplay' in html
        assert 'muted' in html
        assert 'loop' in html
        assert 'playsinline' in html

    def test_video_hls_and_recovery_js_present(self, client):
        """Test que le JS HLS et la récupération visibilitychange sont présents (AC5)."""
        response = client.get('/')
        html = response.data.decode('utf-8')
        assert 'hls.js' in html
        assert 'HLS_URL' in html
        assert 'playLocal' in html
        assert 'visibilitychange' in html
        assert 'prefersReduced' in html

    def test_video_has_preload_auto(self, client):
        """Test that video uses preload=auto pour fiabilité du loop (AC5).

        preload=auto force le téléchargement complet (590KB) évitant les
        erreurs de range-request sur les fichiers MP4 sans faststart.
        """
        response = client.get('/')
        html = response.data.decode('utf-8')
        assert 'preload="auto"' in html

    def test_video_source_points_to_mp4(self, client):
        """Test that video source references background.mp4 (AC1)."""
        response = client.get('/')
        html = response.data.decode('utf-8')
        assert 'video/background.mp4' in html
        assert 'type="video/mp4"' in html


class TestOverlayElements:
    """Tests for cinematic overlay elements in rendered HTML (AC2)."""

    def test_render_contains_overlay_dark(self, client):
        """Test that page contains dark overlay div (AC2)."""
        response = client.get('/')
        html = response.data.decode('utf-8')
        assert 'class="overlay-dark"' in html

    def test_render_contains_overlay_vignette(self, client):
        """Test that page contains vignette overlay div (AC2)."""
        response = client.get('/')
        html = response.data.decode('utf-8')
        assert 'class="overlay-vignette"' in html

    def test_render_contains_overlay_gradient(self, client):
        """Test that page contains gradient overlay div (AC2)."""
        response = client.get('/')
        html = response.data.decode('utf-8')
        assert 'class="overlay-gradient"' in html

    def test_overlays_before_header(self, client):
        """Test that overlays appear before header in DOM order (z-index hierarchy)."""
        response = client.get('/')
        html = response.data.decode('utf-8')
        overlay_pos = html.index('overlay-dark')
        header_pos = html.index('site-header')
        assert overlay_pos < header_pos, "Overlays must appear before header in DOM"


class TestFallbackBehavior:
    """Tests for graceful fallback when video is unavailable (AC1, AC5)."""

    def test_body_has_void_black_background(self, client):
        """Test that body background color is void-black as fallback (AC1)."""
        response = client.get('/')
        html = response.data.decode('utf-8')
        # The inline critical style sets html background to #0f1117
        assert '#0f1117' in html

    def test_fallback_js_present(self, client):
        """Test that video error fallback JavaScript is present (AC1)."""
        response = client.get('/')
        html = response.data.decode('utf-8')
        assert 'video-bg' in html
        assert 'error' in html
        assert "display = 'none'" in html or 'style.display' in html

    def test_reduced_motion_js_present(self, client):
        """Test that prefers-reduced-motion JS handler is present (AC5)."""
        response = client.get('/')
        html = response.data.decode('utf-8')
        assert 'prefers-reduced-motion' in html


class TestCSSTokensInStylesheet:
    """Tests for cinematic CSS tokens availability (AC2, AC3)."""

    def test_stylesheet_loaded(self, client):
        """Test that style.css is loaded in page."""
        response = client.get('/')
        html = response.data.decode('utf-8')
        assert 'css/style.css' in html

    def test_css_file_accessible(self, client):
        """Test that style.css is served without error."""
        response = client.get('/static/css/style.css')
        assert response.status_code == 200
        css = response.data.decode('utf-8')
        assert len(css) > 0

    def test_css_contains_glass_blur_token(self, client):
        """Test that CSS contains --glass-blur token (AC3)."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')
        assert '--glass-blur' in css

    def test_css_contains_overlay_tokens(self, client):
        """Test that CSS contains overlay tokens (AC2)."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')
        assert '--overlay-dark-opacity' in css
        assert '--accent-violet' in css
        assert '--accent-pink' in css

    def test_css_contains_video_bg_styles(self, client):
        """Test that CSS contains .video-bg styles (AC1)."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')
        assert '.video-bg' in css
        assert 'object-fit: cover' in css

    def test_css_contains_overlay_styles(self, client):
        """Test that CSS contains overlay class styles (AC2)."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')
        assert '.overlay-dark' in css
        assert '.overlay-vignette' in css
        assert '.overlay-gradient' in css

    def test_css_contains_backdrop_filter(self, client):
        """Test that CSS contains backdrop-filter for glassmorphism (AC3)."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')
        assert 'backdrop-filter' in css

    def test_css_contains_mobile_media_query(self, client):
        """Test that CSS contains mobile media query to hide video (AC5)."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')
        assert 'max-width: 768px' in css

    def test_css_contains_reduced_motion_media_query(self, client):
        """Test that CSS contains prefers-reduced-motion query (AC5)."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')
        assert 'prefers-reduced-motion' in css
