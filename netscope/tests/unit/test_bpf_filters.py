"""Unit tests for BPF filters module."""

import pytest

from app.core.capture.bpf_filters import (
    build_default_filter,
    validate_filter,
    combine_filters,
    build_capture_filter,
    DEFAULT_BPF_FILTER,
)
from app.models.capture import CaptureError, CAPTURE_INVALID_FILTER


class TestBuildDefaultFilter:
    """Tests for build_default_filter()."""

    def test_returns_default(self):
        """Test that default filter is returned."""
        result = build_default_filter()
        assert result == DEFAULT_BPF_FILTER
        assert result == "not port 22"


class TestValidateFilter:
    """Tests for validate_filter()."""

    def test_returns_default_for_none(self):
        """Test that None returns default filter."""
        result = validate_filter(None)
        assert result == DEFAULT_BPF_FILTER

    def test_returns_default_for_empty(self):
        """Test that empty string returns default filter."""
        result = validate_filter("")
        assert result == DEFAULT_BPF_FILTER

    def test_returns_default_for_whitespace(self):
        """Test that whitespace returns default filter."""
        result = validate_filter("   ")
        assert result == DEFAULT_BPF_FILTER

    def test_valid_filter_passes(self):
        """Test that valid filter is returned unchanged."""
        filter_str = "host 192.168.1.1"
        result = validate_filter(filter_str)
        assert result == filter_str

    def test_valid_complex_filter(self):
        """Test that complex filter is validated."""
        filter_str = "tcp and port 80 or port 443"
        result = validate_filter(filter_str)
        assert result == filter_str

    def test_rejects_semicolon(self):
        """Test that semicolon is rejected."""
        with pytest.raises(CaptureError) as exc_info:
            validate_filter("host 192.168.1.1; rm -rf /")
        assert exc_info.value.code == CAPTURE_INVALID_FILTER

    def test_rejects_pipe(self):
        """Test that pipe is rejected."""
        with pytest.raises(CaptureError) as exc_info:
            validate_filter("tcp | cat /etc/passwd")
        assert exc_info.value.code == CAPTURE_INVALID_FILTER

    def test_rejects_backtick(self):
        """Test that backtick is rejected."""
        with pytest.raises(CaptureError) as exc_info:
            validate_filter("`whoami`")
        assert exc_info.value.code == CAPTURE_INVALID_FILTER

    def test_rejects_dollar_sign(self):
        """Test that dollar sign is rejected."""
        with pytest.raises(CaptureError) as exc_info:
            validate_filter("$(rm -rf /)")
        assert exc_info.value.code == CAPTURE_INVALID_FILTER

    def test_rejects_too_long_filter(self):
        """Test that excessively long filter is rejected."""
        long_filter = "a" * 1001
        with pytest.raises(CaptureError) as exc_info:
            validate_filter(long_filter)
        assert exc_info.value.code == CAPTURE_INVALID_FILTER

    def test_strips_whitespace(self):
        """Test that whitespace is stripped."""
        result = validate_filter("  tcp  ")
        assert result == "tcp"


class TestCombineFilters:
    """Tests for combine_filters()."""

    def test_combine_two_filters(self):
        """Test combining two valid filters."""
        result = combine_filters("not port 22", "host 192.168.1.1")
        assert "(not port 22)" in result
        assert "(host 192.168.1.1)" in result
        assert "and" in result

    def test_combine_with_none_base(self):
        """Test combining with None base."""
        result = combine_filters(None, "tcp")
        assert result == "tcp"

    def test_combine_with_none_custom(self):
        """Test combining with None custom."""
        result = combine_filters("udp", None)
        assert result == "udp"

    def test_combine_both_none(self):
        """Test combining with both None."""
        result = combine_filters(None, None)
        assert result == DEFAULT_BPF_FILTER

    def test_combine_same_filter(self):
        """Test combining identical filters."""
        result = combine_filters("tcp", "tcp")
        assert result == "tcp"


class TestBuildCaptureFilter:
    """Tests for build_capture_filter()."""

    def test_default_excludes_ssh(self):
        """Test that default filter excludes SSH."""
        result = build_capture_filter()
        assert "not port 22" in result

    def test_no_ssh_exclusion(self):
        """Test disabling SSH exclusion returns empty filter."""
        result = build_capture_filter(exclude_ssh=False)
        # With no filters, result should be empty
        assert result == "" or "not port 22" not in result

    def test_exclude_additional_ports(self):
        """Test excluding additional ports."""
        result = build_capture_filter(exclude_ports=[80, 443])
        assert "not port 80" in result
        assert "not port 443" in result

    def test_include_only_ports(self):
        """Test including only specific ports."""
        result = build_capture_filter(
            exclude_ssh=False,
            include_only_ports=[80, 443],
        )
        assert "port 80" in result
        assert "port 443" in result

    def test_include_only_hosts(self):
        """Test including only specific hosts."""
        result = build_capture_filter(
            exclude_ssh=False,
            include_only_hosts=["192.168.1.1", "10.0.0.1"],
        )
        assert "host 192.168.1.1" in result
        assert "host 10.0.0.1" in result

    def test_with_custom_filter(self):
        """Test adding custom filter."""
        result = build_capture_filter(custom_filter="icmp")
        assert "icmp" in result
        assert "not port 22" in result

    def test_ignores_invalid_ports(self):
        """Test that invalid ports are ignored."""
        result = build_capture_filter(
            exclude_ssh=False,
            exclude_ports=[0, -1, 70000, 80],
        )
        assert "port 80" in result
        assert "port 0" not in result
        assert "port 70000" not in result
