"""Unit tests for update status enrichment and history persistence (Story 5.9).

Tests cover: UpdateHistoryEntry serialization, save/load history,
UpdateStatus enriched fields, FIFO limit, _set_status meta propagation.
"""

import json
import os
import tempfile
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from app.services.update_service import (
    UpdateHistoryEntry,
    UpdateService,
    UpdateState,
    UpdateStatus,
    MAX_HISTORY_ENTRIES,
    reset_update_service,
)


@pytest.fixture(autouse=True)
def reset_singleton():
    reset_update_service()
    yield
    reset_update_service()


@pytest.fixture
def service():
    return UpdateService(
        github_repo="iPresing/NETSCOPE",
        check_url_template="https://api.github.com/repos/{repo}/releases/latest",
    )


@pytest.fixture
def tmp_history_file(tmp_path):
    return str(tmp_path / "update_history.json")


class TestUpdateHistoryEntry:
    def test_to_dict_success(self):
        entry = UpdateHistoryEntry(
            date="2026-05-09T14:30:00Z",
            from_version="1.2.0",
            to_version="1.3.0",
            status="done",
            duration_seconds=45,
        )
        d = entry.to_dict()
        assert d["date"] == "2026-05-09T14:30:00Z"
        assert d["from_version"] == "1.2.0"
        assert d["to_version"] == "1.3.0"
        assert d["status"] == "done"
        assert d["error"] is None
        assert d["duration_seconds"] == 45

    def test_to_dict_error(self):
        entry = UpdateHistoryEntry(
            date="2026-05-09T15:00:00Z",
            from_version="1.2.0",
            to_version="1.3.0",
            status="error",
            error="Connexion perdue",
            duration_seconds=12,
        )
        d = entry.to_dict()
        assert d["status"] == "error"
        assert d["error"] == "Connexion perdue"

    def test_to_dict_rolled_back(self):
        entry = UpdateHistoryEntry(
            date="2026-05-09T15:00:00Z",
            from_version="1.2.0",
            to_version="1.3.0",
            status="rolled_back",
            error="Health check échoué",
            duration_seconds=30,
        )
        d = entry.to_dict()
        assert d["status"] == "rolled_back"
        assert d["error"] == "Health check échoué"

    def test_to_dict_no_duration(self):
        entry = UpdateHistoryEntry(
            date="2026-05-09T15:00:00Z",
            from_version="1.2.0",
            to_version="1.3.0",
            status="done",
        )
        d = entry.to_dict()
        assert d["duration_seconds"] is None


class TestUpdateStatusEnriched:
    def test_to_dict_idle_no_extra_fields(self):
        status = UpdateStatus()
        d = status.to_dict()
        assert d["state"] == "idle"
        assert "target_version" not in d
        assert "from_version" not in d
        assert "started_at" not in d
        assert "duration_seconds" not in d

    def test_to_dict_with_target_version(self):
        status = UpdateStatus(
            state=UpdateState.DOWNLOADING,
            target_version="1.3.0",
            from_version="1.2.0",
        )
        d = status.to_dict()
        assert d["target_version"] == "1.3.0"
        assert d["from_version"] == "1.2.0"

    def test_to_dict_with_started_at_calculates_duration(self):
        started = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        status = UpdateStatus(
            state=UpdateState.DOWNLOADING,
            started_at=started,
        )
        d = status.to_dict()
        assert "duration_seconds" in d
        assert d["duration_seconds"] >= 0

    def test_to_dict_no_started_at_no_duration(self):
        status = UpdateStatus(state=UpdateState.DOWNLOADING)
        d = status.to_dict()
        assert "duration_seconds" not in d

    def test_to_dict_frozen_duration_in_terminal_state(self):
        status = UpdateStatus(
            state=UpdateState.DONE,
            started_at="2026-05-09T14:00:00Z",
            duration_seconds=42,
        )
        d = status.to_dict()
        assert d["duration_seconds"] == 42


class TestHistoryPersistence:
    def test_save_and_load_history(self, service, tmp_history_file):
        entry = UpdateHistoryEntry(
            date="2026-05-09T14:30:00Z",
            from_version="1.2.0",
            to_version="1.3.0",
            status="done",
            duration_seconds=45,
        )
        with patch.object(UpdateService, '_get_history_path', return_value=tmp_history_file):
            service._save_history_entry(entry)
            history = service.get_update_history()

        assert len(history) == 1
        assert history[0]["status"] == "done"
        assert history[0]["from_version"] == "1.2.0"

    def test_load_empty_history(self, service, tmp_history_file):
        with patch.object(UpdateService, '_get_history_path', return_value=tmp_history_file):
            history = service.get_update_history()
        assert history == []

    def test_load_corrupt_file_returns_empty(self, service, tmp_history_file):
        with open(tmp_history_file, 'w') as f:
            f.write("{invalid json")
        with patch.object(UpdateService, '_get_history_path', return_value=tmp_history_file):
            history = service.get_update_history()
        assert history == []

    def test_load_non_list_json_returns_empty(self, service, tmp_history_file):
        with open(tmp_history_file, 'w') as f:
            json.dump({"not": "a list"}, f)
        with patch.object(UpdateService, '_get_history_path', return_value=tmp_history_file):
            history = service.get_update_history()
        assert history == []

    def test_fifo_limit_max_entries(self, service, tmp_history_file):
        with patch.object(UpdateService, '_get_history_path', return_value=tmp_history_file):
            for i in range(MAX_HISTORY_ENTRIES + 5):
                entry = UpdateHistoryEntry(
                    date=f"2026-05-{i:02d}T00:00:00Z",
                    from_version="1.0.0",
                    to_version=f"1.{i}.0",
                    status="done",
                    duration_seconds=10,
                )
                service._save_history_entry(entry)

            history = service.get_update_history()
        assert len(history) == MAX_HISTORY_ENTRIES
        assert history[0]["to_version"] == "1.24.0"

    def test_multiple_entries_append(self, service, tmp_history_file):
        with patch.object(UpdateService, '_get_history_path', return_value=tmp_history_file):
            for status in ["done", "error", "rolled_back"]:
                entry = UpdateHistoryEntry(
                    date="2026-05-09T14:30:00Z",
                    from_version="1.0.0",
                    to_version="1.1.0",
                    status=status,
                    duration_seconds=10,
                )
                service._save_history_entry(entry)
            history = service.get_update_history()
        assert len(history) == 3
        assert [e["status"] for e in history] == ["rolled_back", "error", "done"]


class TestSetStatusMetaPropagation:
    def test_set_status_propagates_meta(self, service):
        service._update_meta = {
            'target_version': '2.0.0',
            'from_version': '1.0.0',
            'started_at': '2026-05-09T14:00:00Z',
        }
        service._set_status(state=UpdateState.DOWNLOADING, progress_percent=50)
        status = service.get_update_status()
        assert status.target_version == '2.0.0'
        assert status.from_version == '1.0.0'
        assert status.started_at == '2026-05-09T14:00:00Z'

    def test_set_status_empty_meta(self, service):
        service._update_meta = {}
        service._set_status(state=UpdateState.ERROR, error="test")
        status = service.get_update_status()
        assert status.target_version is None
        assert status.from_version is None

    def test_set_status_explicit_override(self, service):
        service._update_meta = {'target_version': '2.0.0'}
        service._set_status(
            state=UpdateState.DONE,
            target_version='3.0.0',
        )
        status = service.get_update_status()
        assert status.target_version == '3.0.0'
