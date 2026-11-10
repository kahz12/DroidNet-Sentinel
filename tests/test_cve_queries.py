"""NVD pagination, failed queries and CVE applicability, tested offline."""
from datetime import datetime, timedelta
from unittest.mock import Mock

import pytest

from droidnet.modules import cve_watcher as cve


@pytest.fixture
def offline(monkeypatch, tmp_path):
    monkeypatch.setattr(cve, "NVD_CACHE_DIR", tmp_path)
    monkeypatch.setattr(cve.time, "sleep", lambda _: None)
    # Fail if a test accidentally reaches the external API.
    monkeypatch.setattr(cve.requests, "get", Mock(side_effect=AssertionError("unexpected network call")))


def page(start, count, total):
    return {"startIndex": start, "resultsPerPage": count, "totalResults": total,
            "vulnerabilities": [{"cve": {"id": f"CVE-2026-{i:04}"}} for i in range(start, start + count)]}


def test_all_pages_and_complete_cache(offline, monkeypatch):
    get = Mock(side_effect=[page(0, 10, 25), page(10, 10, 25), page(20, 5, 25)])
    monkeypatch.setattr(cve, "_nvd_get", get)
    result = cve.query_nvd("nginx")
    assert len(result) == 25
    assert [call.args[0]["startIndex"] for call in get.call_args_list] == [0, 10, 20]
    params = get.call_args_list[0].args[0]
    assert datetime.fromisoformat(params["pubEndDate"]) - datetime.fromisoformat(params["pubStartDate"]) == timedelta(days=120)
    assert cve.query_nvd("nginx") == result
    assert get.call_count == 3


def test_failed_second_page_does_not_cache_partial_result(offline, monkeypatch):
    get = Mock(side_effect=[page(0, 10, 25), None])
    monkeypatch.setattr(cve, "_nvd_get", get)
    assert cve.query_nvd("nginx") is None
    assert not list(cve.NVD_CACHE_DIR.glob("*.json"))


@pytest.mark.parametrize("days", [0, -1, 121, True, 1.5])
def test_invalid_publication_window(offline, days):
    with pytest.raises(ValueError):
        cve.query_nvd("nginx", days_back=days)


@pytest.mark.parametrize("payload", [None, {}, page(0, 0, 25), page(10, 5, 25)])
def test_bad_or_incomplete_response_is_not_an_empty_success(offline, monkeypatch, payload):
    monkeypatch.setattr(cve, "_nvd_get", lambda *args: payload)
    assert cve.query_nvd("nginx") is None


def setup_watcher(monkeypatch):
    monkeypatch.setattr(cve, "init_db", lambda: None)
    monkeypatch.setattr(cve, "get_latest_scan_with_services", lambda: {
        "id": 1, "network": "test", "targets": {"192.0.2.10": ["80/tcp open http nginx 1.18.0"]}})
    save = Mock()
    monkeypatch.setattr(cve, "save_cve_alert", save)
    monkeypatch.setattr(cve, "send_alert", Mock())
    return save


def test_failed_query_is_reported_incomplete(offline, monkeypatch, capsys):
    save = setup_watcher(monkeypatch)
    query = Mock(return_value=None)
    monkeypatch.setattr(cve, "query_nvd", query)
    result = cve.run_cve_watcher()
    assert not result.complete
    assert result.failed_queries == ["nginx 1.18.0"]
    assert query.call_count == 1  # HTTP errors are not retried as broader matches.
    save.assert_not_called()
    output = capsys.readouterr().out
    assert "incomplete" in output.lower()
    assert "No matching CVEs" not in output


def test_description_match_is_a_candidate(offline, monkeypatch):
    # Not analysed by NVD yet (no CPE match possible), but its description
    # names nginx with a range covering the detected 1.18.0.
    save = setup_watcher(monkeypatch)
    match = {"cve_id": "CVE-2026-0001", "severity": "HIGH", "score": 8.0,
             "description": "nginx before 1.20.0 allows remote code execution",
             "analysed": False}
    monkeypatch.setattr(cve, "query_nvd", Mock(side_effect=[[], [match]]))
    result = cve.run_cve_watcher()
    assert result.complete
    assert result[0]["match_type"] == "candidate"
    assert "not yet confirmed by NVD" in result[0]["impact"]
    assert "not yet confirmed by NVD" in save.call_args.kwargs["impact"]
    assert "candidate" in cve._build_telegram_report(result, "test")
