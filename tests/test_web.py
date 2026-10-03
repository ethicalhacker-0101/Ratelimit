import json
import pytest
from rlcheck.web.app import create_app


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_index_page(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"RLCheck Pro" in response.data


def test_start_assessment_missing_url(client):
    response = client.post(
        "/api/start",
        data=json.dumps({"url": ""}),
        content_type="application/json",
    )
    assert response.status_code == 400
    assert "URL is required" in response.get_json()["error"]


def test_start_assessment_safety_validation(client):
    response = client.post(
        "/api/start",
        data=json.dumps({"url": "https://example.com", "attempts": 0}),
        content_type="application/json",
    )
    assert response.status_code == 400
    assert "Attempts must be at least 1" in response.get_json()["error"]


def test_start_assessment_already_running(client):
    import rlcheck.web.app as web_app
    with web_app._assessment_lock:
        web_app._assessment_running = True
    try:
        response = client.post(
            "/api/start",
            data=json.dumps({"url": "https://example.com"}),
            content_type="application/json",
        )
        assert response.status_code == 409
        assert "already running" in response.get_json()["error"]
    finally:
        with web_app._assessment_lock:
            web_app._assessment_running = False


def test_emit_and_event_stream(client):
    import rlcheck.web.app as web_app
    web_app._emit("test_event", payload="hello")
    # Fetch from SSE stream generator
    response = client.get("/api/events")
    # Read the first event chunk
    line = next(response.response)
    decoded = line.decode() if isinstance(line, bytes) else line
    assert "test_event" in decoded
    assert "hello" in decoded
