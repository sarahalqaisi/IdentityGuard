import asyncio
import json

import pytest
from fastapi import HTTPException, Request
from fastapi.testclient import TestClient

from app.main import MAX_REQUEST_BYTES, app, read_bounded_body
from app.seed import demo_dataset


def client():
    return TestClient(app)


def test_health_and_security_headers():
    with client() as test_client:
        response = test_client.get("/api/health")
        assert response.status_code == 200
        assert response.json()["data_source"] == "synthetic"
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["x-frame-options"] == "DENY"
        assert "default-src 'self'" in response.headers["content-security-policy"]


def test_backward_api_shapes_and_dashboard():
    with client() as test_client:
        assert isinstance(test_client.get("/api/users").json(), list)
        assert isinstance(test_client.get("/api/findings").json(), list)
        assert isinstance(test_client.get("/api/attack-paths").json(), list)
        assert test_client.get("/api/risk/summary").json()["synthetic"] is True
        assert len(test_client.get("/api/coverage").json()["rules"]) == 10
        page = test_client.get("/")
        assert page.status_code == 200
        assert "Identity relationships" in page.text


def test_analyze_demo_and_valid_import():
    with client() as test_client:
        demo = test_client.post("/api/analyze")
        assert demo.status_code == 200
        assert demo.json()["dataset_source"] == "synthetic"
        payload = demo_dataset().model_dump_json().encode("utf-8")
        imported = test_client.post("/api/analyze", content=payload, headers={"content-type": "application/json"})
        assert imported.status_code == 200
        assert imported.json()["summary"]["total_identities"] == 5


def test_malformed_payload_is_sanitized():
    with client() as test_client:
        response = test_client.post("/api/analyze", content=b"not-json", headers={"content-type": "application/json"})
        assert response.status_code == 400
        body = response.json()
        assert body == {"error": {"code": "invalid_dataset", "message": "Dataset validation failed."}}
        rendered = response.text.lower()
        assert "traceback" not in rendered
        assert "/home/" not in rendered
        assert "jsondecodeerror" not in rendered


def test_unknown_resources_use_consistent_safe_error():
    with client() as test_client:
        response = test_client.get("/api/users/unknown")
        assert response.status_code == 404
        assert response.json() == {"error": {"code": "http_404", "message": "The requested resource was not found."}}


def test_oversized_declared_request_is_rejected_with_headers():
    with client() as test_client:
        response = test_client.post("/api/analyze", content=b"{}", headers={"content-length": "2000001"})
        assert response.status_code == 413
        assert response.json()["error"]["code"] == "request_too_large"


def exact_boundary_dataset() -> bytes:
    payload = {
        "metadata": {"synthetic": True, "padding": ""},
        "users": [],
        "groups": [],
        "roles": [],
        "permissions": [],
        "resources": [],
    }
    encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    payload["metadata"]["padding"] = "x" * (MAX_REQUEST_BYTES - len(encoded))
    encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    assert len(encoded) == MAX_REQUEST_BYTES
    return encoded


def test_body_exactly_at_limit_is_accepted():
    with client() as test_client:
        response = test_client.post(
            "/api/analyze",
            content=exact_boundary_dataset(),
            headers={"content-type": "application/json"},
        )
        assert response.status_code == 200
        assert response.json()["summary"]["total_identities"] == 0


def test_chunked_body_over_limit_without_content_length_is_stopped():
    observed_chunks = 0

    def chunks():
        nonlocal observed_chunks
        for _ in range(4):
            observed_chunks += 1
            yield b"x" * 700_000

    with client() as test_client:
        response = test_client.post(
            "/api/analyze",
            content=chunks(),
            headers={"content-type": "application/json", "transfer-encoding": "chunked"},
        )
        assert response.status_code == 413
        assert response.json() == {
            "error": {
                "code": "http_413",
                "message": "Request body exceeds the supported limit.",
            }
        }
        assert observed_chunks == 4  # The synchronous test transport consumes the generator eagerly.
        assert "traceback" not in response.text.lower()
        assert "/home/" not in response.text.lower()


def test_bounded_reader_stops_after_first_exceeding_stream_chunk():
    chunks = [b"x" * 700_000] * 4
    receive_calls = 0

    async def receive():
        nonlocal receive_calls
        chunk = chunks[receive_calls]
        receive_calls += 1
        return {"type": "http.request", "body": chunk, "more_body": receive_calls < len(chunks)}

    request = Request(
        {"type": "http", "method": "POST", "path": "/api/analyze", "headers": []},
        receive,
    )

    with pytest.raises(HTTPException) as error:
        asyncio.run(read_bounded_body(request))

    assert error.value.status_code == 413
    assert receive_calls == 3
