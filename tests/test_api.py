from fastapi.testclient import TestClient

from app.main import app


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
        dataset = test_client.get("/api/users").json()
        assert dataset


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
