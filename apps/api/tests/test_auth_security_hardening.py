from __future__ import annotations

import os
from time import perf_counter

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

os.environ["DATABASE_URL"] = "sqlite+pysqlite:///:memory:"

from app.db.session import Base, get_db
from app.main import app


PASSWORD = "Password123!"
AUTH_MIN_EXPECTED_SECONDS = 0.22


@pytest.fixture()
def test_env(tmp_path):
    db_file = tmp_path / "auth_security.sqlite3"
    engine = create_engine(
        f"sqlite+pysqlite:///{db_file}",
        connect_args={"check_same_thread": False},
    )
    testing_session_local = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = testing_session_local()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    try:
        yield client
    finally:
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def _register(client: TestClient, *, email: str) -> None:
    response = client.post(
        "/auth/register",
        json={"email": email, "password": PASSWORD, "full_name": "Security Owner"},
    )
    assert response.status_code == 200, response.text


def test_register_duplicate_returns_generic_error_and_normalized_timing(test_env: TestClient) -> None:
    client = test_env
    email = "auth-security-owner@example.com"
    _register(client, email=email)

    started = perf_counter()
    response = client.post(
        "/auth/register",
        json={"email": email, "password": PASSWORD, "full_name": "Security Owner"},
    )
    elapsed = perf_counter() - started

    assert response.status_code == 400, response.text
    detail = str(response.json().get("detail") or "")
    assert detail == "Unable to process registration request"
    assert "already exists" not in detail.lower()
    assert elapsed >= AUTH_MIN_EXPECTED_SECONDS


def test_login_invalid_credentials_uses_normalized_timing(test_env: TestClient) -> None:
    client = test_env
    started = perf_counter()
    response = client.post(
        "/auth/login",
        json={"email": "missing-user@example.com", "password": PASSWORD},
    )
    elapsed = perf_counter() - started

    assert response.status_code == 401, response.text
    assert response.json().get("detail") == "Invalid credentials"
    assert elapsed >= AUTH_MIN_EXPECTED_SECONDS


def test_refresh_invalid_token_returns_401_without_server_error(test_env: TestClient) -> None:
    client = TestClient(app, raise_server_exceptions=False)
    try:
        response = client.post("/auth/refresh", json={"refresh_token": "not-a-token"})
    finally:
        client.close()

    assert response.status_code == 401, response.text
    assert response.json().get("detail") == "Invalid refresh token"
