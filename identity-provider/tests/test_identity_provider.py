"""
Tests for the Identity Provider FastAPI app.

Covers OIDC discovery, JWKS, the confidential-client and public-client
(PKCE) authorization code flows, refresh tokens, and the single-use /
client-validation hardening around authorization and refresh tokens.
"""

import base64
import hashlib
import secrets
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient
from jose import jwt as jose_jwt

# main.py lives one directory up from this test file (flat layout, no
# package/__init__.py), so make sure it's importable regardless of how
# pytest was invoked.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import main

# Must be one of the redirect URIs registered in main.REGISTERED_REDIRECT_URIS
REDIRECT_URI = "http://localhost:9999/callback"


@pytest.fixture()
def client():
    return TestClient(main.app)


def _make_pkce_pair() -> tuple[str, str]:
    """Generate a matching (code_verifier, code_challenge) pair using S256."""
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).decode().rstrip("=")
    return verifier, challenge


def _authorize(client: TestClient, client_id: str, **extra_params) -> str:
    """Hit /oauth2/v2.0/authorize and return the full redirect Location header."""
    params = {
        "client_id": client_id,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        **extra_params,
    }
    resp = client.get("/oauth2/v2.0/authorize", params=params, follow_redirects=False)
    assert resp.status_code in (302, 307)
    return resp.headers["location"]


def _get_auth_code(client: TestClient, client_id: str, **extra_params) -> str:
    """Run the authorize step and pull the issued authorization code out of it."""
    location = _authorize(client, client_id, **extra_params)
    qs = parse_qs(urlparse(location).query)
    return qs["code"][0]


def _exchange_code(client: TestClient, code: str, client_id: str, **extra_fields):
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": client_id,
        **extra_fields,
    }
    return client.post("/oauth2/v2.0/token", data=data)


def test_discovery_document(client: TestClient):
    resp = client.get("/.well-known/openid-configuration")
    assert resp.status_code == 200
    data = resp.json()

    assert data["issuer"] == main.ISSUER
    assert data["authorization_endpoint"] == f"{main.ISSUER}/oauth2/v2.0/authorize"
    assert data["token_endpoint"] == f"{main.ISSUER}/oauth2/v2.0/token"
    assert data["jwks_uri"] == f"{main.ISSUER}/discovery/v2.0/keys"
    assert "code" in data["response_types_supported"]
    assert set(data["grant_types_supported"]) == {"authorization_code", "refresh_token"}
    assert set(data["code_challenge_methods_supported"]) == {"S256"}
    assert "RS256" in data["id_token_signing_alg_values_supported"]


def test_jwks_returns_single_rs256_key(client: TestClient):
    resp = client.get("/discovery/v2.0/keys")
    assert resp.status_code == 200
    keys = resp.json()["keys"]

    assert len(keys) == 1
    key = keys[0]
    assert key["kid"] == "default-key-id"
    assert key["kty"] == "RSA"
    assert key["alg"] == "RS256"
    assert key["use"] == "sig"


def test_confidential_client_full_code_flow(client: TestClient):
    location = _authorize(client, main.CLIENT_ID_CONFIDENTIAL, state="round-trip-state")
    qs = parse_qs(urlparse(location).query)
    assert qs["state"] == ["round-trip-state"]
    code = qs["code"][0]

    token_resp = _exchange_code(
        client, code, main.CLIENT_ID_CONFIDENTIAL, client_secret=main.CLIENT_SECRET
    )
    assert token_resp.status_code == 200
    body = token_resp.json()
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == 3600
    assert body["refresh_token"]
    assert body["access_token"]

    jwks_keys = client.get("/discovery/v2.0/keys").json()["keys"]
    decoded = jose_jwt.decode(
        body["access_token"],
        jwks_keys[0],
        algorithms=["RS256"],
        audience=main.CLIENT_ID_CONFIDENTIAL,
        issuer=main.ISSUER,
    )
    assert decoded["iss"] == main.ISSUER
    assert decoded["sub"] == "demo-user"
    assert decoded["aud"] == main.CLIENT_ID_CONFIDENTIAL


def test_confidential_client_wrong_secret_returns_401(client: TestClient):
    code = _get_auth_code(client, main.CLIENT_ID_CONFIDENTIAL)
    resp = _exchange_code(client, code, main.CLIENT_ID_CONFIDENTIAL, client_secret="wrong-secret")
    assert resp.status_code == 401


def test_public_client_pkce_happy_path(client: TestClient):
    verifier, challenge = _make_pkce_pair()
    code = _get_auth_code(
        client, main.CLIENT_ID_PUBLIC, code_challenge=challenge, code_challenge_method="S256"
    )
    resp = _exchange_code(client, code, main.CLIENT_ID_PUBLIC, code_verifier=verifier)
    assert resp.status_code == 200
    assert resp.json()["access_token"]


def test_public_client_wrong_verifier_returns_400(client: TestClient):
    _verifier, challenge = _make_pkce_pair()
    code = _get_auth_code(
        client, main.CLIENT_ID_PUBLIC, code_challenge=challenge, code_challenge_method="S256"
    )
    resp = _exchange_code(
        client, code, main.CLIENT_ID_PUBLIC, code_verifier="not-the-right-verifier"
    )
    assert resp.status_code == 400


def test_public_client_without_pkce_challenge_returns_400(client: TestClient):
    code = _get_auth_code(client, main.CLIENT_ID_PUBLIC)
    resp = _exchange_code(client, code, main.CLIENT_ID_PUBLIC)
    assert resp.status_code == 400


def test_auth_code_is_single_use(client: TestClient):
    code = _get_auth_code(client, main.CLIENT_ID_CONFIDENTIAL)

    first = _exchange_code(
        client, code, main.CLIENT_ID_CONFIDENTIAL, client_secret=main.CLIENT_SECRET
    )
    assert first.status_code == 200

    second = _exchange_code(
        client, code, main.CLIENT_ID_CONFIDENTIAL, client_secret=main.CLIENT_SECRET
    )
    assert second.status_code == 400


def test_confidential_client_with_pkce_challenge_requires_valid_verifier(client: TestClient):
    verifier, challenge = _make_pkce_pair()

    # Correct client_secret alone must not be enough once a challenge was bound to the code.
    bad_code = _get_auth_code(
        client, main.CLIENT_ID_CONFIDENTIAL, code_challenge=challenge, code_challenge_method="S256"
    )
    bad_resp = _exchange_code(
        client,
        bad_code,
        main.CLIENT_ID_CONFIDENTIAL,
        client_secret=main.CLIENT_SECRET,
        code_verifier="wrong-verifier",
    )
    assert bad_resp.status_code == 400

    # A fresh code with the matching verifier succeeds.
    good_code = _get_auth_code(
        client, main.CLIENT_ID_CONFIDENTIAL, code_challenge=challenge, code_challenge_method="S256"
    )
    good_resp = _exchange_code(
        client,
        good_code,
        main.CLIENT_ID_CONFIDENTIAL,
        client_secret=main.CLIENT_SECRET,
        code_verifier=verifier,
    )
    assert good_resp.status_code == 200


def test_authorize_invalid_client_id_returns_400(client: TestClient):
    resp = client.get(
        "/oauth2/v2.0/authorize",
        params={
            "client_id": "no-such-client",
            "redirect_uri": REDIRECT_URI,
            "response_type": "code",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 400


def test_authorize_unsupported_response_type_returns_400(client: TestClient):
    resp = client.get(
        "/oauth2/v2.0/authorize",
        params={
            "client_id": main.CLIENT_ID_CONFIDENTIAL,
            "redirect_uri": REDIRECT_URI,
            "response_type": "token",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 400


def test_authorize_unregistered_redirect_uri_returns_400(client: TestClient):
    resp = client.get(
        "/oauth2/v2.0/authorize",
        params={
            "client_id": main.CLIENT_ID_CONFIDENTIAL,
            "redirect_uri": "https://attacker.example.com/steal-codes",
            "response_type": "code",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 400


def test_authorize_plain_code_challenge_method_returns_400(client: TestClient):
    _verifier, challenge = _make_pkce_pair()
    resp = client.get(
        "/oauth2/v2.0/authorize",
        params={
            "client_id": main.CLIENT_ID_PUBLIC,
            "redirect_uri": REDIRECT_URI,
            "response_type": "code",
            "code_challenge": challenge,
            "code_challenge_method": "plain",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 400


def test_refresh_token_happy_path(client: TestClient):
    code = _get_auth_code(client, main.CLIENT_ID_CONFIDENTIAL)
    token_body = _exchange_code(
        client, code, main.CLIENT_ID_CONFIDENTIAL, client_secret=main.CLIENT_SECRET
    ).json()

    resp = client.post(
        "/oauth2/v2.0/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": token_body["refresh_token"],
            "client_id": main.CLIENT_ID_CONFIDENTIAL,
            "client_secret": main.CLIENT_SECRET,
        },
    )
    assert resp.status_code == 200
    assert resp.json()["access_token"]


def test_refresh_token_wrong_client_is_rejected(client: TestClient):
    code = _get_auth_code(client, main.CLIENT_ID_CONFIDENTIAL)
    token_body = _exchange_code(
        client, code, main.CLIENT_ID_CONFIDENTIAL, client_secret=main.CLIENT_SECRET
    ).json()
    refresh_token = token_body["refresh_token"]

    # A different client_id entirely must be rejected.
    mismatched_client_resp = client.post(
        "/oauth2/v2.0/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": main.CLIENT_ID_PUBLIC,
        },
    )
    assert mismatched_client_resp.status_code == 401

    # The right client_id but a wrong secret must also be rejected.
    wrong_secret_resp = client.post(
        "/oauth2/v2.0/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": main.CLIENT_ID_CONFIDENTIAL,
            "client_secret": "wrong-secret",
        },
    )
    assert wrong_secret_resp.status_code == 401


def test_state_roundtrip_with_url_special_characters(client: TestClient):
    special_state = "abc &=+/xyz"
    location = _authorize(client, main.CLIENT_ID_CONFIDENTIAL, state=special_state)
    qs = parse_qs(urlparse(location).query)

    assert qs["state"] == [special_state]
    assert "code" in qs


# ---------------------------------------------------------------------------
# RFC 8414 authorization server metadata
# ---------------------------------------------------------------------------


def test_oauth_authorization_server_metadata_matches_oidc_discovery(client: TestClient):
    oidc = client.get("/.well-known/openid-configuration")
    rfc8414 = client.get("/.well-known/oauth-authorization-server")

    assert rfc8414.status_code == 200
    assert rfc8414.json() == oidc.json()


# ---------------------------------------------------------------------------
# RFC 8707 resource indicators
# ---------------------------------------------------------------------------


def test_authorize_rejects_unregistered_resource(client: TestClient):
    resp = client.get(
        "/oauth2/v2.0/authorize",
        params={
            "client_id": main.CLIENT_ID_CONFIDENTIAL,
            "redirect_uri": REDIRECT_URI,
            "response_type": "code",
            "resource": "http://attacker.example.com/mcp",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 400
    assert resp.json()["detail"]["error"] == "invalid_target"


def test_token_rejects_unregistered_resource(client: TestClient):
    code = _get_auth_code(client, main.CLIENT_ID_CONFIDENTIAL)
    resp = _exchange_code(
        client,
        code,
        main.CLIENT_ID_CONFIDENTIAL,
        client_secret=main.CLIENT_SECRET,
        resource="http://attacker.example.com/mcp",
    )
    assert resp.status_code == 400
    assert resp.json()["detail"]["error"] == "invalid_target"


def test_resource_accepted_and_binds_audience(client: TestClient):
    """A registered `resource` sent to both /authorize and /token is
    accepted, and the resulting access token's `aud` is the resource, not
    the client_id — the MCP spec's audience-binding requirement."""
    code = _get_auth_code(
        client, main.CLIENT_ID_CONFIDENTIAL, resource=main.MCP_RESOURCE
    )
    resp = _exchange_code(
        client,
        code,
        main.CLIENT_ID_CONFIDENTIAL,
        client_secret=main.CLIENT_SECRET,
        resource=main.MCP_RESOURCE,
    )
    assert resp.status_code == 200
    body = resp.json()

    jwks_keys = client.get("/discovery/v2.0/keys").json()["keys"]
    decoded = jose_jwt.decode(
        body["access_token"],
        jwks_keys[0],
        algorithms=["RS256"],
        audience=main.MCP_RESOURCE,
        issuer=main.ISSUER,
    )
    assert decoded["aud"] == main.MCP_RESOURCE
    assert decoded["aud"] != main.CLIENT_ID_CONFIDENTIAL
    assert decoded["azp"] == main.CLIENT_ID_CONFIDENTIAL


def test_resource_omitted_falls_back_to_client_id_audience(client: TestClient):
    """Plain OIDC clients that never send `resource` keep the pre-RFC-8707
    behavior: `aud` defaults to client_id (already covered by
    test_confidential_client_full_code_flow, asserted explicitly here too
    for clarity)."""
    code = _get_auth_code(client, main.CLIENT_ID_CONFIDENTIAL)
    resp = _exchange_code(
        client, code, main.CLIENT_ID_CONFIDENTIAL, client_secret=main.CLIENT_SECRET
    )
    assert resp.status_code == 200

    jwks_keys = client.get("/discovery/v2.0/keys").json()["keys"]
    decoded = jose_jwt.decode(
        resp.json()["access_token"],
        jwks_keys[0],
        algorithms=["RS256"],
        audience=main.CLIENT_ID_CONFIDENTIAL,
        issuer=main.ISSUER,
    )
    assert decoded["aud"] == main.CLIENT_ID_CONFIDENTIAL


def test_token_resource_must_match_authorize_resource(client: TestClient, monkeypatch):
    """A resource bound at /authorize can't be swapped for a different
    *registered* resource at /token - registering a second resource just
    for this test, since the demo only registers one by default."""
    other_resource = "http://localhost:8002/mcp"
    monkeypatch.setattr(
        main, "REGISTERED_RESOURCES", main.REGISTERED_RESOURCES | {other_resource}
    )

    code = _get_auth_code(client, main.CLIENT_ID_CONFIDENTIAL, resource=main.MCP_RESOURCE)
    resp = _exchange_code(
        client,
        code,
        main.CLIENT_ID_CONFIDENTIAL,
        client_secret=main.CLIENT_SECRET,
        resource=other_resource,
    )
    assert resp.status_code == 400
    assert resp.json()["detail"]["error"] == "invalid_target"


# ---------------------------------------------------------------------------
# Refresh token rotation (OAuth 2.1)
# ---------------------------------------------------------------------------


def test_refresh_token_rotation_issues_new_token_and_invalidates_old(client: TestClient):
    code = _get_auth_code(client, main.CLIENT_ID_CONFIDENTIAL)
    first_token_body = _exchange_code(
        client, code, main.CLIENT_ID_CONFIDENTIAL, client_secret=main.CLIENT_SECRET
    ).json()
    original_refresh_token = first_token_body["refresh_token"]

    refresh_resp = client.post(
        "/oauth2/v2.0/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": original_refresh_token,
            "client_id": main.CLIENT_ID_CONFIDENTIAL,
            "client_secret": main.CLIENT_SECRET,
        },
    )
    assert refresh_resp.status_code == 200
    refresh_body = refresh_resp.json()

    new_refresh_token = refresh_body["refresh_token"]
    assert new_refresh_token
    assert new_refresh_token != original_refresh_token

    # The old refresh token is single-use: replaying it must now fail.
    replay_resp = client.post(
        "/oauth2/v2.0/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": original_refresh_token,
            "client_id": main.CLIENT_ID_CONFIDENTIAL,
            "client_secret": main.CLIENT_SECRET,
        },
    )
    assert replay_resp.status_code == 400

    # The new refresh token works.
    second_refresh_resp = client.post(
        "/oauth2/v2.0/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": new_refresh_token,
            "client_id": main.CLIENT_ID_CONFIDENTIAL,
            "client_secret": main.CLIENT_SECRET,
        },
    )
    assert second_refresh_resp.status_code == 200


def test_refresh_token_rotation_preserves_resource_binding(client: TestClient):
    code = _get_auth_code(
        client, main.CLIENT_ID_CONFIDENTIAL, resource=main.MCP_RESOURCE
    )
    token_body = _exchange_code(
        client,
        code,
        main.CLIENT_ID_CONFIDENTIAL,
        client_secret=main.CLIENT_SECRET,
        resource=main.MCP_RESOURCE,
    ).json()

    refresh_resp = client.post(
        "/oauth2/v2.0/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": token_body["refresh_token"],
            "client_id": main.CLIENT_ID_CONFIDENTIAL,
            "client_secret": main.CLIENT_SECRET,
        },
    )
    assert refresh_resp.status_code == 200

    jwks_keys = client.get("/discovery/v2.0/keys").json()["keys"]
    decoded = jose_jwt.decode(
        refresh_resp.json()["access_token"],
        jwks_keys[0],
        algorithms=["RS256"],
        audience=main.MCP_RESOURCE,
        issuer=main.ISSUER,
    )
    assert decoded["aud"] == main.MCP_RESOURCE
