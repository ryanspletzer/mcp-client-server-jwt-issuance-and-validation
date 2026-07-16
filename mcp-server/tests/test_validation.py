"""
Tests for JWT validation logic in main.py.

All tests generate their own RSA keypair(s) and mint tokens locally, then
monkeypatch main.jwks_cache / main.get_jwks so no real identity provider
or network access is required.
"""

import time

import main
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwk, jwt


def _generate_rsa_keypair():
    """Generate an RSA keypair and return (private_pem, public_pem)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    return private_pem, public_pem


def _jwk_for(public_pem: str, kid: str) -> dict:
    """Build a JWKS-style key entry from a PEM public key."""
    key_dict = jwk.construct(public_pem, algorithm="RS256").to_dict()
    key_dict["kid"] = kid
    key_dict["use"] = "sig"
    key_dict["alg"] = "RS256"
    return key_dict


def _mint_token(
    private_pem: str,
    kid: str,
    *,
    sub: str = "user-123",
    aud: str = "confidential-client-id",
    issuer: str = main.ISSUER,
    expires_in: int = 3600,
) -> str:
    """Mint a JWT signed with private_pem, headers carrying kid."""
    now = int(time.time())
    claims = {
        "sub": sub,
        "aud": aud,
        "iss": issuer,
        "iat": now,
        "exp": now + expires_in,
        "name": "Test User",
    }
    return jwt.encode(claims, private_pem, algorithm="RS256", headers={"kid": kid})


@pytest.fixture
def keypair():
    """A single RSA keypair with kid 'kid-1'."""
    private_pem, public_pem = _generate_rsa_keypair()
    return {
        "kid": "kid-1",
        "private_pem": private_pem,
        "public_pem": public_pem,
        "jwks": {"keys": [_jwk_for(public_pem, "kid-1")]},
    }


@pytest.fixture(autouse=True)
def reset_jwks_cache():
    """Ensure each test starts with a clean JWKS cache."""
    original = main.jwks_cache
    main.jwks_cache = None
    yield
    main.jwks_cache = original


# ---------------------------------------------------------------------------
# validate_token
# ---------------------------------------------------------------------------


async def test_valid_token_returns_claims(keypair, monkeypatch):
    monkeypatch.setattr(main, "jwks_cache", keypair["jwks"])
    token = _mint_token(keypair["private_pem"], keypair["kid"])

    claims = await main.validate_token(token)

    assert claims["sub"] == "user-123"
    assert claims["aud"] == "confidential-client-id"


async def test_wrong_kid_raises_no_matching_key(keypair, monkeypatch):
    monkeypatch.setattr(main, "jwks_cache", keypair["jwks"])

    async def fake_get_jwks(force_refresh: bool = False):
        # Simulate a refresh that returns the same JWKS (kid still absent).
        return keypair["jwks"]

    monkeypatch.setattr(main, "get_jwks", fake_get_jwks)

    token = _mint_token(keypair["private_pem"], "unknown-kid")

    with pytest.raises(ValueError, match="No matching signing key found"):
        await main.validate_token(token)


async def test_kid_rotation_forces_refresh_and_succeeds(keypair, monkeypatch):
    """Cache holds an OLD jwks (without the new kid). A forced refresh
    should pick up the new key and validation should succeed."""
    old_jwks = {"keys": []}
    monkeypatch.setattr(main, "jwks_cache", old_jwks)

    calls = {"count": 0}

    async def fake_get_jwks(force_refresh: bool = False):
        calls["count"] += 1
        if force_refresh:
            return keypair["jwks"]
        return old_jwks

    monkeypatch.setattr(main, "get_jwks", fake_get_jwks)

    token = _mint_token(keypair["private_pem"], keypair["kid"])

    claims = await main.validate_token(token)

    assert claims["sub"] == "user-123"
    assert calls["count"] == 2  # initial lookup + forced refresh retry


async def test_expired_token_raises(keypair, monkeypatch):
    monkeypatch.setattr(main, "jwks_cache", keypair["jwks"])
    token = _mint_token(keypair["private_pem"], keypair["kid"], expires_in=-3600)

    with pytest.raises(ValueError, match="Token validation failed"):
        await main.validate_token(token)


async def test_wrong_issuer_raises(keypair, monkeypatch):
    monkeypatch.setattr(main, "jwks_cache", keypair["jwks"])
    token = _mint_token(
        keypair["private_pem"], keypair["kid"], issuer="http://evil.example.com"
    )

    with pytest.raises(ValueError, match="Token validation failed"):
        await main.validate_token(token)


async def test_invalid_audience_raises(keypair, monkeypatch):
    monkeypatch.setattr(main, "jwks_cache", keypair["jwks"])
    token = _mint_token(keypair["private_pem"], keypair["kid"], aud="some-other-client")

    with pytest.raises(ValueError, match="Invalid audience"):
        await main.validate_token(token)


async def test_bad_signature_raises(keypair, monkeypatch):
    """A token whose header claims the right kid, but was actually signed
    by a different key, must fail signature verification."""
    other_private_pem, _ = _generate_rsa_keypair()
    monkeypatch.setattr(main, "jwks_cache", keypair["jwks"])

    # Signed with a different private key, but headers claim kid-1.
    token = _mint_token(other_private_pem, keypair["kid"])

    with pytest.raises(ValueError, match="Token validation failed"):
        await main.validate_token(token)


# ---------------------------------------------------------------------------
# Tool-level error paths (get_user_info / echo)
# ---------------------------------------------------------------------------


def _tool_fn(tool):
    """Return the underlying coroutine function for a FastMCP tool.

    FastMCP 2.x wraps tools in FunctionTool objects exposing `.fn`;
    FastMCP 3.x returns the original function unchanged.
    """
    return getattr(tool, "fn", tool)


async def test_get_user_info_returns_claims_on_valid_token(keypair, monkeypatch):
    monkeypatch.setattr(main, "jwks_cache", keypair["jwks"])
    token = _mint_token(keypair["private_pem"], keypair["kid"])

    result = await _tool_fn(main.get_user_info)(auth_token=token)

    assert result["user_id"] == "user-123"
    assert result["name"] == "Test User"


async def test_get_user_info_returns_error_on_invalid_token(keypair, monkeypatch):
    monkeypatch.setattr(main, "jwks_cache", keypair["jwks"])
    token = _mint_token(keypair["private_pem"], "unknown-kid")

    async def fake_get_jwks(force_refresh: bool = False):
        return keypair["jwks"]

    monkeypatch.setattr(main, "get_jwks", fake_get_jwks)

    result = await _tool_fn(main.get_user_info)(auth_token=token)

    assert "error" in result
    assert "No matching signing key found" in result["error"]


async def test_echo_returns_authenticated_message_on_valid_token(keypair, monkeypatch):
    monkeypatch.setattr(main, "jwks_cache", keypair["jwks"])
    token = _mint_token(keypair["private_pem"], keypair["kid"])

    result = await _tool_fn(main.echo)(message="hi there", auth_token=token)

    assert result == "[Authenticated as Test User] Echo: hi there"


async def test_echo_returns_auth_failure_message_on_invalid_token(keypair, monkeypatch):
    monkeypatch.setattr(main, "jwks_cache", keypair["jwks"])
    token = _mint_token(keypair["private_pem"], keypair["kid"], expires_in=-3600)

    result = await _tool_fn(main.echo)(message="hi there", auth_token=token)

    assert result.startswith("Authentication failed: ")
