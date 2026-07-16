"""Pure-unit tests for mcp-client helpers (no network required)."""

import base64
import hashlib

import pytest
from main import extract_code_from_redirect, generate_pkce_pair


class TestGeneratePkcePair:
    """Tests for generate_pkce_pair()"""

    def test_verifier_is_base64url_without_padding(self):
        verifier, _ = generate_pkce_pair()
        # Must not contain padding or non-base64url characters.
        assert "=" not in verifier
        assert "+" not in verifier
        assert "/" not in verifier
        # Should decode cleanly once padding is restored.
        padded = verifier + "=" * (-len(verifier) % 4)
        base64.urlsafe_b64decode(padded)

    def test_verifier_length_within_spec_range(self):
        verifier, _ = generate_pkce_pair()
        assert 43 <= len(verifier) <= 128

    def test_challenge_is_base64url_sha256_of_verifier(self):
        verifier, challenge = generate_pkce_pair()
        expected = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()
        ).decode("utf-8").rstrip("=")
        assert challenge == expected

    def test_challenge_has_no_padding(self):
        _, challenge = generate_pkce_pair()
        assert "=" not in challenge

    def test_pairs_are_random(self):
        verifier1, _ = generate_pkce_pair()
        verifier2, _ = generate_pkce_pair()
        assert verifier1 != verifier2


class TestExtractCodeFromRedirect:
    """Tests for extract_code_from_redirect()"""

    def test_happy_path_returns_code(self):
        location = "http://localhost:9999/callback?code=abc123&state=xyz"
        code = extract_code_from_redirect(location, expected_state="xyz")
        assert code == "abc123"

    def test_state_mismatch_raises(self):
        location = "http://localhost:9999/callback?code=abc123&state=attacker-state"
        with pytest.raises(ValueError, match="State mismatch"):
            extract_code_from_redirect(location, expected_state="expected-state")

    def test_missing_state_raises(self):
        location = "http://localhost:9999/callback?code=abc123"
        with pytest.raises(ValueError, match="State mismatch"):
            extract_code_from_redirect(location, expected_state="expected-state")

    def test_missing_code_raises(self):
        location = "http://localhost:9999/callback?state=xyz"
        with pytest.raises(ValueError, match="No authorization code"):
            extract_code_from_redirect(location, expected_state="xyz")

    def test_missing_location_raises(self):
        with pytest.raises(ValueError, match="Location header"):
            extract_code_from_redirect(None, expected_state="xyz")

    def test_empty_location_raises(self):
        with pytest.raises(ValueError, match="Location header"):
            extract_code_from_redirect("", expected_state="xyz")

    def test_url_encoded_state_with_special_characters_round_trips(self):
        # state values are URL-safe base64 (secrets.token_urlsafe), but they
        # can still contain characters that need encoding, e.g. '+' or '/'
        # from other generators. Simulate a state with characters that must
        # be percent-encoded on the wire, then confirm it round-trips through
        # urlencode -> parse_qs correctly.
        import urllib.parse

        raw_state = "abc+def/ghi=jkl xyz"
        encoded_query = urllib.parse.urlencode({"code": "code-123", "state": raw_state})
        location = f"http://localhost:9999/callback?{encoded_query}"

        code = extract_code_from_redirect(location, expected_state=raw_state)
        assert code == "code-123"
