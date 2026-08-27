"""Behavior tests for provider-scoped refresh-token ownership proofs."""
from __future__ import annotations

from hermes_cli.dashboard_auth.refresh_binding import (
    mint_refresh_binding,
    resolve_refresh_owner,
)


def test_binding_authenticates_provider_and_exact_refresh_token():
    binding = mint_refresh_binding(provider="owner", refresh_token="rt-one")

    assert resolve_refresh_owner(binding=binding, refresh_token="rt-one") == "owner"
    assert resolve_refresh_owner(binding=binding, refresh_token="rt-two") is None


def test_binding_rejects_mutable_provider_and_tampered_proof():
    binding = mint_refresh_binding(provider="owner", refresh_token="rt-one")
    version, encoded_provider, token_digest, signature = binding.split(".")
    tampered = ".".join((version, encoded_provider + "A", token_digest, signature))

    assert resolve_refresh_owner(binding="owner", refresh_token="rt-one") is None
    assert resolve_refresh_owner(binding=tampered, refresh_token="rt-one") is None


def test_empty_or_malformed_binding_fails_closed():
    assert mint_refresh_binding(provider="", refresh_token="rt") == ""
    assert mint_refresh_binding(provider="owner", refresh_token="") == ""
    assert resolve_refresh_owner(binding=None, refresh_token="rt") is None
    assert resolve_refresh_owner(binding="not-a-proof", refresh_token="rt") is None
