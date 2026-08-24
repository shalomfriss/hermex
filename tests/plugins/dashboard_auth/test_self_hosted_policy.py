from __future__ import annotations

from copy import deepcopy

import pytest

from hermes_cli.dashboard_auth import AccessDeniedError
from plugins.dashboard_auth.self_hosted.policy import (
    OIDCAuthorizationPolicy,
    read_claim,
)


def test_read_claim_prefers_direct_key_then_traverses_objects():
    claims = {
        "realm_access.roles": ["direct"],
        "realm_access": {"roles": ["nested"]},
    }
    assert read_claim(claims, "realm_access.roles") == ["direct"]
    assert read_claim({"realm_access": {"roles": ["nested"]}}, "realm_access.roles") == ["nested"]
    assert read_claim(claims, "missing.path") is None


def test_read_claim_rejects_array_syntax_and_malformed_intermediate_values():
    with pytest.raises(ValueError, match="array-index"):
        read_claim({"groups": ["admin"]}, "groups[0]")
    with pytest.raises(ValueError, match="traverse"):
        read_claim({"realm_access": "not-an-object"}, "realm_access.roles")


def test_policy_parser_defaults_and_rejects_unknown_or_malformed_values():
    policy = OIDCAuthorizationPolicy.from_mapping({})
    assert policy.require_email is False
    assert policy.groups_claim == "groups"
    assert policy.roles_claim == "realm_access.roles"
    assert policy.max_auth_age_seconds == 0

    with pytest.raises(ValueError, match="unknown authorization policy"):
        OIDCAuthorizationPolicy.from_mapping({"surprise": True})
    with pytest.raises(ValueError, match="require_email"):
        OIDCAuthorizationPolicy.from_mapping({"require_email": "yes"})
    with pytest.raises(ValueError, match="required_groups"):
        OIDCAuthorizationPolicy.from_mapping({"required_groups": "admins"})
    with pytest.raises(ValueError, match="max_auth_age_seconds"):
        OIDCAuthorizationPolicy.from_mapping({"max_auth_age_seconds": -1})


@pytest.mark.parametrize(
    "claims, config, reason",
    [
        ({}, {"require_email": True}, "email_required"),
        ({"email": "a@example.com"}, {"require_verified_email": True}, "email_unverified"),
        (
            {"email": "a@example.com", "email_verified": "true"},
            {"require_verified_email": True},
            "claim_malformed",
        ),
        (
            {"email": "a@evil-example.com"},
            {"allowed_email_domains": ["example.com"]},
            "email_domain_denied",
        ),
        (
            {"email": "a@sub.example.com"},
            {"allowed_email_domains": ["example.com"]},
            "email_domain_denied",
        ),
    ],
)
def test_email_policy_denials_are_stable(claims, config, reason):
    policy = OIDCAuthorizationPolicy.from_mapping(config)
    with pytest.raises(AccessDeniedError) as excinfo:
        policy.authorize(claims)
    assert excinfo.value.reason == reason


def test_email_domain_matching_is_exact_and_case_insensitive():
    policy = OIDCAuthorizationPolicy.from_mapping(
        {
            "require_email": True,
            "require_verified_email": True,
            "allowed_email_domains": ["Example.COM"],
        }
    )
    identity = policy.authorize(
        {"email": "Alice@EXAMPLE.com", "email_verified": True}
    )
    assert identity["email"] == "Alice@EXAMPLE.com"


@pytest.mark.parametrize("claim_value", ["admins", ["admins", "operators"]])
def test_groups_accept_string_or_list_with_all_required_semantics(claim_value):
    policy = OIDCAuthorizationPolicy.from_mapping(
        {"required_groups": ["admins"]}
    )
    expected = (claim_value,) if isinstance(claim_value, str) else tuple(claim_value)
    assert policy.authorize({"groups": claim_value})["groups"] == expected


def test_groups_and_nested_roles_are_required_and_malformed_shapes_fail_closed():
    policy = OIDCAuthorizationPolicy.from_mapping(
        {
            "required_groups": ["admins", "operators", "admins"],
            "roles_claim": "realm_access.roles",
            "required_roles": ["dashboard-admin"],
        }
    )
    claims = {
        "groups": ["admins", "operators"],
        "realm_access": {"roles": ["dashboard-admin", "viewer"]},
    }
    original = deepcopy(claims)
    identity = policy.authorize(claims)
    assert identity["groups"] == ("admins", "operators")
    assert identity["roles"] == ("dashboard-admin", "viewer")
    assert claims == original

    with pytest.raises(AccessDeniedError) as missing:
        policy.authorize({"groups": ["admins"], "realm_access": {"roles": ["dashboard-admin"]}})
    assert missing.value.reason == "group_required"

    malformed = OIDCAuthorizationPolicy.from_mapping({"required_groups": ["admins"]})
    with pytest.raises(AccessDeniedError) as bad_shape:
        malformed.authorize({"groups": {"name": "admins"}})
    assert bad_shape.value.reason == "claim_malformed"


@pytest.mark.parametrize(
    "config, claims, reason",
    [
        ({"allowed_tenants": ["tenant-a"]}, {"tid": "tenant-b"}, "tenant_denied"),
        ({"allowed_acr_values": ["urn:mfa"]}, {"acr": "urn:pwd"}, "acr_denied"),
        ({"require_mfa": True}, {"amr": ["pwd"]}, "mfa_required"),
        ({"require_mfa": True}, {"amr": {"method": "mfa"}}, "claim_malformed"),
        ({"max_auth_age_seconds": 300}, {}, "auth_too_old"),
        ({"max_auth_age_seconds": 300}, {"auth_time": "old"}, "claim_malformed"),
    ],
)
def test_tenant_acr_mfa_and_auth_age_denials(config, claims, reason):
    policy = OIDCAuthorizationPolicy.from_mapping(config)
    with pytest.raises(AccessDeniedError) as excinfo:
        policy.authorize(claims, now=1_000)
    assert excinfo.value.reason == reason


def test_tenant_acr_mfa_and_auth_age_acceptance_with_clock_skew():
    policy = OIDCAuthorizationPolicy.from_mapping(
        {
            "allowed_tenants": ["tenant-a"],
            "allowed_acr_values": ["urn:mfa"],
            "require_mfa": True,
            "max_auth_age_seconds": 300,
        }
    )
    identity = policy.authorize(
        {
            "tid": "tenant-a",
            "acr": "urn:mfa",
            "amr": ["pwd", "mfa"],
            "auth_time": 640,
        },
        now=1_000,
    )
    assert identity["tenant"] == "tenant-a"


@pytest.mark.parametrize("single_factor", ["otp", "hwk", "swk", "fpt", "face", "iris"])
def test_mfa_rejects_single_authentication_methods(single_factor):
    policy = OIDCAuthorizationPolicy.from_mapping({"require_mfa": True})

    with pytest.raises(AccessDeniedError) as excinfo:
        policy.authorize({"amr": [single_factor]})

    assert excinfo.value.reason == "mfa_required"


def test_mfa_accepts_explicit_mfa_assurance_marker():
    policy = OIDCAuthorizationPolicy.from_mapping({"require_mfa": True})

    assert policy.authorize({"amr": ["pwd", "mfa"]})["amr"] == ("pwd", "mfa")


def test_auth_time_future_clock_skew_boundary():
    policy = OIDCAuthorizationPolicy.from_mapping({"max_auth_age_seconds": 300})

    assert policy.authorize({"auth_time": 1_060}, now=1_000)["email"] == ""
    with pytest.raises(AccessDeniedError) as excinfo:
        policy.authorize({"auth_time": 1_060.001}, now=1_000)

    assert excinfo.value.reason == "auth_time_in_future"


def test_disabled_policy_preserves_current_claims_behavior():
    claims = {"sub": "u1", "email_verified": "not-a-bool", "groups": {"odd": True}}
    assert OIDCAuthorizationPolicy.from_mapping({}).authorize(claims)["email"] == ""
