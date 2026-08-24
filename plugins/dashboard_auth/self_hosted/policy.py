"""Pure enterprise OIDC claim extraction and admission policy."""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Mapping

from hermes_cli.dashboard_auth import AccessDeniedError

_CLOCK_SKEW_SECONDS = 60
_MFA_ASSURANCE_MARKERS = frozenset({"mfa"})


def _validate_claim_path(path: str, *, field: str = "claim path") -> str:
    if not isinstance(path, str) or not path or any(not part for part in path.split(".")):
        raise ValueError(f"{field} must be a non-empty dot-separated string")
    if "[" in path or "]" in path:
        raise ValueError(f"{field} does not support array-index syntax")
    return path


def read_claim(claims: Mapping[str, Any], path: str) -> Any:
    """Read a direct claim key first, then traverse dot-separated objects."""
    _validate_claim_path(path)
    if path in claims:
        return claims[path]
    current: Any = claims
    for part in path.split("."):
        if not isinstance(current, Mapping):
            raise ValueError(f"cannot traverse claim path {path!r} through a non-object")
        if part not in current:
            return None
        current = current[part]
    return current


def _string_list(value: Any, *, configured: bool) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, list) and all(isinstance(item, str) for item in value):
        values = value
    elif configured:
        raise AccessDeniedError("claim_malformed")
    else:
        return ()
    return tuple(dict.fromkeys(item for item in values if item))


def _config_string_list(mapping: Mapping[str, Any], key: str) -> tuple[str, ...]:
    value = mapping.get(key, [])
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"{key} must be a list of non-empty strings")
    return tuple(dict.fromkeys(value))


def _config_bool(mapping: Mapping[str, Any], key: str) -> bool:
    value = mapping.get(key, False)
    if not isinstance(value, bool):
        raise ValueError(f"{key} must be a boolean")
    return value


@dataclass(frozen=True)
class OIDCAuthorizationPolicy:
    require_email: bool = False
    require_verified_email: bool = False
    allowed_email_domains: tuple[str, ...] = ()
    groups_claim: str = "groups"
    required_groups: tuple[str, ...] = ()
    roles_claim: str = "realm_access.roles"
    required_roles: tuple[str, ...] = ()
    tenant_claim: str = "tid"
    allowed_tenants: tuple[str, ...] = ()
    acr_claim: str = "acr"
    allowed_acr_values: tuple[str, ...] = ()
    amr_claim: str = "amr"
    require_mfa: bool = False
    max_auth_age_seconds: int = 0

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any] | None) -> "OIDCAuthorizationPolicy":
        if raw is None:
            raw = {}
        if not isinstance(raw, Mapping):
            raise ValueError("authorization policy must be an object")
        known = set(cls.__dataclass_fields__)
        unknown = sorted(set(raw) - known)
        if unknown:
            raise ValueError(f"unknown authorization policy keys: {', '.join(unknown)}")
        max_auth_age = raw.get("max_auth_age_seconds", 0)
        if isinstance(max_auth_age, bool) or not isinstance(max_auth_age, int) or max_auth_age < 0:
            raise ValueError("max_auth_age_seconds must be a non-negative integer")
        return cls(
            require_email=_config_bool(raw, "require_email"),
            require_verified_email=_config_bool(raw, "require_verified_email"),
            allowed_email_domains=tuple(
                domain.lower() for domain in _config_string_list(raw, "allowed_email_domains")
            ),
            groups_claim=_validate_claim_path(raw.get("groups_claim", "groups"), field="groups_claim"),
            required_groups=_config_string_list(raw, "required_groups"),
            roles_claim=_validate_claim_path(raw.get("roles_claim", "realm_access.roles"), field="roles_claim"),
            required_roles=_config_string_list(raw, "required_roles"),
            tenant_claim=_validate_claim_path(raw.get("tenant_claim", "tid"), field="tenant_claim"),
            allowed_tenants=_config_string_list(raw, "allowed_tenants"),
            acr_claim=_validate_claim_path(raw.get("acr_claim", "acr"), field="acr_claim"),
            allowed_acr_values=_config_string_list(raw, "allowed_acr_values"),
            amr_claim=_validate_claim_path(raw.get("amr_claim", "amr"), field="amr_claim"),
            require_mfa=_config_bool(raw, "require_mfa"),
            max_auth_age_seconds=max_auth_age,
        )

    @property
    def enforced(self) -> bool:
        return bool(
            self.require_email
            or self.require_verified_email
            or self.allowed_email_domains
            or self.required_groups
            or self.required_roles
            or self.allowed_tenants
            or self.allowed_acr_values
            or self.require_mfa
            or self.max_auth_age_seconds
        )

    def authorize(
        self, claims: Mapping[str, Any], *, now: float | None = None
    ) -> dict[str, Any]:
        """Return normalized identity attributes or raise a stable denial."""
        email_value = claims.get("email")
        email = email_value if isinstance(email_value, str) else ""
        if (self.require_email or self.require_verified_email or self.allowed_email_domains) and not email:
            raise AccessDeniedError("email_required")
        if self.require_verified_email:
            verified = claims.get("email_verified")
            if verified is not None and not isinstance(verified, bool):
                raise AccessDeniedError("claim_malformed")
            if verified is not True:
                raise AccessDeniedError("email_unverified")
        if self.allowed_email_domains:
            if "@" not in email:
                raise AccessDeniedError("email_domain_denied")
            domain = email.rsplit("@", 1)[1].lower()
            if domain not in self.allowed_email_domains:
                raise AccessDeniedError("email_domain_denied")

        groups = self._claim_strings(claims, self.groups_claim, bool(self.required_groups))
        if self.required_groups and not set(self.required_groups).issubset(groups):
            raise AccessDeniedError("group_required")
        roles = self._claim_strings(claims, self.roles_claim, bool(self.required_roles))
        if self.required_roles and not set(self.required_roles).issubset(roles):
            raise AccessDeniedError("role_required")

        tenant = self._claim_string(claims, self.tenant_claim, bool(self.allowed_tenants))
        if self.allowed_tenants and tenant not in self.allowed_tenants:
            raise AccessDeniedError("tenant_denied")
        acr = self._claim_string(claims, self.acr_claim, bool(self.allowed_acr_values))
        if self.allowed_acr_values and acr not in self.allowed_acr_values:
            raise AccessDeniedError("acr_denied")

        amr = self._claim_strings(claims, self.amr_claim, self.require_mfa)
        # RFC 8176's ``mfa`` value asserts multiple-factor authentication.
        # Individual methods such as otp, hwk, or face identify only one
        # method and cannot prove that a second independent factor occurred.
        if self.require_mfa and not (_MFA_ASSURANCE_MARKERS & set(amr)):
            raise AccessDeniedError("mfa_required")

        if self.max_auth_age_seconds > 0:
            auth_time = claims.get("auth_time")
            if auth_time is None:
                raise AccessDeniedError("auth_too_old")
            if isinstance(auth_time, bool) or not isinstance(auth_time, (int, float)):
                raise AccessDeniedError("claim_malformed")
            current = time.time() if now is None else now
            if float(auth_time) - current > _CLOCK_SKEW_SECONDS:
                raise AccessDeniedError("auth_time_in_future")
            if current - float(auth_time) > self.max_auth_age_seconds + _CLOCK_SKEW_SECONDS:
                raise AccessDeniedError("auth_too_old")

        return {
            "email": email,
            "groups": groups,
            "roles": roles,
            "tenant": tenant,
            "acr": acr,
            "amr": amr,
        }

    @staticmethod
    def _claim_strings(
        claims: Mapping[str, Any], path: str, configured: bool
    ) -> tuple[str, ...]:
        if not configured:
            return ()
        try:
            value = read_claim(claims, path)
        except ValueError as exc:
            raise AccessDeniedError("claim_malformed") from exc
        return _string_list(value, configured=True)

    @staticmethod
    def _claim_string(claims: Mapping[str, Any], path: str, configured: bool) -> str:
        if not configured:
            return ""
        try:
            value = read_claim(claims, path)
        except ValueError as exc:
            raise AccessDeniedError("claim_malformed") from exc
        if value is None:
            return ""
        if not isinstance(value, str):
            raise AccessDeniedError("claim_malformed")
        return value
