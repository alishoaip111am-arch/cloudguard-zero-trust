
"""CloudGuard ZT: Zero-Trust Access Decision Engine.

Educational simulator, not production security software.
"""

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Dict, FrozenSet, Iterable, List, Tuple

ALLOW = "ALLOW"
STEP_UP = "STEP_UP"
DENY = "DENY"

ROLE_LEVEL = {
    "guest": 1,
    "employee": 2,
    "admin": 3,
}

SENSITIVITY_LEVEL = {
    "low": 1,
    "medium": 2,
    "high": 3,
}

# Maximum acceptable risk for each resource sensitivity.
ALLOW_MAX = {
    "low": 40,
    "medium": 25,
    "high": 10,
}

RISK_UNMANAGED_DEVICE = 30
RISK_UNPATCHED_DEVICE = 20
RISK_UNUSUAL_COUNTRY = 25
RISK_NO_MFA = 20

REPEATED_DENIAL_LIMIT = 3


@dataclass(frozen=True)
class Request:
    user: str
    role: str
    resource: str
    sensitivity: str
    device_managed: bool
    device_patched: bool
    country: str
    mfa_verified: bool


@dataclass(frozen=True)
class Decision:
    action: str
    risk: int
    reasons: Tuple[str, ...]
    user: str
    resource: str
    timestamp: str


def _now() -> str:
    """Return the current UTC timestamp."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _who(request) -> Tuple[str, str]:
    """Extract safe user and resource labels for audit logging."""
    user = getattr(request, "user", None)
    resource = getattr(request, "resource", None)

    return (
        user.strip()
        if isinstance(user, str) and user.strip()
        else "unknown",
        resource.strip()
        if isinstance(resource, str) and resource.strip()
        else "unknown",
    )


def _normalize_countries(allowed_countries):
    """Validate and normalize the allowed-country policy."""
    if isinstance(allowed_countries, (str, bytes)):
        return None

    if not isinstance(allowed_countries, Iterable):
        return None

    try:
        countries = tuple(allowed_countries)
    except (TypeError, ValueError):
        return None

    for country in countries:
        if (
            not isinstance(country, str)
            or len(country) != 2
            or not country.isascii()
            or not country.isalpha()
        ):
            return None

    return frozenset(country.upper() for country in countries)


class AuditLog:
    """Store access decisions and detect repeated denials."""

    def __init__(self) -> None:
        self.entries: List[Decision] = []

    def record(self, decision: Decision) -> None:
        self.entries.append(decision)

    def count(self, action: str) -> int:
        return sum(
            1 for entry in self.entries
            if entry.action == action
        )

    def repeated_denials(
        self,
        limit: int = REPEATED_DENIAL_LIMIT,
    ) -> List[Tuple[str, str, int]]:
        """Return user/resource pairs with a current denial streak."""
        if type(limit) is not int or limit < 1:
            raise ValueError("limit must be a positive integer")

        streaks: Dict[Tuple[str, str], int] = {}

        for entry in self.entries:
            key = (entry.user, entry.resource)

            if entry.action == DENY:
                streaks[key] = streaks.get(key, 0) + 1
            else:
                streaks[key] = 0

        return sorted(
            (user, resource, count)
            for (user, resource), count in streaks.items()
            if count >= limit
        )

    def to_json(self) -> str:
        """Export all audit entries as JSON."""
        return json.dumps(
            [asdict(entry) for entry in self.entries],
            indent=2,
        )


def _validate(request, allowed_countries) -> List[str]:
    """Validate request fields and security policy."""
    errors = []

    if not isinstance(request, Request):
        return ["Invalid request object."]

    if not isinstance(request.user, str) or not request.user.strip():
        errors.append("Invalid user.")

    if (
        not isinstance(request.resource, str)
        or not request.resource.strip()
    ):
        errors.append("Invalid resource.")

    if (
        not isinstance(request.role, str)
        or request.role not in ROLE_LEVEL
    ):
        errors.append("Unknown role.")

    if (
        not isinstance(request.sensitivity, str)
        or request.sensitivity not in SENSITIVITY_LEVEL
    ):
        errors.append("Unknown resource sensitivity.")

    if (
        not isinstance(request.country, str)
        or len(request.country) != 2
        or not request.country.isascii()
        or not request.country.isalpha()
    ):
        errors.append("Invalid country code.")

    for name in (
        "device_managed",
        "device_patched",
        "mfa_verified",
    ):
        if type(getattr(request, name)) is not bool:
            errors.append(f"Invalid {name} value.")

    if allowed_countries is None:
        errors.append("Invalid allowed-countries policy.")

    return errors


def _calculate_risk(
    request: Request,
    allowed: FrozenSet[str],
) -> Tuple[int, List[str]]:
    """Calculate risk points and explain every risk signal."""
    risk = 0
    reasons = []

    if not request.device_managed:
        risk += RISK_UNMANAGED_DEVICE
        reasons.append(
            f"Device is not managed (+{RISK_UNMANAGED_DEVICE})."
        )

    if not request.device_patched:
        risk += RISK_UNPATCHED_DEVICE
        reasons.append(
            f"Device is not patched (+{RISK_UNPATCHED_DEVICE})."
        )

    if request.country.upper() not in allowed:
        risk += RISK_UNUSUAL_COUNTRY
        reasons.append(
            f"Country is not in the allowed list (+{RISK_UNUSUAL_COUNTRY})."
        )

    if not request.mfa_verified:
        risk += RISK_NO_MFA
        reasons.append(
            f"MFA is not verified (+{RISK_NO_MFA})."
        )

    return risk, reasons


def decide(
    request: Request,
    allowed_countries,
) -> Decision:
    """Evaluate a request without recording it. Fails closed."""

    user, resource = _who(request)
    allowed = _normalize_countries(allowed_countries)

    def result(action, risk, reasons):
        return Decision(
            action=action,
            risk=risk,
            reasons=tuple(reasons),
            user=user,
            resource=resource,
            timestamp=_now(),
        )

    errors = _validate(request, allowed)

    if errors:
        return result(DENY, 100, errors)

    # Enforce role-based access before risk evaluation.
    if (
        ROLE_LEVEL[request.role]
        < SENSITIVITY_LEVEL[request.sensitivity]
    ):
        return result(
            DENY,
            0,
            ["Role does not have permission for this resource."],
        )

    risk, reasons = _calculate_risk(request, allowed)
    maximum = ALLOW_MAX[request.sensitivity]

    mfa_required = request.sensitivity in ("medium", "high")

    # MFA step-up: request additional verification if MFA alone
    # would reduce the risk to an acceptable level.
    if mfa_required and not request.mfa_verified:
        if risk - RISK_NO_MFA <= maximum:
            return result(
                STEP_UP,
                risk,
                reasons + [
                    "Additional MFA verification is required."
                ],
            )

        return result(
            DENY,
            risk,
            reasons + [
                "Risk remains too high even after MFA."
            ],
        )

    if risk > maximum:
        return result(
            DENY,
            risk,
            reasons + ["Risk exceeds the allowed threshold."],
        )

    return result(
        ALLOW,
        risk,
        reasons or ["All access checks passed."],
    )


def evaluate(
    request: Request,
    allowed_countries,
    log: AuditLog,
) -> Decision:
    """Evaluate a request and record its decision."""
    decision = decide(request, allowed_countries)
    log.record(decision)
    return decision
