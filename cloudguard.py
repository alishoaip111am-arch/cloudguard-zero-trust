"""Educational, explainable zero-trust access decisions."""

from dataclasses import dataclass


@dataclass(frozen=True)
class AccessRequest:
    """Context supplied for one access attempt."""

    subject: str
    resource: str
    identity_verified: bool = False
    mfa_verified: bool = False
    device_trusted: bool = False
    risk_score: int = 0
    session_age_minutes: int = 0
    network_zone: str = "unknown"

    def __post_init__(self) -> None:
        if not self.subject.strip():
            raise ValueError("subject must not be empty")
        if not self.resource.strip():
            raise ValueError("resource must not be empty")
        if not 0 <= self.risk_score <= 100:
            raise ValueError("risk_score must be between 0 and 100")
        if self.session_age_minutes < 0:
            raise ValueError("session_age_minutes must not be negative")
        if not self.network_zone.strip():
            raise ValueError("network_zone must not be empty")


@dataclass(frozen=True)
class AccessPolicy:
    """Limits used when evaluating each request."""

    max_risk_score: int = 40
    max_session_age_minutes: int = 60

    def __post_init__(self) -> None:
        if not 0 <= self.max_risk_score <= 100:
            raise ValueError("max_risk_score must be between 0 and 100")
        if self.max_session_age_minutes < 0:
            raise ValueError("max_session_age_minutes must not be negative")


@dataclass(frozen=True)
class AccessDecision:
    """A decision and the checks that explain it."""

    allowed: bool
    subject: str
    resource: str
    reasons: tuple[str, ...]
    checks: tuple[tuple[str, bool], ...]


def evaluate_access(
    request: AccessRequest,
    policy: AccessPolicy | None = None,
) -> AccessDecision:
    """Evaluate one request; access is granted only when every check passes.

    Network location is included as context for the decision but is never
    sufficient on its own to establish trust or grant access.
    """

    active_policy = policy or AccessPolicy()
    checks = (
        ("Identity is verified", request.identity_verified),
        ("MFA is verified", request.mfa_verified),
        ("Device is trusted", request.device_trusted),
        (
            f"Risk score is at or below {active_policy.max_risk_score}",
            request.risk_score <= active_policy.max_risk_score,
        ),
        (
            "Session age is within "
            f"{active_policy.max_session_age_minutes} minutes",
            request.session_age_minutes
            <= active_policy.max_session_age_minutes,
        ),
    )
    failed_checks = tuple(label for label, passed in checks if not passed)

    if failed_checks:
        reasons = ("Access denied: " + "; ".join(failed_checks) + ".",)
    else:
        reasons = ("Access granted: all required checks passed.",)

    reasons += (
        f"Network zone '{request.network_zone}' was recorded as context only.",
    )
    return AccessDecision(
        allowed=not failed_checks,
        subject=request.subject,
        resource=request.resource,
        reasons=reasons,
        checks=checks,
    )
