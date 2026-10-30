"""CloudGuard ZT: a small Zero-Trust access decision engine (educational)."""

import json
from dataclasses import asdict, dataclass, fields
from datetime import datetime, timezone

ALLOW, STEP_UP, DENY = "ALLOW", "STEP_UP", "DENY"

ROLES = {"guest": 1, "employee": 2, "admin": 3}
SENSITIVITY = {"low": 1, "medium": 2, "high": 3}
MAX_RISK = {"low": 40, "medium": 25, "high": 10}  # highest risk still allowed
MFA_POINTS = 20
NAME_LIMIT = 64


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
    reasons: tuple
    user: str
    resource: str
    time: str


def parse(data) -> Request:
    """Build a Request from a dict, or raise ValueError describing errors."""
    if not isinstance(data, dict):
        raise ValueError("Request must be a JSON object.")
    names = {f.name for f in fields(Request)}
    missing, unknown = names - set(data), set(data) - names
    if missing or unknown:
        parts = []
        if missing:
            parts.append("missing " + ", ".join(sorted(missing)))
        if unknown:
            names = sorted(map(_label, unknown))
            extra = f" (+{len(names) - 5} more)" if len(names) > 5 else ""
            parts.append("unknown " + ", ".join(names[:5]) + extra)
        raise ValueError("Bad request: " + "; ".join(parts) + ".")
    return Request(**data)


def _label(value) -> str:
    """Return a bounded, log-safe label; escape control characters."""
    if not isinstance(value, str) or not value.strip():
        return "unknown"
    safe = "".join(
        char if char.isprintable() else char.encode("unicode_escape").decode("ascii")
        for char in value.strip()
    )
    return safe[:NAME_LIMIT]


def _name_ok(value) -> bool:
    return (
        isinstance(value, str)
        and value.isprintable()
        and 0 < len(value.strip()) <= NAME_LIMIT
    )


def _country_ok(value) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 2
        and value.isascii()
        and value.isalpha()
    )


def _countries(value):
    """Return a normalized non-empty country set, or None for invalid policy."""
    if isinstance(value, (str, bytes)):
        return None
    try:
        items = list(value)
    except (TypeError, ValueError):
        return None
    if not items or not all(_country_ok(country) for country in items):
        return None
    return frozenset(country.upper() for country in items)


def _errors(request, countries) -> list:
    if not isinstance(request, Request):
        return ["Invalid request object."]

    errors = [
        f"Invalid {name}."
        for name in ("user", "resource")
        if not _name_ok(getattr(request, name))
    ]
    if not (isinstance(request.role, str) and request.role in ROLES):
        errors.append("Unknown role.")
    if not (
        isinstance(request.sensitivity, str)
        and request.sensitivity in SENSITIVITY
    ):
        errors.append("Unknown sensitivity.")
    if not _country_ok(request.country):
        errors.append("Invalid country code.")
    errors.extend(
        f"Invalid {name}."
        for name in ("device_managed", "device_patched", "mfa_verified")
        if type(getattr(request, name)) is not bool
    )
    if countries is None:
        errors.append("Invalid allowed-countries policy.")
    return errors


def decide(request, allowed_countries) -> Decision:
    """Decide ALLOW / STEP_UP / DENY for one request. Fails closed."""
    user = _label(getattr(request, "user", None))
    resource = _label(getattr(request, "resource", None))
    countries = _countries(allowed_countries)

    def out(action, risk, reasons):
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        return Decision(action, risk, tuple(reasons), user, resource, now)

    errors = _errors(request, countries)
    if errors:
        return out(DENY, 100, errors)

    signals = [
        (not request.device_managed, 30, "device not managed"),
        (not request.device_patched, 20, "device not patched"),
        (request.country.upper() not in countries, 25, "unusual country"),
        (not request.mfa_verified, MFA_POINTS, "MFA not verified"),
    ]
    risk = sum(points for hit, points, _ in signals if hit)
    reasons = [f"{why} (+{points})" for hit, points, why in signals if hit]
    limit = MAX_RISK[request.sensitivity]

    if ROLES[request.role] < SENSITIVITY[request.sensitivity]:
        return out(DENY, risk, reasons + ["role not permitted"])

    if request.sensitivity != "low" and not request.mfa_verified:
        if risk - MFA_POINTS <= limit:
            return out(STEP_UP, risk, reasons + ["step-up MFA required"])
        return out(DENY, risk, reasons + ["too risky even after MFA"])

    if risk > limit:
        return out(DENY, risk, reasons + ["risk above limit"])

    return out(ALLOW, risk, reasons or ["all checks passed"])


class AuditLog:
    """Keep decisions and detect repeated denials."""

    def __init__(self):
        self.entries = []

    def record(self, decision: Decision) -> Decision:
        self.entries.append(decision)
        return decision

    def evaluate(self, request, allowed_countries) -> Decision:
        return self.record(decide(request, allowed_countries))

    def reject(self, reason: str, user=None, resource=None) -> Decision:
        """Log a DENY for input that could not be parsed into a Request."""
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        return self.record(
            Decision(DENY, 100, (str(reason),), _label(user), _label(resource), now)
        )

    def count(self, action: str) -> int:
        return sum(entry.action == action for entry in self.entries)

    def alerts(self, limit=3, window=10) -> list:
        """Alert on consecutive denials and multi-resource probing.

        A successful ALLOW resets a user/resource denial streak; STEP_UP does
        not. Probing counts denials across distinct resources in the user's
        most recent `window` requests.
        """
        if type(limit) is not int or limit < 1:
            raise ValueError("limit must be a positive integer")
        if type(window) is not int or window < 1:
            raise ValueError("window must be a positive integer")

        streak, history, found = {}, {}, []
        for entry in self.entries:
            key = (entry.user, entry.resource)
            if entry.action == DENY:
                streak[key] = streak.get(key, 0) + 1
            elif entry.action == ALLOW:
                streak[key] = 0
            history.setdefault(entry.user, []).append(entry)

        for (user, resource), count in sorted(streak.items()):
            if count >= limit:
                found.append(f"{user} denied {count} times in a row on {resource}")

        for user, entries in sorted(history.items()):
            denied = [entry for entry in entries[-window:] if entry.action == DENY]
            resources = {entry.resource for entry in denied}
            if len(denied) >= limit and len(resources) >= 2:
                found.append(
                    f"{user} denied {len(denied)} times across "
                    f"{len(resources)} resources (probing)"
                )
        return found

    def to_json(self) -> str:
        return json.dumps([asdict(entry) for entry in self.entries], indent=2)
