"""CloudGuard ZT command line: python main.py [requests.json] [--json]."""

import argparse
import json
import os
import sys

from cloudguard import ALLOW, DENY, STEP_UP, AuditLog, parse

ALLOWED_COUNTRIES = {"LY", "TR"}

BASE = {
    "user": "ali", "role": "employee", "resource": "wiki",
    "sensitivity": "low", "device_managed": True, "device_patched": True,
    "country": "LY", "mfa_verified": True,
}

DEMO = [
    {},
    {"resource": "finance-app", "sensitivity": "medium", "mfa_verified": False},
    {"user": "omar", "resource": "finance-app", "sensitivity": "medium",
     "device_managed": False, "mfa_verified": False},
    {"user": "lina", "role": "guest", "resource": "admin-panel",
     "sensitivity": "high"},
    {"user": "noor", "role": "admin", "resource": "admin-panel",
     "sensitivity": "high", "country": "RU", "device_patched": False},
    {"role": "root"},
] + [{"user": "sam", "role": "guest", "resource": "payroll-db",
      "sensitivity": "high"}] * 3


def show(decision) -> None:
    print(f"[{decision.action:<7}] {decision.user:<10} -> "
          f"{decision.resource:<12} risk {decision.risk:>3}  "
          f"{'; '.join(decision.reasons)}")


def load(path: str) -> list:
    try:
        with open(path, encoding="utf-8") as file:
            data = json.load(file)
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise SystemExit(f"Error: cannot read {path}: {error}") from None
    if not isinstance(data, list) or not data:
        raise SystemExit("Error: JSON must be a non-empty list of requests.")
    return data


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="CloudGuard ZT demo")
    parser.add_argument("file", nargs="?", help="JSON file of requests "
                        "(default: built-in demo)")
    parser.add_argument("--json", action="store_true",
                        help="print only the audit log as valid JSON")
    args = parser.parse_args(argv)

    if args.file is not None:
        items = load(args.file)
    else:
        items = [{**BASE, **item} for item in DEMO]
    log = AuditLog()

    for item in items:
        try:
            log.evaluate(parse(item), ALLOWED_COUNTRIES)
        except ValueError as error:
            known = item if isinstance(item, dict) else {}
            log.reject(str(error), known.get("user"), known.get("resource"))

    if args.json:
        print(log.to_json())
        return 0

    for decision in log.entries:
        show(decision)

    print(f"\nAllowed {log.count(ALLOW)} | Step-up {log.count(STEP_UP)} | "
          f"Denied {log.count(DENY)}")
    for alert in log.alerts():
        print(f"ALERT: {alert}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        # A downstream command (for example, `head`) closed the pipe early.
        # Redirect stdout before interpreter shutdown to avoid a second flush error.
        devnull = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(devnull, sys.stdout.fileno())
        finally:
            os.close(devnull)
        sys.exit(0)
