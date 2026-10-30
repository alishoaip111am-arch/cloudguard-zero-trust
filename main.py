"""CloudGuard ZT: Command-line Zero-Trust demonstration."""

import argparse
import json
import sys
from pathlib import Path

from cloudguard import ALLOW, DENY, STEP_UP, AuditLog, Request, evaluate

ALLOWED_COUNTRIES = {"LY", "TR"}


def show_result(label: str, request, log: AuditLog) -> None:
    """Evaluate a request and display its decision."""
    decision = evaluate(request, ALLOWED_COUNTRIES, log)

    print("\n" + "=" * 65)
    print(label)
    print("=" * 65)
    print(f"User:       {decision.user}")
    print(f"Resource:   {decision.resource}")
    print(f"Decision:   {decision.action}")
    print(f"Risk score: {decision.risk}")

    for reason in decision.reasons:
        print(f"  - {reason}")

    if decision.action == STEP_UP:
        print("\nAction required: Complete MFA and submit again.")
    elif decision.action == DENY:
        print("\nAccess denied.")


def run_demo(log: AuditLog) -> None:
    """Run the built-in demonstration scenarios."""
    base = {
        "user": "ali",
        "role": "employee",
        "resource": "wiki",
        "sensitivity": "low",
        "device_managed": True,
        "device_patched": True,
        "country": "LY",
        "mfa_verified": True,
    }

    scenarios = [
        ("1. Normal request from a trusted device", base),
        ("2. Medium resource without MFA",
         {**base, "sensitivity": "medium", "mfa_verified": False}),
        ("3. Unmanaged device and missing MFA",
         {**base, "user": "omar", "sensitivity": "medium",
          "device_managed": False, "mfa_verified": False}),
        ("4. Guest attempts to access a high-sensitivity resource",
         {**base, "user": "lina", "role": "guest", "sensitivity": "high"}),
        ("5. Admin using an unpatched device from an unusual country",
         {**base, "user": "noor", "role": "admin", "sensitivity": "high",
          "country": "RU", "device_patched": False}),
        ("6. Invalid role", {**base, "role": "root"}),
    ]

    for label, data in scenarios:
        show_result(label, Request(**data), log)

    for attempt in range(1, 4):
        data = {**base, "user": "sam", "role": "guest",
                "resource": "payroll-db", "sensitivity": "high"}
        show_result(f"7.{attempt} Repeated attempt to access payroll database",
                    Request(**data), log)


def run_file(file_path: str, log: AuditLog) -> None:
    """Load and evaluate access requests from a JSON file."""
    path = Path(file_path)

    try:
        with path.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except FileNotFoundError:
        raise ValueError(f"File not found: {path}") from None
    except json.JSONDecodeError as error:
        raise ValueError(
            f"Invalid JSON at line {error.lineno}, column {error.colno}."
        ) from None
    except OSError as error:
        raise ValueError(f"Could not read file: {error}") from None

    if not isinstance(data, list):
        raise ValueError("JSON root must be a list of access requests.")
    if not data:
        raise ValueError("The JSON file contains no access requests.")

    print(f"Loaded {len(data)} request(s) from {path}")

    for index, item in enumerate(data, start=1):
        print(f"\nProcessing request {index}/{len(data)}")

        request = None
        if isinstance(item, dict):
            try:
                request = Request(**item)
            except (TypeError, ValueError):
                request = None

        if request is None:
            show_result(f"Request {index}: Invalid request format", None, log)
        else:
            show_result(f"Request {index}: JSON access request", request, log)


def show_summary(log: AuditLog) -> None:
    """Display the audit summary and repeated-denial alerts."""
    print("\n" + "=" * 65)
    print("AUDIT SUMMARY")
    print("=" * 65)
    print(f"Allowed:  {log.count(ALLOW)}")
    print(f"Step-up:  {log.count(STEP_UP)}")
    print(f"Denied:   {log.count(DENY)}")

    alerts = log.repeated_denials()
    if alerts:
        print("\nSECURITY ALERTS")
        for user, resource, count in alerts:
            print(f"ALERT: {user} was denied {count} consecutive "
                  f"times on {resource}.")
    else:
        print("\nNo repeated-denial alerts.")


def main() -> int:
    """Parse command-line options and run CloudGuard."""
    parser = argparse.ArgumentParser(
        description="CloudGuard ZT - Zero-Trust access decision engine."
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--file", metavar="PATH",
                        help="Read access requests from a JSON file.")
    source.add_argument("--demo", action="store_true",
                        help="Run the built-in demonstration scenarios.")
    parser.add_argument("--json", action="store_true",
                        help="Print the audit log as JSON.")

    args = parser.parse_args()
    log = AuditLog()

    try:
        if args.file:
            run_file(args.file, log)
        else:
            run_demo(log)

        show_summary(log)

        if args.json:
            print("\nAUDIT LOG JSON")
            print(log.to_json())
    except ValueError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
