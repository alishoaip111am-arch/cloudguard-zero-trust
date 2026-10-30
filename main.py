"""Command-line entry point for the CloudGuard ZT learning demo."""

import argparse
import json
from dataclasses import asdict
from typing import Sequence

from cloudguard import AccessRequest, evaluate_access


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Make an explainable zero-trust access decision."
    )
    parser.add_argument("--subject", default="learner", help="Identity requesting access")
    parser.add_argument("--resource", default="training-data", help="Requested resource")
    parser.add_argument(
        "--identity-verified",
        action="store_true",
        help="Mark the identity as verified",
    )
    parser.add_argument(
        "--mfa-verified",
        action="store_true",
        help="Mark multi-factor authentication as verified",
    )
    parser.add_argument(
        "--device-trusted",
        action="store_true",
        help="Mark the device as trusted",
    )
    parser.add_argument(
        "--risk-score",
        type=int,
        default=0,
        help="Risk score from 0 to 100 (default: 0)",
    )
    parser.add_argument(
        "--session-age-minutes",
        type=int,
        default=0,
        help="Age of the current session in minutes (default: 0)",
    )
    parser.add_argument(
        "--network-zone",
        default="unknown",
        help="Network location to record; it does not grant trust",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        request = AccessRequest(
            subject=args.subject,
            resource=args.resource,
            identity_verified=args.identity_verified,
            mfa_verified=args.mfa_verified,
            device_trusted=args.device_trusted,
            risk_score=args.risk_score,
            session_age_minutes=args.session_age_minutes,
            network_zone=args.network_zone,
        )
    except ValueError as error:
        parser.error(str(error))

    decision = evaluate_access(request)
    print(json.dumps(asdict(decision), indent=2))
    return 0 if decision.allowed else 1


if __name__ == "__main__":
    raise SystemExit(main())
