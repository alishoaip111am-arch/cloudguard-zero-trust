CloudGuard Zero Trust

An Educational Zero-Trust Access Decision Engine built with Python.

Overview

CloudGuard Zero Trust is a Python-based educational project that demonstrates how a Zero-Trust security model can evaluate access requests using identity, device security, location, authentication, and resource sensitivity.

The system evaluates every request independently and returns one of three decisions:

- ALLOW: Access is permitted.
- STEP_UP: Additional authentication (MFA) is required.
- DENY: Access is rejected.

Key Features

- Role-based access control.
- Risk-based access evaluation.
- Device security and patch-status checks.
- Country-based access policies.
- Multi-factor authentication (MFA) step-up decisions.
- Fail-closed validation for invalid requests.
- UTC audit logging.
- Detection of repeated access denials.
- JSON audit log export.
- Automated unit tests using Python's standard library.

Risk Evaluation

The system assigns risk points based on request conditions:

Condition| Risk Points
Unmanaged device| +30
Unpatched device| +20
Unusual country| +25
MFA not enabled| +20

Access decisions also consider the user's role and the requested resource's sensitivity.

Requirements

- Python 3.10 or later.
- No third-party Python packages required.

How to Run

Run the default demonstration:

python main.py

Run the sample requests:

python main.py --file requests.json

Run with JSON output:

python main.py --file requests.json --json

Run the unit tests:

python -m unittest discover -s tests -v

Project Structure

- "cloudguard.py" — Core access-control and risk-evaluation logic.
- "main.py" — Command-line interface.
- "requests.json" — Sample access requests.
- "tests/" — Automated unit tests.
- ".github/workflows/" — GitHub Actions workflow.

Security Approach

CloudGuard follows the principle of "Never Trust, Always Verify."

Each access request is evaluated using the available security context. Invalid or incomplete requests are handled with a fail-closed approach.

Limitations

This project is an educational simulation intended to demonstrate Zero-Trust access decision concepts. It is not a production-ready security platform and does not replace a complete identity provider, endpoint protection system, or enterprise security infrastructure.

Author

Ali Shoaib
