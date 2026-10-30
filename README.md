CloudGuard Zero Trust

An Educational Zero-Trust Access Decision Engine built with Python.

Overview

CloudGuard Zero Trust is an educational Python project demonstrating how a Zero-Trust security model evaluates access requests using identity, role permissions, device security, location, and Multi-Factor Authentication (MFA).

The engine returns one of three decisions:

- ALLOW: Access is permitted.
- STEP_UP: Additional MFA verification is required.
- DENY: Access is rejected.

Key Features

- Role-based access control (RBAC).
- Risk-based access evaluation.
- Device security and patch-status checks.
- Country-based access policies.
- MFA step-up decisions.
- Fail-closed request validation.
- UTC audit logging.
- Repeated-denial detection.
- JSON audit log export.
- Automated unit tests.

Risk Model

The engine calculates risk using the following signals:

Risk Signal| Points
Unmanaged device| +30
Unpatched device| +20
Country outside allowed list| +25
MFA not verified| +20

Maximum Risk for ALLOW

Resource Sensitivity| Maximum Risk
Low| 40
Medium| 25
High| 10

Medium- and high-sensitivity resources require MFA.

Requirements

- Python 3.10 or later.
- No third-party dependencies.

Run the Project

Run the demonstration:

python main.py --demo

Process sample requests:

python main.py --file requests.json

Export audit records as JSON:

python main.py --file requests.json --json

Run Tests

python -m unittest discover -s tests -v

Project Structure

cloudguard-zero-trust/
├── .github/
│   └── workflows/
│       └── tests.yml
├── tests/
│   ├── __init__.py
│   ├── test_cloudguard.py
│   └── test_main.py
├── cloudguard.py
├── main.py
├── requests.json
├── pyproject.toml
├── .gitignore
└── README.md

Security Design

CloudGuard demonstrates the principle of Never Trust, Always Verify.

Every request is validated before access is evaluated. Role permissions are enforced before risk assessment, and invalid requests are rejected using a fail-closed approach.

Limitations

This is an educational simulator, not production-ready security software.

It does not connect to real identity providers, endpoint management systems, MFA services, geolocation databases, or cloud infrastructure.

Its risk scores and policies are illustrative.

