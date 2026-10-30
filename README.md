CloudGuard ZT — Zero-Trust Access Decision Engine

CloudGuard ZT is a small educational Zero-Trust access decision engine written in Python.

It evaluates access requests using identity, role permissions, device security posture, location, and Multi-Factor Authentication (MFA).

The engine returns one of three decisions:

- "ALLOW" — Access is permitted.
- "STEP_UP" — Additional MFA verification is required.
- "DENY" — Access is rejected.

Key Features

- Role-based access control.
- Risk-based access evaluation.
- Device security checks.
- Country-based access policy.
- MFA verification and step-up decisions.
- Fail-closed validation for invalid requests.
- Audit logging with UTC timestamps.
- Detection of repeated access denials.
- JSON export of audit records.
- Automated unit tests using Python's standard library.

Risk Model

Risk signal| Risk points
Unmanaged device| +30
Unpatched device| +20
Country outside allowed list| +25
MFA not verified| +20

Maximum risk for ALLOW

Resource sensitivity| Maximum risk
Low| 40
Medium| 25
High| 10

Medium- and high-sensitivity resources require MFA. If MFA alone can bring the risk within the allowed threshold, the engine returns "STEP_UP"; otherwise, it returns "DENY".

Role Permissions

The educational role hierarchy is:

- Guest: Level 1
- Employee: Level 2
- Admin: Level 3

A role must meet or exceed the sensitivity level of the requested resource.

Project Structure

cloudguard-zero-trust-engine/
├── cloudguard.py
├── main.py
├── README.md
├── pyproject.toml
└── tests/
    ├── __init__.py
    └── test_cloudguard.py

Requirements

- Python 3.10 or later.
- No third-party dependencies.

Run the Project

Run the example scenarios:

python main.py

Print the results as JSON:

python main.py --json

Run Tests

Run the automated test suite:

python -m unittest discover -s tests -v

Security Design Principles

CloudGuard ZT demonstrates several security concepts:

1. Never trust an access request by default.
2. Validate request data before making an access decision.
3. Enforce permissions before evaluating risk.
4. Use multiple security signals instead of relying on a single factor.
5. Fail closed when request or policy validation fails.
6. Record access decisions for auditing.

Limitations

This project is an educational simulator, not production-ready security software.

It does not connect to real identity providers, endpoint management systems, MFA services, geolocation databases, or cloud infrastructure.

Its risk scores and policies are illustrative and should be reviewed and calibrated before any real-world use.

Author

Developed as a Python project to explore Zero-Trust security principles, access control, risk evaluation, and automated testing.