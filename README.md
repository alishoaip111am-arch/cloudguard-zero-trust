CloudGuard Zero Trust

""Tests" (https://github.com/alishoaip111am-arch/cloudguard-zero-trust/actions/workflows/tests.yml/badge.svg)" (https://github.com/alishoaip111am-arch/cloudguard-zero-trust/actions/workflows/tests.yml)

CloudGuard Zero Trust is an educational Python-based access decision engine that demonstrates core Zero Trust security principles.

The system evaluates every access request using role authorization, device posture, country policies, and Multi-Factor Authentication (MFA) status.

Each request receives one of three decisions:

- ALLOW — Access is granted.
- STEP_UP — Additional authentication through MFA is required.
- DENY — Access is rejected.

All decisions are recorded in an audit log that supports security monitoring and repeated-denial detection.

The project uses only Python's standard library and requires no third-party dependencies.

---

1. Key Features

- Role-Based Access Control (RBAC).
- Context-aware access evaluation.
- Device security posture assessment.
- Country-based access policies.
- MFA verification and step-up authentication.
- Risk-based decision-making.
- Input validation and fail-closed behavior.
- Audit logging with JSON export.
- Repeated-denial and probing detection.
- Automated testing through GitHub Actions.

2. Quick Start

Requirements

- Python 3.10 or later.
- No external Python packages required.

Run the demonstration

python main.py

Evaluate requests from a JSON file

python main.py requests.json

Export audit results as JSON

python main.py requests.json --json

Run the test suite

python -m unittest discover -s tests -v

---

3. System Architecture

The project consists of three primary components:

Component| Responsibility
"main.py"| Command-line interface, input loading, execution and output presentation.
"cloudguard.py"| Core decision engine, request parsing, risk evaluation and audit logging.
"requests.json"| Sample access requests used for demonstration and testing.

Request Processing Flow

       Access Request
              |
              v
       Input Parsing
              |
              v
      Input Validation
         /       \
      Valid     Invalid
        |          |
        v          v
   Risk Scoring   DENY
        |
        v
   Role Authorization
      /        \
   Allowed    Rejected
      |          |
      v          v
   MFA and      DENY
   Risk Check
      |
      v
  Final Decision
      |
  +---+---+
  |   |   |
ALLOW STEP_UP DENY
  |
  v
 Audit Logging
      |
      v
 Security Alerts

4. Risk Assessment Model

CloudGuard calculates a numerical risk score based on four security signals.

Security Signal| Risk Points
Device is not managed| 30
Device is not patched| 20
Country is outside the allowed list| 25
MFA is not verified| 20

The total risk score is calculated by adding the points associated with applicable signals.

Resource Sensitivity Thresholds

Resource Sensitivity| Maximum Risk for ALLOW
Low| 40
Medium| 25
High| 10

Higher-sensitivity resources have stricter risk thresholds.

Decision Logic

After input validation and role authorization, the engine evaluates MFA status and the calculated risk.

The general decision process is:

1. Reject invalid requests.
2. Reject requests when the user's role does not meet the resource requirements.
3. Calculate the risk score.
4. Evaluate MFA requirements.
5. Compare the resulting risk against the resource threshold.
6. Return the appropriate access decision.

For requests missing MFA, the engine determines whether completing MFA would reduce the risk sufficiently to permit access.

- If MFA can make the request acceptable, the result is "STEP_UP".
- If MFA cannot make the request acceptable, the result is "DENY".
- If all requirements are satisfied, the result is "ALLOW".

Medium- and high-sensitivity resources require MFA.

5. RBAC and Zero Trust

RBAC and Zero Trust serve different but complementary security purposes.

Aspect| RBAC| Zero Trust
Main purpose| Role-based authorization| Context-aware access evaluation
Evaluation| User role and resource permissions| Identity, device, location, MFA and risk
Trust model| Permissions based on assigned roles| No implicit trust
Evaluation frequency| Depends on the authorization system| Re-evaluated for every request

In CloudGuard, RBAC is a necessary authorization layer, but it is not sufficient on its own.

A user with the correct role can still be denied access because of an untrusted device, unusual country or excessive risk score.

This demonstrates the principle:

Never Trust, Always Verify.

6. Input Data Format

Each access request contains the following fields:

Field| Description
"user"| User identifier
"role"| User authorization role
"resource"| Requested resource
"sensitivity"| Resource sensitivity level
"device_managed"| Whether the device is managed
"device_patched"| Whether the device is patched
"country"| Two-letter country code
"mfa_verified"| Whether MFA has been verified

Supported Roles

Role| Level
"guest"| 1
"employee"| 2
"admin"| 3

Resource Sensitivity Levels

Sensitivity| Level
"low"| 1
"medium"| 2
"high"| 3

A user's role must meet or exceed the sensitivity level of the requested resource.

The allowed country policy is configured in "main.py".

---

7. Security Controls

CloudGuard demonstrates several defensive security mechanisms:

Fail-Closed Validation

Malformed requests, invalid field values and invalid policy configurations are rejected rather than implicitly trusted.

Output-Injection Protection

User and resource labels are bounded and control characters are escaped before being displayed in audit output.

Repeated-Denial Detection

The audit system monitors repeated access denials.

It supports:

- Consecutive denial detection for the same user and resource.
- Detection of probing behavior across multiple resources.
- Configurable alert thresholds and request windows through the Python API.

Alert configuration is performed through:

AuditLog.alerts(limit=..., window=...)

These settings are not command-line options.

Audit Logging

Each recorded decision includes information such as:

- UTC timestamp.
- User and requested resource.
- Final access decision.
- Risk score.
- Decision reasons.

Audit records can also be exported in JSON format.

---

8. Testing and Validation

The project includes automated unit tests covering the main security and functional components.

Run the complete test suite using:

python -m unittest discover -s tests -v

The tests cover:

Test Area| Description
Risk Assessment| Risk calculations and threshold handling
Access Decisions| ALLOW, STEP_UP and DENY behavior
Authorization| Role and resource sensitivity enforcement
MFA| Authentication requirements
Input Validation| Invalid values, missing fields and malformed requests
Audit Logging| Decision records and alert detection
JSON Processing| Input parsing and audit export
Command-Line Interface| Demonstration and file-based execution

Continuous Integration

GitHub Actions is configured to run automated tests across supported Python versions:

- Python 3.10
- Python 3.11
- Python 3.12
- Python 3.13

The workflow also validates the demonstration output.

"View GitHub Actions" (https://github.com/alishoaip111am-arch/cloudguard-zero-trust/actions)

---

9. Project Structure

cloudguard-zero-trust/
├── .github/
│   └── workflows/
│       └── tests.yml
├── tests/
│   ├── __init__.py
│   └── test_cloudguard.py
├── cloudguard.py
├── main.py
├── requests.json
├── .gitignore
├── LICENSE
└── README.md

---

10. Limitations and Future Development

CloudGuard is an educational security simulator and is not intended to replace a production Zero Trust security platform.

The current implementation does not integrate with:

- Real identity providers.
- Enterprise endpoint-management systems.
- External MFA services.
- Live geolocation databases.
- Cloud infrastructure or production network gateways.

Risk scores and security policies are illustrative.

Audit records are maintained in memory during program execution and are not persisted in a production database.

Potential Future Improvements

- Integration with real identity providers.
- Persistent audit storage.
- Advanced device posture verification.
- Configurable policy management.
- Web-based administration dashboard.
- Real-time security monitoring.
- Integration with external MFA providers.

---

11. License

This project is distributed under the MIT License.

See the "LICENSE" (LICENSE) file for details.
