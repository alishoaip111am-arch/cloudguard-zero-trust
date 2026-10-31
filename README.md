# CloudGuard Zero Trust

[![Tests](https://github.com/alishoaip111am-arch/cloudguard-zero-trust/actions/workflows/tests.yml/badge.svg)](https://github.com/alishoaip111am-arch/cloudguard-zero-trust/actions/workflows/tests.yml)

CloudGuard Zero Trust is an educational Python-based access decision engine that demonstrates core Zero Trust security principles.

The system evaluates every access request using role authorization, device posture, country policies, and Multi-Factor Authentication (MFA) status.

Each request receives one of three decisions:

- **ALLOW**: access is granted.
- **STEP_UP**: additional authentication through MFA is required.
- **DENY**: access is rejected.

All decisions are recorded in an audit log that supports security monitoring and repeated-denial detection.

The project uses only Python's standard library and requires no third-party dependencies.

---

## 1. Key Features

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

## 2. Quick Start

**Requirements**

- Python 3.10 or later.
- No external Python packages required.

**Run the demonstration**

```bash
python main.py
```

**Evaluate requests from a JSON file**

```bash
python main.py requests.json
```

**Export audit results as JSON**

```bash
python main.py requests.json --json
```

**Run the test suite**

```bash
python -m unittest discover -s tests -v
```

---

## 3. System Architecture

The project consists of three primary components:

| Component | Responsibility |
| --- | --- |
| `main.py` | Command-line interface, input loading, execution and output presentation. |
| `cloudguard.py` | Core decision engine, request parsing, risk evaluation and audit logging. |
| `requests.json` | Sample access requests used for demonstration and testing. |

### Request Processing Flow

```text
          Access Request
                |
                v
          Input Parsing ---- missing or unknown fields ----> DENY
                |
                v
        Input Validation ---- invalid ---------------------> DENY
                |
                v
           Risk Scoring
                |
                v
       Role Authorization ---- role too low ---------------> DENY
                |
                v
       MFA and Risk Check
                |
        +-------+-------+
        |       |       |
      ALLOW   STEP_UP   DENY
        |       |       |
        +-------+-------+
                |
                v
         Audit Logging ----> Security Alerts
```

Every decision, including each `DENY` shown above, is recorded in the audit log.

## 4. Risk Assessment Model

CloudGuard calculates a numerical risk score based on four security signals.

| Security Signal | Risk Points |
| --- | ---: |
| Device is not managed | 30 |
| Device is not patched | 20 |
| Country is outside the allowed list | 25 |
| MFA is not verified | 20 |

The total risk score is calculated by adding the points associated with applicable signals.

### Resource Sensitivity Thresholds

| Resource Sensitivity | Maximum Risk for ALLOW |
| --- | ---: |
| Low | 40 |
| Medium | 25 |
| High | 10 |

Higher-sensitivity resources have stricter risk thresholds.

### Decision Logic

The engine processes each request in this order:

1. Reject invalid requests.
2. Calculate the risk score.
3. Reject requests when the user's role does not meet the resource requirements. The calculated risk is still recorded.
4. If MFA is missing, check whether completing MFA would bring the risk within the resource threshold. If so, the result is `STEP_UP`; otherwise it is `DENY`.
5. Otherwise, compare the risk with the resource threshold: `ALLOW` when it is within the threshold, `DENY` when it is above.

**STEP_UP is an intermediate authentication decision, not an access grant. Access is not permitted until the required MFA verification is completed.**

Medium- and high-sensitivity resources always require MFA. Low-sensitivity resources ask for MFA only when it would turn a denial into an approval.

## 5. RBAC and Zero Trust

RBAC and Zero Trust serve different but complementary security purposes.

| Aspect | RBAC | Zero Trust |
| --- | --- | --- |
| Main purpose | Role-based authorization | Context-aware access evaluation |
| Evaluation | User role and resource permissions | Identity, device, location, MFA and risk |
| Trust model | Permissions based on assigned roles | No implicit trust |
| Evaluation frequency | Depends on the authorization system | Re-evaluated for every request |

In CloudGuard, RBAC is a necessary authorization layer, but it is not sufficient on its own.

A user with the correct role can still be denied access because of an untrusted device, unusual country or excessive risk score.

This demonstrates the principle: **Never Trust, Always Verify.**

## 6. Input Data Format

Each access request contains the following fields:

| Field | Description |
| --- | --- |
| `user` | User identifier |
| `role` | User authorization role |
| `resource` | Requested resource |
| `sensitivity` | Resource sensitivity level |
| `device_managed` | Whether the device is managed |
| `device_patched` | Whether the device is patched |
| `country` | Two-letter country code |
| `mfa_verified` | Whether MFA has been verified |

**Supported roles**

| Role | Level |
| --- | ---: |
| `guest` | 1 |
| `employee` | 2 |
| `admin` | 3 |

**Resource sensitivity levels**

| Sensitivity | Level |
| --- | ---: |
| `low` | 1 |
| `medium` | 2 |
| `high` | 3 |

A user's role must meet or exceed the sensitivity level of the requested resource.

The allowed country policy is configured in `main.py`.

---

## 7. Security Controls

CloudGuard demonstrates several defensive security mechanisms.

### Fail-Closed Validation

Malformed requests, invalid field values and invalid policy configurations are rejected rather than implicitly trusted.

### Output-Injection Protection

User and resource names must be 1 to 64 printable characters. Control characters are escaped before being displayed in audit output.

### Repeated-Denial Detection

The audit system monitors repeated access denials. It supports:

- Consecutive denial detection for the same user and resource.
- Detection of probing behavior across multiple resources.
- Configurable alert thresholds and request windows through the Python API.

Alert configuration is performed through `AuditLog.alerts(limit=..., window=...)`. These settings are not command-line options.

### Audit Logging

Each recorded decision includes:

- UTC timestamp.
- User and requested resource.
- Final access decision.
- Risk score.
- Decision reasons.

Audit records can also be exported in JSON format.

---

## 8. Testing and Validation

The project includes automated unit tests covering the main security and functional components.

```bash
python -m unittest discover -s tests -v
```

| Test Area | Description |
| --- | --- |
| Risk Assessment | Risk calculations and threshold handling |
| Access Decisions | ALLOW, STEP_UP and DENY behavior |
| Authorization | Role and resource sensitivity enforcement |
| MFA | Authentication requirements |
| Input Validation | Invalid values, missing fields and malformed requests |
| Audit Logging | Decision records and alert detection |
| JSON Processing | Input parsing and audit export |
| Command-Line Interface | Demonstration and file-based execution |

### Continuous Integration

The GitHub Actions workflow is configured to run the tests on Python 3.10, 3.11, 3.12 and 3.13, and to validate the demonstration output. The badge above shows the status of the latest run.

[View GitHub Actions](https://github.com/alishoaip111am-arch/cloudguard-zero-trust/actions)

---

## 9. Project Structure

```text
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
```

---

## 10. Limitations and Future Development

CloudGuard is an educational security simulator and is not intended to replace a production Zero Trust security platform.

The current implementation does not integrate with:

- Real identity providers.
- Enterprise endpoint-management systems.
- External MFA services.
- Live geolocation databases.
- Cloud infrastructure or production network gateways.

Risk scores and security policies are illustrative.

Audit records are kept in memory during program execution and are not persisted.

### Potential Future Improvements

- Integration with real identity providers.
- Persistent audit storage.
- Advanced device posture verification.
- Configurable policy management.
- Integration with external MFA providers.

## 11. License

This project is distributed under the MIT License. See the [LICENSE](LICENSE) file for details.
