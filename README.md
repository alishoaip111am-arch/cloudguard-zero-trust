# CloudGuard Zero Trust

An educational Python engine that evaluates access requests using role
authorization, device posture, country policy, MFA status, and risk scoring.
It returns **ALLOW**, **STEP_UP**, or **DENY** and records each decision.

## Decision model

| Signal | Risk points |
| --- | ---: |
| Device is not managed | 30 |
| Device is not patched | 20 |
| Country is outside the allowed list | 25 |
| MFA is not verified | 20 |

| Resource sensitivity | Maximum risk for ALLOW |
| --- | ---: |
| Low | 40 |
| Medium | 25 |
| High | 10 |

Role authorization is checked independently of the risk threshold. Medium- and
high-sensitivity resources require MFA; when appropriate, the engine returns
`STEP_UP` rather than granting access.

## Security controls demonstrated

- **Fail-closed validation:** malformed requests and invalid policy values are
  denied.
- **Output-injection protection:** user and resource labels are bounded and
  control characters are escaped before they appear in text audit output.
- **Repeated-denial detection:** the audit log detects consecutive denials for
  a resource and probing across resources within the most recent request window.
  The window and denial threshold can be configured through the
  `AuditLog.alerts(limit=..., window=...)` Python API; they are not CLI options.
- **Auditability:** decisions include UTC timestamps, risk scores, reasons, and
  can be exported as JSON.

## Example output

Running `python main.py` produces output similar to:

```text
[ALLOW  ] ali        -> wiki         risk   0  all checks passed
[STEP_UP] ali        -> finance-app  risk  20  MFA not verified (+20); step-up MFA required
[DENY   ] omar       -> finance-app  risk  50  device not managed (+30); MFA not verified (+20); too risky even after MFA

Allowed 1 | Step-up 1 | Denied 7
ALERT: sam denied 3 times in a row on payroll-db
```

## Requirements

- Python 3.10 or later.
- No third-party dependencies.

## Run

Run the built-in demonstration:

```bash
python main.py
```

Evaluate requests from the included JSON file:

```bash
python main.py requests.json
```

Export only machine-readable audit JSON:

```bash
python main.py requests.json --json
```

Run the test suite:

```bash
python -m unittest discover -s tests -v
```

## Project structure

```text
cloudguard-zero-trust/
├── .github/workflows/tests.yml
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

## Limitations

This is an educational simulator, not production-ready security software. It
does not integrate with real identity providers, endpoint-management platforms,
MFA services, geolocation databases, or cloud infrastructure. Policies and risk
scores are illustrative, and audit records remain in memory for the lifetime
of the process.
