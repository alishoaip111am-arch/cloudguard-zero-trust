# CloudGuard ZT

CloudGuard ZT is an educational Zero-Trust Access Decision Engine. It evaluates
each access request using explicit identity, MFA, device, risk, and session-age
checks, then explains the result.

## Requirements

- Python 3.10 or newer
- Python standard library only

## Run the demo

The default request is denied because identity, MFA, and device trust have not
been verified:

```sh
python main.py
```

Pass evidence for a request that meets the default policy:

```sh
python main.py \
  --subject alice \
  --resource payroll \
  --identity-verified \
  --mfa-verified \
  --device-trusted \
  --risk-score 12 \
  --session-age-minutes 10 \
  --network-zone office
```

The command prints a JSON decision and its checks. It exits with status `0` for
an allowed request and `1` for a denied request. Invalid input is reported as a
command-line error.

## Use the decision engine

```python
from cloudguard import AccessPolicy, AccessRequest, evaluate_access

request = AccessRequest(
    subject="alice",
    resource="payroll",
    identity_verified=True,
    mfa_verified=True,
    device_trusted=True,
    risk_score=12,
    session_age_minutes=10,
    network_zone="office",
)

decision = evaluate_access(request, AccessPolicy(max_risk_score=30))
print(decision.allowed)
print(decision.reasons)
```

The default policy allows a risk score up to `40` and a session age up to
`60` minutes. Access is granted only when every required check passes. A
network zone is recorded for context but never grants access by itself.

This small example is for learning, not production authorization. A real
system needs carefully designed policies, reliable identity and device signals,
auditing, and a threat model for its environment.

## Run tests

```sh
python -m unittest discover -s tests -v
```
