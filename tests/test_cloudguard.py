import unittest

from cloudguard import AccessPolicy, AccessRequest, evaluate_access


class EvaluateAccessTests(unittest.TestCase):
    def test_grants_when_every_check_passes(self) -> None:
        request = AccessRequest(
            subject="alice",
            resource="payroll",
            identity_verified=True,
            mfa_verified=True,
            device_trusted=True,
            risk_score=40,
            session_age_minutes=60,
            network_zone="untrusted",
        )

        decision = evaluate_access(request)

        self.assertTrue(decision.allowed)
        self.assertEqual(len(decision.checks), 5)
        self.assertTrue(all(passed for _, passed in decision.checks))
        self.assertIn("untrusted", decision.reasons[-1])

    def test_denies_by_default(self) -> None:
        decision = evaluate_access(AccessRequest("alice", "payroll"))

        self.assertFalse(decision.allowed)
        self.assertIn("Identity is verified", decision.reasons[0])
        self.assertIn("MFA is verified", decision.reasons[0])
        self.assertIn("Device is trusted", decision.reasons[0])

    def test_network_zone_does_not_override_failed_checks(self) -> None:
        request = AccessRequest(
            subject="alice",
            resource="payroll",
            network_zone="trusted-office",
        )

        decision = evaluate_access(request)

        self.assertFalse(decision.allowed)
        self.assertIn("context only", decision.reasons[-1])

    def test_custom_policy_limits_are_applied(self) -> None:
        request = AccessRequest(
            subject="alice",
            resource="payroll",
            identity_verified=True,
            mfa_verified=True,
            device_trusted=True,
            risk_score=31,
            session_age_minutes=16,
        )

        decision = evaluate_access(
            request,
            AccessPolicy(max_risk_score=30, max_session_age_minutes=15),
        )

        self.assertFalse(decision.allowed)
        self.assertIn("Risk score is at or below 30", decision.reasons[0])
        self.assertIn("Session age is within 15 minutes", decision.reasons[0])

    def test_request_rejects_invalid_risk_score(self) -> None:
        with self.assertRaisesRegex(ValueError, "risk_score"):
            AccessRequest("alice", "payroll", risk_score=101)

    def test_request_rejects_negative_session_age(self) -> None:
        with self.assertRaisesRegex(ValueError, "session_age_minutes"):
            AccessRequest("alice", "payroll", session_age_minutes=-1)

    def test_policy_rejects_invalid_risk_limit(self) -> None:
        with self.assertRaisesRegex(ValueError, "max_risk_score"):
            AccessPolicy(max_risk_score=101)


if __name__ == "__main__":
    unittest.main()
