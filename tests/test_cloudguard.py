
"""Unit tests for the CloudGuard Zero-Trust engine."""

import json
import unittest

from cloudguard import (
    ALLOW,
    DENY,
    STEP_UP,
    AuditLog,
    Request,
    decide,
    evaluate,
)

ALLOWED = {"LY", "TR"}


def make(**changes):
    """Create a valid request that tests can customize."""
    data = {
        "user": "ali",
        "role": "employee",
        "resource": "wiki",
        "sensitivity": "low",
        "device_managed": True,
        "device_patched": True,
        "country": "LY",
        "mfa_verified": True,
    }
    data.update(changes)
    return Request(**data)


class DecisionTests(unittest.TestCase):

    def test_clean_request_is_allowed(self):
        self.assertEqual(decide(make(), ALLOWED).action, ALLOW)

    def test_low_resource_can_be_allowed_without_mfa(self):
        self.assertEqual(
            decide(make(mfa_verified=False), ALLOWED).action,
            ALLOW,
        )

    def test_guest_cannot_access_high_resource(self):
        self.assertEqual(
            decide(
                make(role="guest", sensitivity="high"),
                ALLOWED,
            ).action,
            DENY,
        )

    def test_employee_can_access_medium_resource(self):
        self.assertEqual(
            decide(make(sensitivity="medium"), ALLOWED).action,
            ALLOW,
        )

    def test_missing_mfa_requests_step_up(self):
        decision = decide(
            make(sensitivity="medium", mfa_verified=False),
            ALLOWED,
        )
        self.assertEqual(decision.action, STEP_UP)

    def test_high_risk_request_is_denied(self):
        decision = decide(
            make(
                role="admin",
                sensitivity="high",
                country="RU",
                device_patched=False,
            ),
            ALLOWED,
        )
        self.assertEqual(decision.action, DENY)

    def test_step_up_not_offered_if_mfa_is_insufficient(self):
        decision = decide(
            make(
                sensitivity="medium",
                device_managed=False,
                device_patched=False,
                mfa_verified=False,
            ),
            ALLOWED,
        )
        self.assertEqual(decision.action, DENY)

    def test_country_check_ignores_case(self):
        self.assertEqual(
            decide(make(country="ly"), ALLOWED).action,
            ALLOW,
        )


class ValidationTests(unittest.TestCase):

    def test_unknown_role_is_denied(self):
        self.assertEqual(
            decide(make(role="root"), ALLOWED).action,
            DENY,
        )

    def test_blank_user_is_denied(self):
        self.assertEqual(
            decide(make(user="  "), ALLOWED).action,
            DENY,
        )

    def test_blank_resource_is_denied(self):
        self.assertEqual(
            decide(make(resource=" "), ALLOWED).action,
            DENY,
        )

    def test_non_boolean_flag_is_denied(self):
        self.assertEqual(
            decide(make(mfa_verified="yes"), ALLOWED).action,
            DENY,
        )

    def test_invalid_country_is_denied(self):
        self.assertEqual(
            decide(make(country="L1"), ALLOWED).action,
            DENY,
        )

    def test_non_ascii_country_is_denied(self):
        self.assertEqual(
            decide(make(country="éé"), ALLOWED).action,
            DENY,
        )

    def test_invalid_request_object_is_denied(self):
        self.assertEqual(decide(None, ALLOWED).action, DENY)

    def test_missing_country_policy_is_denied(self):
        self.assertEqual(decide(make(), None).action, DENY)

    def test_country_policy_string_is_denied(self):
        self.assertEqual(decide(make(), "LY").action, DENY)

    def test_unknown_sensitivity_is_denied(self):
        self.assertEqual(
            decide(make(sensitivity="critical"), ALLOWED).action,
            DENY,
        )


class AuditTests(unittest.TestCase):

    def test_every_decision_is_logged(self):
        log = AuditLog()
        evaluate(make(), ALLOWED, log)
        evaluate(make(role="root"), ALLOWED, log)

        self.assertEqual(log.count(ALLOW), 1)
        self.assertEqual(log.count(DENY), 1)

    def test_log_contains_user_and_resource(self):
        log = AuditLog()
        evaluate(make(user="sam", resource="database"), ALLOWED, log)

        entry = log.entries[0]
        self.assertEqual(entry.user, "sam")
        self.assertEqual(entry.resource, "database")

    def test_json_export_is_valid(self):
        log = AuditLog()
        evaluate(make(), ALLOWED, log)

        data = json.loads(log.to_json())
        self.assertEqual(data[0]["action"], ALLOW)

    def test_decide_does_not_modify_audit_log(self):
        log = AuditLog()
        decision = decide(make(), ALLOWED)

        self.assertEqual(decision.action, ALLOW)
        self.assertEqual(len(log.entries), 0)


class RepeatedDenialTests(unittest.TestCase):

    def denied_request(self, **changes):
        return make(
            role="guest",
            sensitivity="high",
            **changes,
        )

    def test_three_denials_raise_alert(self):
        log = AuditLog()

        for _ in range(3):
            evaluate(self.denied_request(), ALLOWED, log)

        self.assertEqual(
            log.repeated_denials(),
            [("ali", "wiki", 3)],
        )

    def test_two_denials_do_not_raise_alert(self):
        log = AuditLog()

        for _ in range(2):
            evaluate(self.denied_request(), ALLOWED, log)

        self.assertEqual(log.repeated_denials(), [])

    def test_success_resets_denial_streak(self):
        log = AuditLog()

        for _ in range(2):
            evaluate(self.denied_request(), ALLOWED, log)

        evaluate(make(), ALLOWED, log)
        evaluate(self.denied_request(), ALLOWED, log)

        self.assertEqual(log.repeated_denials(), [])

    def test_denial_streaks_are_per_user_and_resource(self):
        log = AuditLog()

        for user in ("a", "b", "a", "b", "a"):
            evaluate(
                self.denied_request(user=user),
                ALLOWED,
                log,
            )

        self.assertEqual(
            log.repeated_denials(),
            [("a", "wiki", 3)],
        )


if __name__ == "__main__":
    unittest.main()

