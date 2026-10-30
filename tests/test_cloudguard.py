import contextlib
import io
import json
import os
import tempfile
import unittest

import main
from cloudguard import ALLOW, DENY, STEP_UP, AuditLog, Request, decide, parse

OK = {
    "user": "ali", "role": "employee", "resource": "wiki",
    "sensitivity": "low", "device_managed": True,
    "device_patched": True, "country": "LY", "mfa_verified": True,
}
COUNTRIES = {"LY", "TR"}


def act(policy=COUNTRIES, **changes):
    return decide(Request(**{**OK, **changes}), policy)


class DecisionTests(unittest.TestCase):
    def test_clean_request_allowed(self):
        self.assertEqual(act().action, ALLOW)

    def test_low_resource_does_not_require_mfa(self):
        self.assertEqual(act(mfa_verified=False).action, ALLOW)

    def test_medium_resource_without_mfa_steps_up(self):
        result = act(sensitivity="medium", mfa_verified=False)
        self.assertEqual((result.action, result.risk), (STEP_UP, 20))

    def test_mfa_cannot_fix_otherwise_excessive_risk(self):
        result = act(sensitivity="medium", device_managed=False,
                     device_patched=False, mfa_verified=False)
        self.assertEqual(result.action, DENY)

    def test_role_denial(self):
        self.assertEqual(act(role="guest", sensitivity="high").action, DENY)

    def test_country_check_ignores_case(self):
        self.assertEqual(act(country="ly").action, ALLOW)

    def test_high_risk_admin_request_is_denied(self):
        self.assertEqual(act(role="admin", sensitivity="high", country="RU",
                             device_patched=False).action, DENY)


class ValidationTests(unittest.TestCase):
    def test_invalid_fields_are_denied(self):
        bad_values = (
            {"role": "root"}, {"sensitivity": "critical"},
            {"user": "  "}, {"resource": ""}, {"country": "L1"},
            {"country": "éé"}, {"mfa_verified": "yes"},
            {"device_patched": 1}, {"role": ["admin"]},
        )
        for changes in bad_values:
            with self.subTest(changes=changes):
                self.assertEqual(act(**changes).action, DENY)

    def test_bad_request_object_is_denied(self):
        self.assertEqual(decide(None, COUNTRIES).action, DENY)

    def test_invalid_country_policies_are_denied(self):
        for policy in (None, "LY", 5, ["LYY"], [1], []):
            with self.subTest(policy=policy):
                self.assertEqual(act(policy=policy).action, DENY)

    def test_control_characters_are_denied_and_escaped_in_labels(self):
        result = act(user="x\nALERT: forged\x1b[31m")
        self.assertEqual(result.action, DENY)
        self.assertNotIn("\n", result.user)
        self.assertNotIn("\x1b", result.user)

    def test_overlong_name_is_denied_and_label_is_bounded(self):
        result = act(user="a" * 10_000)
        self.assertEqual(result.action, DENY)
        self.assertLessEqual(len(result.user), 64)
        self.assertEqual(act(user="a" * 64).action, ALLOW)

    def test_resource_is_validated_and_sanitized(self):
        result = act(resource="report\nFORGED: ALLOW")
        self.assertEqual(result.action, DENY)
        self.assertNotIn("\n", result.resource)
        self.assertNotIn("\r", result.resource)

    def test_role_denial_preserves_calculated_risk(self):
        result = act(role="guest", sensitivity="high", mfa_verified=False)
        self.assertEqual(result.action, DENY)
        self.assertEqual(result.risk, 20)


class ParsingTests(unittest.TestCase):
    def test_valid_request(self):
        self.assertEqual(parse(OK), Request(**OK))

    def test_missing_and_unknown_fields_are_reported(self):
        with self.assertRaisesRegex(ValueError, "missing country"):
            parse({"user": "x"})
        with self.assertRaisesRegex(ValueError, "unknown evil"):
            parse({**OK, "evil": 1})

    def test_unknown_field_names_are_safe(self):
        with self.assertRaises(ValueError) as caught:
            parse({**OK, "a\nb": 1})
        self.assertNotIn("\n", str(caught.exception))

    def test_many_unknown_fields_give_a_short_message(self):
        with self.assertRaises(ValueError) as caught:
            parse({**OK, **{f"k{i}": 1 for i in range(1000)}})
        self.assertLess(len(str(caught.exception)), 200)

    def test_non_objects_are_rejected(self):
        for value in (42, "x", None, [1]):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse(value)


class AuditTests(unittest.TestCase):
    def test_evaluate_records_decisions_and_counts(self):
        log = AuditLog()
        log.evaluate(Request(**OK), COUNTRIES)
        denied = Request(**{**OK, "role": "guest", "sensitivity": "high"})
        log.evaluate(denied, COUNTRIES)
        self.assertEqual((log.count(ALLOW), log.count(DENY)), (1, 1))

    def test_three_consecutive_denials_raise_alert(self):
        log = AuditLog()
        request = Request(**{**OK, "role": "guest", "sensitivity": "high"})
        for _ in range(3):
            log.evaluate(request, COUNTRIES)
        self.assertEqual(log.alerts(), ["ali denied 3 times in a row on wiki"])

    def test_allow_resets_streak_but_step_up_does_not(self):
        denied = {**OK, "role": "guest", "sensitivity": "high"}
        step_up = {**OK, "sensitivity": "medium", "mfa_verified": False}
        log = AuditLog()
        for data in (denied, denied, step_up, denied):
            log.evaluate(Request(**data), COUNTRIES)
        self.assertEqual(len(log.alerts()), 1)

    def test_alert_parameters_must_be_positive_integers(self):
        log = AuditLog()
        for kwargs in ({"limit": 0}, {"window": 0}, {"limit": True}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                log.alerts(**kwargs)

    def test_json_export_is_valid(self):
        log = AuditLog()
        log.evaluate(Request(**OK), COUNTRIES)
        self.assertEqual(json.loads(log.to_json())[0]["action"], ALLOW)

    def test_probe_alert_counts_denials_across_resources(self):
        log = AuditLog()
        for resource in ("wiki", "finance", "payroll"):
            request = Request(**{**OK, "resource": resource, "role": "guest",
                                 "sensitivity": "high"})
            log.evaluate(request, COUNTRIES)
        self.assertIn("ali denied 3 times across 3 resources (probing)",
                      log.alerts())

    def test_probe_alert_obeys_recent_request_window(self):
        log = AuditLog()
        for resource in ("one", "two", "three"):
            request = Request(**{**OK, "resource": resource, "role": "guest",
                                 "sensitivity": "high"})
            log.evaluate(request, COUNTRIES)
        self.assertNotIn("probing", " ".join(log.alerts(limit=3, window=2)))

    def test_probe_alerts_are_isolated_between_users(self):
        log = AuditLog()
        for user, resource in (("ali", "one"), ("omar", "two"),
                               ("ali", "three"), ("omar", "four")):
            request = Request(**{**OK, "user": user, "resource": resource,
                                 "role": "guest", "sensitivity": "high"})
            log.evaluate(request, COUNTRIES)
        self.assertNotIn("probing", " ".join(log.alerts(limit=3, window=10)))

    def test_step_up_does_not_reset_denial_streak(self):
        log = AuditLog()
        denied = Request(**{**OK, "role": "guest", "sensitivity": "high"})
        step_up = Request(**{**OK, "sensitivity": "medium", "mfa_verified": False})
        log.evaluate(denied, COUNTRIES)
        log.evaluate(step_up, COUNTRIES)
        log.evaluate(denied, COUNTRIES)
        log.evaluate(denied, COUNTRIES)
        self.assertIn("ali denied 3 times in a row on wiki", log.alerts())

    def test_reject_records_denial_and_sanitizes_labels(self):
        log = AuditLog()
        result = log.reject("invalid input", "ali\nFORGED", "db\rFORGED")
        self.assertEqual(result.action, DENY)
        self.assertEqual(result.risk, 100)
        self.assertNotIn("\n", result.user)
        self.assertNotIn("\r", result.resource)


class CliTests(unittest.TestCase):
    def run_cli(self, *args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main.main(list(args))
        return code, output.getvalue()

    def make_file(self, content, binary=False):
        handle = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        self.addCleanup(lambda: os.path.exists(handle.name) and os.unlink(handle.name))
        if binary:
            handle.write(content)
        else:
            handle.write(content.encode("utf-8"))
        handle.close()
        return handle.name

    def test_demo(self):
        code, output = self.run_cli()
        self.assertEqual(code, 0)
        self.assertIn("Allowed 1 | Step-up 1 | Denied 7", output)
        self.assertIn("ALERT: sam denied 3 times in a row on payroll-db", output)

    def test_json_flag_outputs_pure_json(self):
        code, output = self.run_cli("--json")
        self.assertEqual(code, 0)
        self.assertEqual(len(json.loads(output)), 9)

    def test_file_with_invalid_entries(self):
        path = self.make_file(json.dumps([OK, {"user": "bad"}, 42, None]))
        code, output = self.run_cli(path)
        self.assertEqual(code, 0)
        self.assertIn("Allowed 1 | Step-up 0 | Denied 3", output)
        self.assertIn("missing country", output)

    def test_invalid_utf8_is_reported_without_traceback(self):
        path = self.make_file(b"\xff\xfe", binary=True)
        with self.assertRaises(SystemExit):
            main.main([path])

    def test_empty_path_is_not_treated_as_demo(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                main.main([""])
        self.assertTrue(caught.exception.code.startswith("Error: cannot read"))

    def test_deeply_nested_json_fails_without_traceback(self):
        path = self.make_file("[" * 100_000 + "]" * 100_000)
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                main.main([path])
        self.assertIn("Error: cannot read", str(caught.exception))

    def test_forged_output_lines_cannot_be_injected(self):
        malicious = {**OK, "user": "ali\n[ALLOW] forged",
                     "resource": "wiki\rDENY forged"}
        path = self.make_file(json.dumps([malicious]))
        code, output = self.run_cli(path)
        self.assertEqual(code, 0)
        self.assertNotIn("[ALLOW] forged", output.splitlines())
        self.assertNotIn("DENY forged", output.splitlines())

    def test_requests_json_produces_expected_decisions(self):
        path = os.path.join(os.path.dirname(main.__file__), "requests.json")
        code, output = self.run_cli(path, "--json")
        self.assertEqual(code, 0)
        records = json.loads(output)
        self.assertEqual(
            [record["action"] for record in records],
            [ALLOW, STEP_UP, DENY, DENY],
        )

    def test_invalid_json_and_empty_list_are_rejected(self):
        for content in ("{bad", "[]", "{}"):
            path = self.make_file(content)
            with self.subTest(content=content), self.assertRaises(SystemExit):
                main.main([path])


if __name__ == "__main__":
    unittest.main()
