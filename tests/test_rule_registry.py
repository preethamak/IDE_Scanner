import unittest

from ide_scanner.rule_registry import rule_registry, rules_json


class RuleRegistryTests(unittest.TestCase):
    def test_all_rules_publish_engine_and_decision_semantics(self) -> None:
        rules = rule_registry()

        self.assertEqual(len(rules), 40)
        self.assertTrue(all(rule.engine for rule in rules))
        self.assertTrue(all(rule.decision_effect for rule in rules))
        self.assertTrue(all(rule.confidence_basis for rule in rules))

    def test_provider_and_policy_metadata_match_evidence_source(self) -> None:
        rules = {rule.rule_id: rule for rule in rule_registry()}

        self.assertEqual(rules["untrusted-workspace-input-to-process"].engine, "semgrep")
        self.assertEqual(rules["unicode-evasion"].engine, "yara")
        self.assertEqual(rules["ast-dynamic-call-target"].engine, "javascript-ast")
        self.assertEqual(rules["encoded-dynamic-execution"].decision_effect, "review-context")
        self.assertEqual(rules["known-bad-artifact"].decision_effect, "block-by-default")
        self.assertEqual(rules["network-access"].decision_effect, "review-context")

    def test_rules_json_is_self_describing(self) -> None:
        payload = rules_json()
        first = payload["rules"][0]

        self.assertIn("engine", first)
        self.assertIn("decision_effect", first)
        self.assertIn("confidence_basis", first)
