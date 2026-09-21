import ast
import unittest
from pathlib import Path

from ide_scanner.rule_registry import rule_registry, rules_json


class RuleRegistryTests(unittest.TestCase):
    def test_all_rules_publish_engine_and_decision_semantics(self) -> None:
        rules = rule_registry()

        self.assertEqual(len(rules), 97)
        self.assertTrue(all(rule.engine for rule in rules))

    def test_runtime_rules_are_published_as_dynamic_sandbox_rules(self) -> None:
        rules = {rule.rule_id: rule for rule in rule_registry()}
        self.assertEqual(rules["runtime-network-attempt"].engine, "dynamic-sandbox")
        self.assertEqual(rules["observed-secret-exfil"].engine, "dynamic-sandbox")
        self.assertTrue(all(rule.decision_effect for rule in rules))
        self.assertTrue(all(rule.confidence_basis for rule in rules))

    def test_provider_and_policy_metadata_match_evidence_source(self) -> None:
        rules = {rule.rule_id: rule for rule in rule_registry()}

        self.assertEqual(rules["untrusted-workspace-input-to-process"].engine, "semgrep")
        self.assertEqual(rules["untrusted-workspace-input-to-process"].evidence_class, "capability")
        self.assertEqual(rules["untrusted-workspace-input-to-process"].default_severity, "MEDIUM")
        self.assertEqual(rules["unicode-evasion"].engine, "yara")
        self.assertEqual(rules["ast-dynamic-call-target"].engine, "javascript-ast")
        self.assertEqual(rules["encoded-dynamic-execution"].decision_effect, "review-context")
        self.assertEqual(rules["known-bad-artifact"].decision_effect, "block-by-default")
        self.assertEqual(rules["known-malicious-extension"].evidence_class, "confirmed")
        self.assertEqual(rules["known-malicious-extension"].decision_effect, "block-by-default")
        self.assertEqual(rules["network-access"].decision_effect, "review-context")
        self.assertEqual(rules["sandbox-runtime-timeout"].decision_effect, "review-context")
        self.assertEqual(rules["sandbox-runtime-error"].decision_effect, "review-context")
        self.assertEqual(rules["observed-secret-exfil"].decision_effect, "review-or-block-by-policy")
        self.assertEqual(rules["runtime-canary-exposed"].decision_effect, "review-context")

    def test_rules_json_is_self_describing(self) -> None:
        payload = rules_json()
        first = payload["rules"][0]

        self.assertIn("engine", first)
        self.assertIn("decision_effect", first)
        self.assertIn("confidence_basis", first)

    def test_literal_native_findings_are_present_in_rule_catalog(self) -> None:
        scanner_path = Path(__file__).resolve().parents[1] / "src" / "ide_scanner" / "scanner.py"
        tree = ast.parse(scanner_path.read_text(encoding="utf-8"))
        emitted = {
            node.args[2].value
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_finding"
            and len(node.args) > 2
            and isinstance(node.args[2], ast.Constant)
            and isinstance(node.args[2].value, str)
        }
        registered = {rule.rule_id for rule in rule_registry()}
        self.assertFalse(emitted - registered, f"Missing rule metadata: {sorted(emitted - registered)}")

    def test_dynamic_observation_findings_are_present_in_rule_catalog(self) -> None:
        scanner_path = Path(__file__).resolve().parents[1] / "src" / "ide_scanner" / "scanner.py"
        tree = ast.parse(scanner_path.read_text(encoding="utf-8"))
        dynamic_ids: set[str] = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef) or node.name != "_sandbox_observation_finding":
                continue
            for child in ast.walk(node):
                if not isinstance(child, ast.Assign) or not any(
                    isinstance(target, ast.Name) and target.id == "mapping" for target in child.targets
                ):
                    continue
                if not isinstance(child.value, ast.Dict):
                    continue
                for value in child.value.values:
                    if isinstance(value, ast.Tuple) and value.elts and isinstance(value.elts[0], ast.Constant):
                        if isinstance(value.elts[0].value, str):
                            dynamic_ids.add(value.elts[0].value)
        registered = {rule.rule_id for rule in rule_registry()}
        self.assertTrue(dynamic_ids, "Expected runtime observation mapping to be discoverable")
        self.assertFalse(dynamic_ids - registered, f"Missing dynamic rule metadata: {sorted(dynamic_ids - registered)}")
