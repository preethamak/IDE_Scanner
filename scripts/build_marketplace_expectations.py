"""Build the v2 marketplace-cohort expectations manifest.

Merges the live public registry inventory (the 100 served artifacts, with
their exact versions and artifact hashes) with the researcher-validated
calibration targets from the 2026-08 audit. Strict fields (decision,
public_outcome, malware ceiling) fail the cohort run; tolerant fields
(risk bands, severity ceilings) warn so score drift stays visible without
blocking.

Usage:
  python scripts/build_marketplace_expectations.py \
      --inventory /path/to/inventory.json \
      --out benchmarks/marketplace-cohort/v2/expectations.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

# Researcher-validated calibration targets (audit of the 100 served verdicts).
# decision/public_outcome are STRICT; risk bands and severity ceilings are
# TOLERANT. "unchanged" rows pin today-correct verdicts against regressions.
TARGETS: dict[str, dict] = {
    # --- preventive-block false positives -> review via intent veto ---
    "ms-python.python": {
        "decision": "review", "outcome": "explained_preventive_chain",
        "risk_range": [40, 99], "severity_max": "HIGH",
        "evidence": "Toolchain manager; chain is documented updater behavior",
    },
    "ms-python.vscode-pylance": {"decision": "review", "outcome": "explained_preventive_chain", "risk_range": [40, 99], "severity_max": "HIGH", "evidence": "MS language server; updater flow"},
    "ms-python.vscode-python-envs": {"decision": "review", "outcome": "explained_preventive_chain", "risk_range": [40, 99], "severity_max": "HIGH", "evidence": "MS env manager"},
    "ms-toolsai.jupyter": {"decision": "review", "outcome": "explained_preventive_chain", "risk_range": [40, 99], "severity_max": "HIGH", "evidence": "Kernel installer"},
    "ms-vscode-remote.remote-containers": {"decision": "review", "outcome": "explained_preventive_chain", "risk_range": [40, 99], "severity_max": "HIGH", "evidence": "Container tooling"},
    "eamodio.gitlens": {"decision": "review", "outcome": "explained_preventive_chain", "risk_range": [40, 99], "severity_max": "HIGH", "evidence": "Built-in extension updater"},
    "redhat.vscode-yaml": {"decision": "review", "outcome": "explained_preventive_chain", "risk_range": [40, 99], "severity_max": "HIGH", "evidence": "SchemaStore fetcher"},
    "dart-code.dart-code": {"decision": "review", "outcome": "explained_preventive_chain", "risk_range": [40, 99], "severity_max": "HIGH", "evidence": "SDK downloader"},
    # --- correct block preserved ---
    "formulahendry.code-runner": {
        "decision": "block", "outcome": "preventive_block",
        "forbidden_rule_ids_absent": [], "require_rule_ids": ["known-vulnerable-extension"],
        "evidence": "CVE-2025-65715 policy_action=block — must survive all phases",
    },
    # --- vuln-severity honesty (exact-match blanket HIGH was wrong) ---
    "aaron-bond.better-comments": {"decision": "allow", "alt_decisions": ["review"], "severity_max": "MEDIUM", "risk_range": [0, 60], "evidence": "json5 advisory mapped by database severity"},
    "naumovs.color-highlight": {"decision": "allow", "alt_decisions": ["review"], "severity_max": "MEDIUM", "risk_range": [0, 60], "evidence": "@babel/runtime advisory mapped"},
    "xdebug.php-debug": {"decision": "review", "alt_decisions": ["allow"], "severity_max": "MEDIUM", "risk_range": [20, 75], "evidence": "same mechanism, debugger capability keeps review defensible"},
    "Zignd.html-css-class-completion": {"decision": "allow", "alt_decisions": ["review"], "severity_max": "MEDIUM", "risk_range": [0, 65], "evidence": "advisory-mapped"},
    "GitHub.copilot-chat": {"decision": "review", "severity_max": "MEDIUM", "risk_range": [30, 80], "evidence": "AI class review retained; severity honest"},
    # --- bundled-context demotion ---
    "oderwat.indent-rainbow": {"decision": "allow", "severity_max": "LOW", "risk_range": [0, 36], "evidence": "YARA weak hits in vendored playwright code"},
    # --- AI-assistant class consistency ---
    "TabNine.tabnine-vscode": {"decision": "review", "outcome": "investigate", "risk_range": [30, 70], "evidence": "agentic API surface now detected"},
    "openai.chatgpt": {"decision": "review", "outcome": "investigate", "risk_range": [30, 70], "evidence": "agentic API surface now detected"},
}

# Reviews that were already correct and must not move.
REVIEW_UNCHANGED = {
    "GitHub.copilot", "Anthropic.claude-code", "WakaTime.vscode-wakatime",
    "MS-vsliveshare.vsliveshare", "ritwickdey.LiveServer", "ms-mssql.mssql",
    "ms-vscode.PowerShell", "ms-dotnettools.csdevkit",
    "VisualStudioExptTeam.vscodeintellicode", "HookyQR.beautify",
    "donjayamanne.githistory", "cschlosser.doxdocgen", "ms-python.debugpy",
}

_SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    items = json.loads(args.inventory.read_text(encoding="utf-8"))["items"]
    extensions: dict[str, dict] = {}
    for item in items:
        ext_id = item["extension_id"]
        key = f"{ext_id}@{item['version']}"
        target = TARGETS.get(ext_id)
        if target is not None:
            row = {
                "extension_id": ext_id,
                "version": item["version"],
                "artifact_sha256": item["artifact_sha256"],
                "expected_decision": target["decision"],
                "strict_decision": True,
                "allowed_alt_decisions": target.get("alt_decisions", []),
                "expected_outcome": target.get("outcome"),
                "risk_band": target.get("risk_range"),
                "severity_max": target.get("severity_max"),
                "require_rule_ids": target.get("require_rule_ids", []),
                "label_evidence": target["evidence"],
            }
        else:
            current = item["decision"]
            outcome = {"allow": "clear", "review": "investigate", "block": "preventive_block"}[current]
            if current == "review" and ext_id in REVIEW_UNCHANGED:
                pass  # strict unchanged
            row = {
                "extension_id": ext_id,
                "version": item["version"],
                "artifact_sha256": item["artifact_sha256"],
                "expected_decision": current,
                "strict_decision": True,
                "allowed_alt_decisions": [],
                "expected_outcome": outcome if current != "review" or ext_id in REVIEW_UNCHANGED else None,
                "risk_band": None,
                "severity_max": None,
                "require_rule_ids": [],
                "label_evidence": "unchanged verdict (researcher-assessed correct)",
            }
        extensions[key] = row

    manifest = {
        "cohort_id": "marketplace-served-v2",
        "source_inventory": args.inventory.name,
        "policy_version": "3.2.0-intent-gate.1",
        "ruleset_version": "see rule_registry.RULESET_VERSION at run time",
        "count": len(extensions),
        "extensions": extensions,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(manifest, indent=2))
    print(f"wrote {len(extensions)} expectation rows to {args.out}")


if __name__ == "__main__":
    main()
