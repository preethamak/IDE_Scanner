from pathlib import Path


def test_release_workflow_installs_pytest_before_unittest_discovery() -> None:
    workflow = (Path(__file__).parents[1] / ".github" / "workflows" / "release-core.yml").read_text(encoding="utf-8")
    install_line = next(line for line in workflow.splitlines() if "pip install --upgrade" in line)
    assert "pytest" in install_line
    assert "python -m unittest discover" in workflow
