"""GitHub Action wrapper: read-only permissions, no secret-bearing outputs."""

from pathlib import Path

import yaml

ACTION_PATH = Path(__file__).parent.parent / "action.yml"
WORKFLOW_PATH = (
    Path(__file__).parent.parent / "examples" / "workflows" / "closure-audit.yml"
)


def load_action():
    return yaml.safe_load(ACTION_PATH.read_text())


def test_action_is_valid_yaml_with_expected_inputs():
    action = load_action()
    inputs = action["inputs"]
    for name in (
        "org",
        "repo",
        "include-repo",
        "exclude-repo",
        "config",
        "output",
        "out-dir",
        "redact-repo-names",
        "fail-on-gcs3",
        "fail-on-gcs4",
    ):
        assert name in inputs, f"missing action input: {name}"
    assert action["runs"]["using"] == "composite"


def test_action_has_no_secret_outputs():
    """The action must not expose alert/secret data as action outputs."""
    action = load_action()
    outputs = action.get("outputs", {}) or {}
    for name in outputs:
        assert "secret" not in name.lower()
    # No step echoes secret values into outputs or environment files.
    text = ACTION_PATH.read_text().lower()
    assert "github_output" not in text
    assert "secrets." not in text  # the action never references workflow secrets


def test_action_uploads_report_artifact():
    action = load_action()
    steps = action["runs"]["steps"]
    uses = [s.get("uses", "") for s in steps]
    assert any(u.startswith("actions/upload-artifact") for u in uses)


def test_action_never_runs_write_commands():
    """The audit step invokes only the groundcyber CLI (read-only GETs)."""
    action = load_action()
    for step in action["runs"]["steps"]:
        script = step.get("run", "")
        for forbidden in ("curl -X POST", "curl -X PATCH", "curl -X DELETE",
                          "gh api -X", "git push", "git commit"):
            assert forbidden not in script


def test_example_workflow_uses_read_only_permissions():
    workflow = yaml.safe_load(WORKFLOW_PATH.read_text())
    permissions = workflow["permissions"]
    assert permissions == {"contents": "read", "security-events": "read"}
