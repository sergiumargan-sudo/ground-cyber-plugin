"""Config parsing: safety rules must be non-weakenable; filtering must work."""

import pytest
import yaml

from groundcyber.config import (
    DEFAULT_NON_CLOSING_LABELS,
    SAMPLE_CONFIG,
    Config,
    ConfigError,
    load_config,
    parse_config,
    write_sample_config,
)


def test_sample_config_is_valid_yaml_and_parses():
    data = yaml.safe_load(SAMPLE_CONFIG)
    config = parse_config(data)
    assert config.outputs == ["markdown", "json"]
    assert config.treat_unknown_validity_as == "provisional"
    assert config.stale_resolved_days == 30
    for label in DEFAULT_NON_CLOSING_LABELS:
        assert label in config.non_closing_labels


def test_init_writes_loadable_file(tmp_path):
    path = tmp_path / ".groundcyber.yml"
    write_sample_config(str(path))
    config = load_config(str(path))
    assert isinstance(config, Config)
    with pytest.raises(ConfigError):
        write_sample_config(str(path))  # refuses to overwrite without force


def test_missing_config_file_yields_defaults(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config = load_config(None)
    assert config.outputs == ["markdown", "json"]


def test_cannot_disable_provider_inactive_rule():
    with pytest.raises(ConfigError, match="cannot be disabled"):
        parse_config({"closure": {"require_provider_inactive_for_gcs0": False}})


def test_unknown_validity_cannot_be_treated_as_safe():
    for unsafe in ("safe", "closed", "verified", "gcs0", ""):
        with pytest.raises(ConfigError):
            parse_config({"closure": {"treat_unknown_validity_as": unsafe}})


def test_privacy_rules_cannot_be_weakened():
    for key in ("store_raw_secrets", "print_raw_secrets"):
        with pytest.raises(ConfigError):
            parse_config({"privacy": {key: True}})
    with pytest.raises(ConfigError):
        parse_config({"privacy": {"hash_secret_values": False}})
    with pytest.raises(ConfigError):
        parse_config({"privacy": {"upload_to_ground_dashboard": True}})


def test_read_only_cannot_be_disabled():
    with pytest.raises(ConfigError):
        parse_config({"github": {"read_only": False}})


def test_default_non_closing_labels_cannot_be_removed():
    config = parse_config(
        {"closure": {"resolution_labels_do_not_close": ["my_custom_label"]}}
    )
    assert "my_custom_label" in config.non_closing_labels
    for label in DEFAULT_NON_CLOSING_LABELS:
        assert label in config.non_closing_labels


def test_invalid_output_format_rejected():
    with pytest.raises(ConfigError):
        parse_config({"report": {"outputs": ["pdf"]}})


def test_include_exclude_repo_filtering():
    config = Config(
        include_repos=["acme/*"],
        exclude_repos=["acme/sandbox-*"],
    )
    assert config.repo_in_scope("acme/api") is True
    assert config.repo_in_scope("acme/sandbox-test") is False
    assert config.repo_in_scope("other/api") is False

    no_filters = Config()
    assert no_filters.repo_in_scope("anything/at-all") is True

    exclude_only = Config(exclude_repos=["*/archived-*"])
    assert exclude_only.repo_in_scope("acme/archived-old") is False
    assert exclude_only.repo_in_scope("acme/live") is True
