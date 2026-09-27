"""
Phase 1 tests — policy/config plumbing for command_injection_detector.

Covers:
  - YAML policy loads and validates
  - per-mission-profile override merging (positive + negative)
  - invalid config fails loudly (ConfigError) — schema + structural
  - fail_mode end-to-end: alert_and_pass never drops; alert_and_block marks drop
  - legacy constructor API still works (no config required)

Run:  python -m pytest test_command_injection_config.py -v
"""

import os
import sys
import tempfile

import pytest
import yaml


from ids.command_injection_detector import (  # noqa: E402
    CMD_ARM_DISARM,
    CMD_TAKEOFF,
    CommandInjectionDetector,
    MockCommandMessage,
)
from ids.ids_config import ConfigError, load_config  # noqa: E402

CFG = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "..", "configs", "command_injection.yaml")


def make_cmd(msg_type: str, sysid: int, cmd) -> MockCommandMessage:
    return MockCommandMessage(msg_type, sysid, cmd)


# ---------------------------------------------------------------------------
# YAML load + schema validation
# ---------------------------------------------------------------------------
def test_valid_yaml_loads():
    cfg = load_config(CFG)
    assert cfg["fail_mode"] == "alert_and_pass"
    assert 255 in cfg["authorized_sysids"]
    assert "FLYING" in cfg["states"]


def test_invalid_yaml_raises():
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
        yaml.dump({"fail_mode": "bogus", "states": {}, "rate_limit": -1}, fh)
        path = fh.name
    try:
        with pytest.raises(ConfigError):
            load_config(path)
    finally:
        os.unlink(path)


def test_missing_file_raises():
    with pytest.raises(ConfigError):
        load_config("/nonexistent/policy.yaml")


def test_bad_transition_reference_raises():
    pol = {
        "fail_mode": "alert_and_pass",
        "states": {"A": {"allowed_commands": ["X"],
                         "transitions_to": ["NOPE"]}},
        "rate_limit": {"commands_per_sec": 5},
        "authorized_sysids": [255],
        "mission_profiles": {},
    }
    with pytest.raises(ConfigError):
        load_config(default_policy=pol)


def test_unknown_profile_raises():
    with pytest.raises(ConfigError):
        load_config(CFG, profile="does_not_exist")


# ---------------------------------------------------------------------------
# Per-mission-profile merging
# ---------------------------------------------------------------------------
def test_profile_recon_lowers_rate_limit():
    det = CommandInjectionDetector(config_path=CFG, profile="recon")
    assert det._max_per_sec == 10
    assert det.policy["fail_mode"] == "alert_and_pass"


def test_profile_delivery_adds_command_positive():
    det = CommandInjectionDetector(config_path=CFG, profile="delivery")
    det.update_state_from_telemetry("FLYING")
    alert = det.process_command(
        make_cmd("COMMAND_LONG", 255, "NAV_CONTINUE_AND_CHANGE_ALT"))
    assert alert is None          # added by delivery profile -> OK


def test_profile_delivery_adds_command_negative():
    det = CommandInjectionDetector(config_path=CFG)   # base policy
    det.update_state_from_telemetry("FLYING")
    alert = det.process_command(
        make_cmd("COMMAND_LONG", 255, "NAV_CONTINUE_AND_CHANGE_ALT"))
    assert alert is not None      # NOT in base policy -> flagged


def test_profile_survey_allows_second_sysid_positive():
    det = CommandInjectionDetector(config_path=CFG, profile="survey")
    alert = det.process_command(make_cmd("COMMAND_LONG", 10, CMD_ARM_DISARM))
    assert alert is None          # sysid 10 allowed in survey profile


def test_profile_survey_rejects_outsider_negative():
    det = CommandInjectionDetector(config_path=CFG, profile="survey")
    alert = det.process_command(make_cmd("COMMAND_LONG", 7, CMD_ARM_DISARM))
    assert alert is not None and alert["reason"] == "unauthorized_command_source"


# ---------------------------------------------------------------------------
# Fail mode behaviour
# ---------------------------------------------------------------------------
def test_fail_mode_alert_and_pass_default_no_drop():
    det = CommandInjectionDetector(config_path=CFG)   # default alert_and_pass
    assert det.fail_mode == "alert_and_pass"
    alert = det.process_command(make_cmd("COMMAND_LONG", 7, CMD_ARM_DISARM))
    assert alert is not None and alert.get("drop") is False


def test_fail_mode_alert_and_block_sets_drop():
    pol = load_config(CFG)
    pol["fail_mode"] = "alert_and_block"
    det = CommandInjectionDetector(policy=pol)
    assert det.fail_mode == "alert_and_block"
    alert = det.process_command(make_cmd("COMMAND_LONG", 7, CMD_ARM_DISARM))
    assert alert is not None and alert.get("drop") is True


def test_fail_mode_clean_command_no_alert():
    pol = load_config(CFG)
    pol["fail_mode"] = "alert_and_block"
    det = CommandInjectionDetector(policy=pol, initial_state="DISARMED")
    assert det.process_command(make_cmd("COMMAND_LONG", 255, CMD_ARM_DISARM)) is None


def test_config_path_and_policy_conflict_raises():
    with pytest.raises(ValueError):
        CommandInjectionDetector(config_path=CFG, policy=load_config(CFG))


# ---------------------------------------------------------------------------
# Legacy API preserved
# ---------------------------------------------------------------------------
def test_legacy_constructor_no_config():
    det = CommandInjectionDetector(initial_state="DISARMED", authorized_sysid=255)
    assert det.process_command(make_cmd("COMMAND_LONG", 255, CMD_ARM_DISARM)) is None


def test_legacy_unauthorized_sysid():
    det = CommandInjectionDetector(initial_state="DISARMED", authorized_sysid=255)
    alert = det.process_command(make_cmd("COMMAND_LONG", 7, CMD_ARM_DISARM))
    assert alert is not None and alert["reason"] == "unauthorized_command_source"


def test_legacy_state_takeoff_injection():
    det = CommandInjectionDetector(initial_state="FLYING", authorized_sysid=255)
    alert = det.process_command(make_cmd("COMMAND_LONG", 255, CMD_TAKEOFF))
    assert alert is not None and alert["reason"] == "command_not_allowed_in_state"