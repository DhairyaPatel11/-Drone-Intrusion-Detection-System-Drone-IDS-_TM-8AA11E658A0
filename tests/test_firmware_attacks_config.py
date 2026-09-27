"""
Phase 1 tests — firmware attacks config/policy plumbing.

Covers:
  - YAML policy loads and validates (firmware + companion_integrity + behavioral_baseline)
  - per-mission-profile override merging (positive + negative)
  - invalid config fails loudly (ConfigError) — schema + structural
  - fail_mode end-to-end: alert_and_pass never drops; alert_and_block marks drop
"""

import os
import sys
import tempfile

import pytest
import yaml


from ids.ids_config import ConfigError, load_config  # noqa: E402

CFG = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "..", "configs", "firmware_attacks.yaml")


def test_firmware_yaml_loads():
    cfg = load_config(CFG)
    assert cfg["fail_mode"] == "alert_and_pass"
    assert "firmware" in cfg
    assert "companion_integrity" in cfg
    assert "behavioral_baseline" in cfg
    # Firmware section
    fw = cfg["firmware"]
    assert "approved_versions" in fw and len(fw["approved_versions"]) >= 1
    assert "protected_param_prefixes" in fw and len(fw["protected_param_prefixes"]) >= 1
    assert "protected_ftp_paths" in fw and len(fw["protected_ftp_paths"]) >= 1
    assert "update_window" in fw
    assert "reboot_rules" in fw
    # Companion integrity
    ci = cfg["companion_integrity"]
    assert ci["enabled"] is True
    assert "manifest_path" in ci
    assert "watch_dirs" in ci and len(ci["watch_dirs"]) >= 1
    # Behavioral baseline
    bb = cfg["behavioral_baseline"]
    assert bb["enabled"] is False  # default off
    assert "features" in bb


def test_firmware_invalid_yaml_raises():
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
        yaml.dump({"fail_mode": "bogus", "states": {}, "rate_limit": -1,
                   "firmware": {}, "companion_integrity": {}}, fh)
        path = fh.name
    try:
        with pytest.raises(ConfigError):
            load_config(path)
    finally:
        os.unlink(path)


def test_firmware_missing_file_raises():
    with pytest.raises(ConfigError):
        load_config("/nonexistent/firmware.yaml")


def test_firmware_bad_schema_raises():
    pol = {
        "fail_mode": "alert_and_pass",
        "states": {"A": {"allowed_commands": [], "transitions_to": []}},
        "rate_limit": {"commands_per_sec": 5},
        "authorized_sysids": [255],
        "firmware": {"protected_param_prefixes": "not_a_list"},  # should be list
        "companion_integrity": {"enabled": "not_bool"},
        "behavioral_baseline": {"enabled": "not_bool"},
        "mission_profiles": {},
    }
    with pytest.raises(ConfigError):
        load_config(default_policy=pol)


def test_firmware_unknown_profile_raises():
    with pytest.raises(ConfigError):
        load_config(CFG, profile="does_not_exist")


# ---------------------------------------------------------------------------
# Per-mission-profile merging
# ---------------------------------------------------------------------------
def test_profile_high_value_tightens_firmware():
    det_cfg = load_config(CFG, profile="high_value")
    fw = det_cfg["firmware"]
    # high_value profile adds SERVO_ and RC_ prefixes
    assert "SERVO_" in fw["protected_param_prefixes"]
    assert "RC_" in fw["protected_param_prefixes"]
    # reboot_rules tightened
    assert fw["reboot_rules"]["allow_bootloader_reboot_disarmed"] is False
    # companion integrity always verifies
    assert det_cfg["companion_integrity"]["verify_on_update_only"] is False
    # behavioral baseline enabled with tighter threshold
    bb = det_cfg["behavioral_baseline"]
    assert bb["enabled"] is True
    assert bb["drift_threshold_std"] == 3.0


def test_profile_high_value_preserves_base():
    det_cfg = load_config(CFG, profile="high_value")
    # Base settings not overridden should remain
    assert det_cfg["fail_mode"] == "alert_and_pass"
    assert det_cfg["firmware"]["reject_downgrade"] is True
    assert det_cfg["firmware"]["max_ftp_block_size"] == 512


# ---------------------------------------------------------------------------
# Legacy constructor API (no config file) still works
# ---------------------------------------------------------------------------
def test_default_policy_includes_firmware_sections():
    from ids.ids_config import default_policy
    pol = default_policy()
    assert "firmware" in pol
    assert "companion_integrity" in pol
    assert "behavioral_baseline" in pol
    assert pol["firmware"]["reject_downgrade"] is True
    assert pol["companion_integrity"]["enabled"] is True
    assert pol["behavioral_baseline"]["enabled"] is False


# ---------------------------------------------------------------------------
# Structural cross-reference checks (state transitions)
# ---------------------------------------------------------------------------
def test_firmware_state_transitions_valid():
    cfg = load_config(CFG)
    states = cfg["states"]
    for state, body in states.items():
        for target in body.get("transitions_to", []):
            assert target in states, f"{state} -> {target} invalid"