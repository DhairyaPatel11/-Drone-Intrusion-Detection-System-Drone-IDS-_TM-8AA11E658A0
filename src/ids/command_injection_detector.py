#!/usr/bin/env python3
"""
command_injection_detector.py

STATE-MACHINE BASED COMMAND INJECTION DETECTOR
================================================
Layer 2 of the Communication-Attacks IDS pipeline.

The FIRST layer of defence (MAVLink 2.0 signing, enforced by the flight
controller upstream via MAV1_OPTIONS=1) rejects *unsigned/unauthorized*
frames. This module is the SECOND layer: a state-machine validator that
catches commands which are technically well-formed and correctly signed,
but LOGICALLY INVALID given the drone's current flight state.

Example attack caught here:
  - Attacker has the signing key (or is an insider/compromised GCS).
  - Attacker sends "NAV_TAKEOFF" while the drone is already FLYING at
    cruise altitude -> most flight controllers would not execute it, but
    some might re-trigger takeoff logic. We flag it BEFORE it reaches the
    autopilot handler.

Design notes (for the viva):
  - State transitions come ONLY from ground-truth telemetry (HEARTBEAT
    mode field), never from the command stream. This prevents an attacker
    from spoofing a state-confirmation message to reset our state machine.
  - Every check is logged at DEBUG; every alert at WARNING.
  - The command->allowed-state mapping implements the principle of least
    privilege for the command channel.
"""

import logging
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, NamedTuple, Any

# Phase 1: policy/config loading with schema validation (fail loud).
from .ids_config import (
    ConfigError,
    default_policy,
    get_authorized_sysids,
    get_fail_mode,
    load_config,
)

# Phase 4 — MITRE ATT&CK for ICS mapping per rule_id
_MITRE_MAP: Dict[str, str] = {
    "unauthorized_command_source": "T0883",          # Command Injection
    "unauthorized_command_compid": "T0883",
    "command_rate_limit_exceeded": "T0886",          # DoS via command flood
    "command_not_allowed_in_state": "T0831",         # Command injection
    "unknown_command_not_in_policy": "T0883",
    "validator_state_unknown": "T0831",
    "command_param_out_of_bounds": "T0883",
    "disarm_while_airborne": "T0831",
    "takeoff_while_flying": "T0831",
    "waypoint_teleport": "T0831",
    "waypoint_alt_step_too_large": "T0831",
    "altitude_teleport_vs_telemetry": "T0831",
    "unsolicited_ack_command": "T0831",
    "missing_ack_command": "T0831",
    "unauthorized_command_compid": "T0883",
    "mission_seq_duplicate": "T0831",
    "mission_seq_gap": "T0831",
    "mission_geofence": "T0831",
    "unsigned_frame_but_signing_required": "T0856",   # Integrity violation
    "malformed_signature_too_short": "T0856",
    "signature_timestamp_out_of_window": "T0856",
    "invalid_signature": "T0856",
    "crc_mismatch": "T0856",
    "duplicate_sequence": "T0886",
    "backward_sequence_jump": "T0886",
    "large_forward_gap": "T0886",
    "stale_packet": "T0886",
    "replay_detected": "T0886",
    "stale_timestamp": "T0886",
    "timestamp_not_newer": "T0886",
    "stale_frame": "T0886",
    # ---- Firmware attacks (Phases 2-3) ----
    "bootloader_reboot_armed": "T0831",
    "bootloader_reboot_disarmed": "T0831",
    "bootloader_mode_armed": "T0831",
    "bootloader_mode_disarmed": "T0831",
    "bootloader_status_text": "T0831",
    "unauthorized_firmware_update": "T0831",
    "unauthorized_file_operation": "T0831",
    "ftp_block_oversized": "T0856",
    "ftp_file_oversized": "T0856",
    "ftp_write_to_protected_path": "T0856",
    "unexpected_firmware_version": "T0856",
    "firmware_version_downgrade": "T0856",
    "unexpected_git_hash": "T0856",
    "git_hash_downgrade": "T0856",
    "unexpected_boot_count_jump": "T0856",
    "unexpected_uptime_jump": "T0856",
    "protected_parameter_change_invalid_state": "T0831",
    "protected_parameter_change_not_allowed": "T0831",
    "companion_file_hash_mismatch": "T0856",
    "companion_file_unexpected": "T0856",
    "companion_file_missing": "T0856",
    "manifest_signature_invalid": "T0856",
    "manifest_load_error": "T0856",
    "update_outside_allowed_window": "T0831",
    "update_without_valid_manifest": "T0831",
    "behavioral_baseline_drift": "T0856",
    "lua_script_upload": "T0856",
}

# Phase 4 — structured alert dataclass
@dataclass(slots=True)
class IDSAlert:
    """Structured alert for JSON serialization."""
    timestamp: float
    severity: str                 # high | medium | low
    reason: str                   # rule-specific code
    rule_id: Optional[str] = None # e.g., PHY-001, SIGN-001
    mitre_attack: Optional[str] = None
    command: Optional[str] = None
    state: Optional[str] = None
    sysid: Optional[int] = None
    compid: Optional[int] = None
    msg_id: Optional[int] = None
    detail: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None
    confidence: Optional[float] = None
    # Phase 5 (firmware attacks) — classification + observability origin
    attack_class: Optional[str] = None      # e.g. 'unauthorized_upload'
    observable_from: Optional[str] = None   # 'mavlink_stream'|'companion'|'needs_fc_trust'
    # Phase 5 (navigation) — extended fields
    affected_channel: Optional[str] = None  # e.g. 'gnss', 'baro', 'magnetometer', 'optflow', 'rtk'
    recommended_action: Optional[str] = None  # 'distrust', 'caution', 're_anchor', 'none'

    def to_json(self, include_mitre: bool = True) -> Dict[str, Any]:
        d = {
            "timestamp": round(self.timestamp, 6),
            "severity": self.severity,
            "reason": self.reason,
            "rule_id": self.rule_id,
            "command": self.command,
            "state": self.state,
            "sysid": self.sysid,
            "compid": self.compid,
            "msg_id": self.msg_id,
            "detail": self.detail,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "attack_class": self.attack_class,
            "observable_from": self.observable_from,
            "affected_channel": self.affected_channel,
            "recommended_action": self.recommended_action,
        }
        if include_mitre and self.mitre_attack:
            d["mitre_attack"] = self.mitre_attack
        # drop None values
        return {k: v for k, v in d.items() if v is not None}

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger("ids.command_injection")
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("[%(name)s] %(levelname)s: %(message)s"))
    logger.addHandler(_h)
    logger.setLevel(logging.DEBUG)


# ---------------------------------------------------------------------------
# Drone flight-state finite state machine
# ---------------------------------------------------------------------------
# Canonical flight states understood by the validator.
FlightState = str

VALID_STATES: Tuple[FlightState, ...] = (
    "DISARMED", "ARMED", "TAKING_OFF", "FLYING", "LANDING", "RETURNING",
)

# MAVLink command names (MAV_CMD_* camelCase, without the "MAV_CMD_" prefix
# for brevity — see COMMAND_LONG/COMMAND_INT payload field7 == command id).
# Common ArduPilot command names used across the system:
CMD_ARM_DISARM     = "COMPONENT_ARM_DISARM"
CMD_TAKEOFF        = "NAV_TAKEOFF"
CMD_LAND           = "NAV_LAND"
CMD_RTL            = "NAV_RETURN_TO_LAUNCH"
CMD_SET_MODE       = "DO_SET_MODE"
CMD_LOITER         = "NAV_LOITER_UNLIM"
CMD_WAYPOINT       = "NAV_WAYPOINT"
CMD_MAINTAIN_ALT   = "NAV_CONTINUE_AND_CHANGE_ALT"
CMD_SET_PARAM      = "PARAM_SET"


# ---------------------------------------------------------------------------
# State -> allowed commands mapping
# ---------------------------------------------------------------------------
# Each flight state only accepts the commands that are legal in that state.
# This is the security policy of the command channel.
STATE_ALLOWED_COMMANDS: Dict[FlightState, List[str]] = {
    "DISARMED":   [CMD_ARM_DISARM],                       # only arming allowed
    "ARMED":      [CMD_TAKEOFF, CMD_LOITER, CMD_SET_MODE],  # takeoff prep
    "TAKING_OFF": [CMD_SET_MODE],                         # auto-transitioning; minimal external input
    "FLYING":     [CMD_LAND, CMD_RTL, CMD_LOITER, CMD_SET_MODE, CMD_WAYPOINT, CMD_SET_PARAM],
    "LANDING":    [CMD_SET_MODE],                         # auto-transitioning
    "RETURNING":  [CMD_SET_MODE],                         # auto-transitioning
}

# State transitions that are legal (used only for validation clarity).
# Ground truth always comes from telemetry via update_state().
VALID_TRANSITIONS: Dict[FlightState, Tuple[FlightState, ...]] = {
    "DISARMED":   ("ARMED",),
    "ARMED":      ("TAKING_OFF", "DISARMED"),
    "TAKING_OFF": ("FLYING", "LANDING"),
    "FLYING":     ("LANDING", "RETURNING", "DISARMED"),   # DISARMED via crash/wind-down
    "LANDING":    ("DISARMED", "ARMED"),
    "RETURNING":  ("LANDING", "FLYING", "DISARMED"),
}


# ---------------------------------------------------------------------------
# pymavlink-compatible message mock (only used if pymavlink is not present)
# ---------------------------------------------------------------------------
class MockMavlinkMessage(NamedTuple):
    """Minimal stand-in for a pymavlink message object."""
    get_type: str          # (= attribute name shadowed, careful)
    sysid: int
    command: Optional[str] = None   # extracted MAV_CMD name for COMMAND_* msgs


class MockCommandMessage:
    """Simple dict-like message with attribute access, for testing."""
    def __init__(self, msg_type: str, sysid: int, command: Optional[str] = None):
        self._type = msg_type
        self.sysid = sysid
        self.command = command

    def get_type(self) -> str:
        return self._type


# ---------------------------------------------------------------------------
# Helper: extract command name + sysid from a pymavlink message
# ---------------------------------------------------------------------------
def parse_mavlink_command(msg) -> Tuple[Optional[str], Optional[int]]:
    """
    Extract (command_name, system_id) from a pymavlink message object.

    Supports:
      - COMMAND_LONG / COMMAND_INT:  .command is the int MAV_CMD id
      - SET_MODE:                    synthesized as "DO_SET_MODE"
      - Raw mavutil messages:        .get_type() and .sysid/.get_srcSystem()

    If pymavlink is installed with the ArduPilot dialect, the 3-byte int
    command id is resolved to its mavlink name (e.g. 400 ->
    "MAV_CMD_COMPONENT_ARM_DISARM"). Otherwise we fall back to the numeric
    id as a string.

    Args:
        msg: A pymavlink message, or a MockCommandMessage in tests.

    Returns:
        (command_name, sysid) — (None, None) for non-command messages.
    """
    try:
        msg_type = msg.get_type()
    except AttributeError:
        logger.warning("Cannot read get_type() from message: %r", msg)
        return None, None

    # Source system id — pymavlink exposes this via get_srcSystem() or .sysid
    sysid = getattr(msg, "sysid", None)
    if sysid is None and hasattr(msg, "get_srcSystem"):
        sysid = msg.get_srcSystem()

    # Only command-carrying messages are relevant
    command = None
    if msg_type in ("COMMAND_LONG", "COMMAND_INT"):
        raw_cmd = getattr(msg, "command", None)
        command = _resolve_command_name(raw_cmd)
    elif msg_type == "SET_MODE":
        command = CMD_SET_MODE
    elif msg_type == "PARAM_SET":
        command = CMD_SET_PARAM

    return command, sysid


# Local int->name map (kept small: only commands our policy cares about).
_CMD_ID_TO_NAME: Dict[int, str] = {
    400: CMD_ARM_DISARM,   # MAV_CMD_COMPONENT_ARM_DISARM
    22:  CMD_TAKEOFF,      # MAV_CMD_NAV_TAKEOFF
    21:  CMD_LAND,         # MAV_CMD_NAV_LAND
    20:  CMD_RTL,          # MAV_CMD_NAV_RETURN_TO_LAUNCH
    183: CMD_SET_MODE,     # MAV_CMD_DO_SET_MODE
    16:  CMD_WAYPOINT,     # MAV_CMD_NAV_WAYPOINT
    17:  CMD_LOITER,       # MAV_CMD_NAV_LOITER_UNLIM
}

# Phase 1 — a module-level default policy derived from the legacy constants,
# returned by _module_policy(). It is replaced by a YAML policy whenever a
# config path is supplied to CommandInjectionDetector(). Kept in sync with
# default_policy() in ids_config.py (single source of truth there).
_DEFAULT_POLICY: Optional[Dict[str, Any]] = None


def _module_policy() -> Dict[str, Any]:
    """Return the default in-memory policy (used when no YAML is given)."""
    global _DEFAULT_POLICY
    if _DEFAULT_POLICY is None:
        _DEFAULT_POLICY = default_policy()
    return _DEFAULT_POLICY


def _resolve_command_name(raw_cmd: Optional[int]) -> Optional[str]:
    """Map a MAV_CMD id (int) to a canonical command name, WITHOUT prefix.

    Accepts both:
      - an int id (as real pymavlink COMMAND_LONG/COMMAND_INT expose)
      - a str name (as used by tests/mocks) — normalised by stripping any
        "MAV_CMD_" prefix and mapping known ids.

    Resolution order:
      1. pymavlink's enum table (authoritative) when installed
      2. local compact map (int ids)
      3. if already a plain string, return it stripped of prefix
      4. unknown int -> "MAV_CMD_<id>" string (still resolvable downstream)
    """
    if raw_cmd is None:
        return None

    # --- String input: normalise -------------------------------------
    if isinstance(raw_cmd, str):
        name = raw_cmd
        if name.startswith("MAV_CMD_"):
            name = name[len("MAV_CMD_"):]
        # Map known aliases back to canonical constants
        for c in (CMD_ARM_DISARM, CMD_TAKEOFF, CMD_LAND, CMD_RTL,
                  CMD_SET_MODE, CMD_WAYPOINT, CMD_LOITER, CMD_SET_PARAM):
            if name.endswith(c):
                return c
        return name

    # --- Int input: pymavlink first, then local map -------------------
    try:
        from pymavlink import mavutil
        name = mavutil.mavlink.enums["MAV_CMD"][raw_cmd].name  # type: ignore[index]
        return name.replace("MAV_CMD_", "")
    except Exception:
        pass

    return _CMD_ID_TO_NAME.get(raw_cmd, f"MAV_CMD_{raw_cmd}")


# ---------------------------------------------------------------------------
# State-machine validator
# ---------------------------------------------------------------------------
class StateMachineValidator:
    """
    Validates incoming commands against the drone's current flight state.

    The policy (states, allowed commands, transitions, fail mode) comes
    from a validated policy dict (default: `_module_policy()`), normally
    loaded from YAML via ids_config.load_config().

    State is only ever updated through update_state(), which the pipeline
    must call with *ground-truth* telemetry (e.g. the mode field of a
    HEARTBEAT message parsed by the autopilot), never with data derived
    from the command stream itself.

    Attributes:
        state: flight state (str).
        policy: policy dict in use (validated).
    """

    def __init__(
        self,
        initial_state: str = "DISARMED",
        policy: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.policy = policy if policy is not None else _module_policy()
        self._states = self.policy["states"]

        if initial_state not in self._states:
            raise ValueError(
                f"Unknown initial state {initial_state!r}; "
                f"valid: {list(self._states)}"
            )
        self.state: str = initial_state
        logger.info("StateMachineValidator initialized in state %s", self.state)

    # ------------------------------------------------------------------
    def check(self, incoming_command: str) -> Optional[dict]:
        """
        Validate one incoming command against the current flight state.

        Args:
            incoming_command: MAVLink command name (no MAV_CMD_ prefix),
                e.g. "COMPONENT_ARM_DISARM", "NAV_TAKEOFF", "NAV_LAND".

        Returns:
            None if the command is legal in the current state.
            Alert dict otherwise:
                {"severity", "reason", "command", "state", "timestamp"}
        """
        now = time.time()

        # Defensive: unknown command names fail SAFELY (alert, don't crash)
        if not isinstance(incoming_command, str) or not incoming_command:
            alert = {
                "severity": "high",
                "reason": "empty_or_invalid_command",
                "command": str(incoming_command),
                "state": self.state,
                "timestamp": now,
            }
            logger.warning("ALERT %s", alert)
            return alert

        # Known commands = union of all allowed commands across states,
        # from the policy (not a hardcoded set).
        known = {c for body in self._states.values() for c in body["allowed_commands"]}
        if incoming_command not in known:
            alert = {
                "severity": "medium",
                "reason": "unknown_command_not_in_policy",
                "command": incoming_command,
                "state": self.state,
                "timestamp": now,
            }
            logger.warning("ALERT %s", alert)
            return alert

        # Unknown flight state — fail safely (should never happen)
        if self.state not in self._states:
            alert = {
                "severity": "high",
                "reason": "validator_state_unknown",
                "command": incoming_command,
                "state": self.state,
                "timestamp": now,
            }
            logger.warning("ALERT %s", alert)
            return alert

        allowed = self._states[self.state]["allowed_commands"]

        if incoming_command in allowed:
            logger.debug(
                "PASS command=%s in state=%s", incoming_command, self.state
            )
            return None

        # Command present but NOT allowed in this state → injection suspect
        alert = {
            "severity": "high",
            "reason": "command_not_allowed_in_state",
            "command": incoming_command,
            "state": self.state,
            "timestamp": now,
        }
        logger.warning("ALERT %s", alert)
        return alert

    # ------------------------------------------------------------------
    def update_state(self, new_state: str) -> None:
        """
        Update the drone's flight state from GROUND-TRUTH telemetry only.

        This method must NEVER be called from the command stream. It is the
        single choke-point used by the pipeline when a HEARTBEAT reports a
        mode change.

        Args:
            new_state: a state defined in the policy's `states` section.
        """
        if new_state not in self._states:
            logger.warning(
                "Ignoring unknown telemetry state %r (keeping %s)",
                new_state, self.state,
            )
            return

        old = self.state
        self.state = new_state
        logger.debug("State transition %s -> %s (from telemetry)", old, new_state)


# ---------------------------------------------------------------------------
# Phase 2 — ArduPilot mode awareness + mode-transition table
# ---------------------------------------------------------------------------
_MODE_ALIASES = {
    "STABILIZE": "STABILIZE", "ACRO": "ACRO", "ALT_HOLD": "ALT_HOLD",
    "ALT_HOLD.ALL": "ALT_HOLD", "AUTO": "AUTO", "GUIDED": "GUIDED",
    "LOITER": "LOITER", "RTL": "RTL", "CIRCLE": "CIRCLE", "LAND": "LAND",
    "DRIFT": "DRIFT", "SPORT": "SPORT", "FLIP": "FLIP", "POSHOLD": "POSHOLD",
    "BRAKE": "BRAKE", "THROW": "THROW", "AVOID_ADSB": "AVOID_ADSB",
    "GUIDED_NOGPS": "GUIDED_NOGPS", "SMART_RTL": "SMART_RTL",
    "FLOWHOLD": "FLOWHOLD", "FOLLOW": "FOLLOW", "ZIGZAG": "ZIGZAG",
    "SYSTEMID": "SYSTEMID", "AUTOROTATE": "AUTOROTATE", "AUTO_RTL": "AUTO_RTL",
}
# Map each ArduPilot mode to the canonical operational phase used in the
# phase-level allow-list tables (STABILIZE/etc. while airborne => FLYING).
_MODE_TO_PHASE = {
    "STABILIZE": "FLYING", "ACRO": "FLYING", "ALT_HOLD": "FLYING",
    "AUTO": "FLYING", "GUIDED": "FLYING", "LOITER": "FLYING",
    "CIRCLE": "FLYING", "DRIFT": "FLYING", "SPORT": "FLYING", "FLIP": "FLYING",
    "POSHOLD": "FLYING", "BRAKE": "FLYING", "THROW": "FLYING",
    "AVOID_ADSB": "FLYING", "GUIDED_NOGPS": "FLYING", "SMART_RTL": "FLYING",
    "FLOWHOLD": "FLYING", "FOLLOW": "FLYING", "ZIGZAG": "FLYING",
    "SYSTEMID": "FLYING", "AUTOROTATE": "FLYING", "AUTO_RTL": "FLYING",
    "RTL": "RETURNING", "LAND": "LANDING",
}


def _canonical_mode(raw) -> Optional[str]:
    """Normalize a mode int/str to its canonical ArduPilot mode name."""
    if raw is None:
        return None
    if isinstance(raw, int):
        return _MODE_ALIASES.get(str(raw))  # int IDs handled via config below
    s = str(raw).upper()
    return _MODE_ALIASES.get(s)


# ---------------------------------------------------------------------------
# Phase 2 — parameter validator (bounds / geofence / enum / mode validity)
# ---------------------------------------------------------------------------
class ParameterValidator:
    """
    Validates the *values* of command parameters, not just the command ID.

    Rules come from policy["command_params"][cmd] plus policy["geofence"],
    policy["param_set_rules"] and policy["modes"]. Each rule:
        {"param1": {"min":..,"max":..} | {"enum":[...]} | {"mode": True}}
    """

    def __init__(self, policy: Dict[str, Any]) -> None:
        self._policy = policy
        self._rules = policy.get("command_params", {})
        self._geo = policy.get("geofence", {})
        self._param_rules = policy.get("param_set_rules", {})
        self._mode_ids = {int(k): v for k, v in policy.get("modes", {}).items()}

    def check_command_params(
        self, command: str, params: Dict[int, float], xyz: Tuple[float, float, float],
    ) -> Optional[str]:
        """
        Returns None if OK, or a reason string naming the violated constraint.
        params: {1..7: value}; xyz: (x, y, z) raw command coords.
        """
        rules = self._rules.get(command)
        if not rules:
            return None
        for key, rule in rules.items():
            if key == "mode":
                mode_no = round(params.get(1, -1))
                if self._canonical_by_id(mode_no) is None:
                    return f"invalid_mode_param={mode_no}"
                continue
            if key.startswith("param"):
                idx = int(key[5:])
                val = params.get(idx)
                if val is None:
                    # Real MAVLink always transmits all 7 params (0.0 when
                    # unused); a missing value here means the parser/mock did
                    # not expose it -> nothing to validate, NOT an anomaly
                    # (flagging absence is an FPR risk).
                    continue
                if "enum" in rule and int(val) not in rule["enum"]:
                    return f"param{idx}_not_in_enum={val}"
                if "min" in rule and val < rule["min"]:
                    return f"param{idx}_below_min={val}"
                if "max" in rule and val > rule["max"]:
                    return f"param{idx}_above_max={val}"

        # geofence on z (altitude) and x/y (lat/lon values as MAVLink reports)
        z = xyz[2] if len(xyz) > 2 else params.get(7, 0.0)
        if self._geo:
            if "alt_min" in self._geo and z < self._geo["alt_min"]:
                return f"altitude_below_geofence={z}"
            if "alt_max" in self._geo and z > self._geo["alt_max"]:
                return f"altitude_above_geofence={z}"
        return None

    def check_param_set(self, name: str, value: float) -> Optional[str]:
        """Validate PARAM_SET name/range against the allow-list policy."""
        rule = self._param_rules.get(name)
        if rule is None:
            return f"unauthorized_param={name}"
        if "min" in rule and value < rule["min"]:
            return f"param_{name}_below_min={value}"
        if "max" in rule and value > rule["max"]:
            return f"param_{name}_above_max={value}"
        return None

    def check_geofence(self, lat: float, lon: float, alt: float) -> Optional[str]:
        """Independent geofence check for coordinate-bearing messages."""
        if not self._geo:
            return None
        if lat < self._geo.get("lat_min", -90) or lat > self._geo.get("lat_max", 90):
            return f"lat_outside_geofence={lat}"
        if lon < self._geo.get("lon_min", -180) or lon > self._geo.get("lon_max", 180):
            return f"lon_outside_geofence={lon}"
        if alt < self._geo.get("alt_min", -5000) or alt > self._geo.get("alt_max", 50000):
            return f"alt_outside_geofence={alt}"
        return None

    def _canonical_by_id(self, mode_id: int) -> Optional[str]:
        return self._mode_ids.get(mode_id)


# ---------------------------------------------------------------------------
# Phase 2 — COMMAND vs COMMAND_ACK correlation
# ---------------------------------------------------------------------------
class AckTracker:
    """
    Tracks in-flight COMMAND_LONG/COMMAND_INT and correlates COMMAND_ACK.
    Flags: unsolicited ACK, ACK mismatch, missing ACK (timeout).
    Bounded: pending dict pruned on every call (timeout window).
    """

    def __init__(self, timeout_s: float = 3.0) -> None:
        self.timeout_s = timeout_s
        self._pending: Dict[Tuple[int, int, int], float] = {}  # (sysid,compid,cmd)->ts

    def note_command(self, sysid: int, compid: int, command: int, now: float) -> None:
        self._prune(now)
        self._pending[(sysid, compid, command)] = now

    def check_ack(self, sysid: int, compid: int, command: int, now: float,
                  result: int = 0) -> Optional[str]:
        self._prune(now)
        key = (sysid, compid, command)
        if key not in self._pending:
            return f"unsolicited_ack_command={command}"
        self._pending.pop(key, None)
        return None  # acknowledged as expected

    def missing_acks(self, now: float) -> List[str]:
        """Report pending commands whose ACK timed out (no purge of fresh)."""
        return [f"missing_ack_command={c}" for (_, _, c), ts in self._pending.items()
                if now - ts > self.timeout_s]

    def _prune(self, now: float) -> None:
        """Drop entries that have outlived the timeout window."""
        stale = [k for k, ts in self._pending.items() if now - ts > self.timeout_s]
        for k in stale:
            self._pending.pop(k, None)


# ---------------------------------------------------------------------------
# Phase 2 — mission upload integrity
# ---------------------------------------------------------------------------
class MissionTracker:
    """Enforces MISSION_ITEM/MISSION_ITEM_INT sequence integrity + bounds."""

    def __init__(self, policy: Dict[str, Any]) -> None:
        self.max_items = policy.get("mission", {}).get("max_items", 32767)
        self.min_sep = policy.get("mission", {}).get("min_waypoint_sep_m", 0.0)
        self._last_seq: Optional[int] = None
        self._count: int = 0

    def check_item(self, seq: int, is_last: bool = False) -> Optional[str]:
        if seq >= self.max_items:
            return f"mission_seq_above_max={seq}"
        if self._last_seq is not None:
            if seq == self._last_seq:
                return f"mission_seq_duplicate={seq}"
            if seq < self._last_seq:
                return f"mission_seq_backwards={seq}"
            if seq > self._last_seq + 1:
                return f"mission_seq_gap={self._last_seq}->{seq}"
        self._last_seq = seq
        if is_last:
            self._count = seq + 1
            self._last_seq = None
        return None

    def reset(self) -> None:
        self._last_seq = None
        self._count = 0


# ---------------------------------------------------------------------------
# Phase 2 — MAVLink 2.0 signing presence/verification
# ---------------------------------------------------------------------------
class SigningVerifier:
    """
    Flag unsigned frames when signing is EXPECTED, and (optionally) verify
    the 13-byte signature when a secret key is configured.
    Never stores or logs the key. Key rotation tolerated via 48-bit
    timestamp window (MAVLink 2 signing uses 10-microsecond units).
    """

    _SIG_LEN = 13
    _IFLAG_SIGNED = 0x01

    def __init__(self, policy: Dict[str, Any]) -> None:
        sp = policy.get("signing", {})
        self.require = bool(sp.get("require", False))
        self.verify = bool(sp.get("verify_when_present", False))
        self.tolerance_s = float(sp.get("timestamp_tolerance_s", 30.0))
        self._key: Optional[bytes] = None
        self._last_ts = 0.0

    def set_signing_key(self, key: bytes) -> None:
        """Configure the 32-byte shared secret (kept internal, never logged)."""
        if len(key) != 32:
            raise ValueError("MAVLink signing key must be 32 bytes")
        self._key = key

    def check(self, raw_frame: bytes, now: float = 0.0) -> Optional[dict]:
        """
        Inspect a raw MAVLink v2 frame's signing state.

        Returns None if signing policy is satisfied, or an alert dict:
            {"severity","reason","rule_id","timestamp"}
        """
        import time as _t
        now = now or _t.time()
        incompat = raw_frame[2] if len(raw_frame) > 2 else 0
        signed = bool(incompat & self._IFLAG_SIGNED)

        if self.require and not signed:
            return {"severity": "high", "reason": "unsigned_frame_but_signing_required",
                    "rule_id": "SIGN-001", "timestamp": now}
        if not (self.verify and signed and self._key):
            return None

        if len(raw_frame) < self._SIG_LEN:
            return {"severity": "high",
                    "reason": "malformed_signature_too_short",
                    "rule_id": "SIGN-002", "timestamp": now}
        frame = raw_frame[:-self._SIG_LEN]
        sig = raw_frame[-self._SIG_LEN:]
        link_id, ts, mac = sig[0], int.from_bytes(sig[1:7], "little"), sig[7:13]
        del link_id  # link id is informational; not needed for HMAC here

        # timestamp in 10us units -> seconds; must be >= last - tolerance (skew)
        ts_s = ts / 100000.0
        if self._last_ts and ts_s < self._last_ts - self.tolerance_s:
            return {"severity": "high", "reason": "signature_timestamp_out_of_window",
                    "rule_id": "SIGN-003", "timestamp": now}
        self._last_ts = max(self._last_ts, ts_s)

        # HMAC-SHA256(key, frame) truncated to 6 bytes (per MAVLink 2 spec)
        import hashlib, hmac as _hmac
        expect = _hmac.new(self._key, frame, hashlib.sha256).digest()[:6]
        if not _hmac.compare_digest(expect, mac):
            return {"severity": "high", "reason": "invalid_signature",
                    "rule_id": "SIGN-004", "timestamp": now}
        return None

    def clear_key(self) -> None:
        self._key = None


# ---------------------------------------------------------------------------
# Phase 3 — cyber-physical fusion: telemetry state + plausibility checks
# ---------------------------------------------------------------------------
class TelemetryState:
    """
    Bounded store of the LATEST telemetry values (ATTITUDE, GLOBAL_POSITION_INT,
    VFR_HUD, SCALED_PRESSURE, GPS_RAW_INT, SYS_STATUS).

    Bounded: fixed-size feature dict; old features are dropped once older
    than max_age_s (staleness protects against cross-checking against an
    obsolete snapshot — a false-positive source).
    """

    # feature name -> (value, received_at)
    _FEATURES: Tuple[str, ...] = (
        "relative_alt", "groundspeed", "climb", "vx", "vy", "vz",
        "airspeed", "lat", "lon", "baro_alt", "gps_fix", "satellites",
        "roll_rate", "pitch_rate", "yaw_rate",
    )

    def __init__(self, max_age_s: float = 5.0) -> None:
        self.max_age_s = max_age_s
        self._data: Dict[str, tuple] = {}   # feature -> (value, ts)

    def ingest(self, msg_type: str, ts: float, **fields) -> None:
        """Merge one telemetry message's fields into the state (drop stale)."""
        if not fields:
            return
        for k, v in fields.items():
            if k in self._FEATURES and v is not None:
                self._data[k] = (v, ts)

    def get(self, feature: str, default: float = 0.0, now: float = 0.0) -> float:
        """Latest value of a feature, or `default` if missing/stale/unknown."""
        ent = self._data.get(feature)
        if ent is None:
            return default
        val, ts = ent
        if now and now - ts > self.max_age_s:
            return default
        return val

    def fresh(self, feature: str, now: float) -> bool:
        ent = self._data.get(feature)
        return ent is not None and now - ent[1] <= self.max_age_s

    def clear(self) -> None:
        self._data.clear()


class PhysicalCrossChecker:
    """
    Pluggable cyber-physical plausibility checks. Thresholds come from
    policy["physical"]["checks"] so each platform tunes its own bounds;
    a check is skipped if 'enabled' is false or its inputs are stale.

    Returns a reason string, or None when the command is physically plausible.
    """

    def __init__(self, policy: Dict[str, Any]) -> None:
        ph = policy.get("physical", {})
        self.enabled = bool(ph.get("enabled", True))
        self.max_age_s = float(ph.get("max_telemetry_age_s", 5.0))
        self._checks = ph.get("checks", {}) or {}
        self.state = TelemetryState(self.max_age_s)

    # ------------------------------------------------------------------
    def ingest_telemetry(self, msg_type: str, ts: float, msg) -> None:
        """Extract relevant fields from one pymavlink telemetry message."""
        if not self.enabled:
            return
        g = getattr
        if msg_type == "GLOBAL_POSITION_INT":
            self.state.ingest(msg_type, ts,
                              relative_alt=g(msg, "relative_alt", 0),
                              vx=g(msg, "vx", 0.0) / 100.0,
                              vy=g(msg, "vy", 0.0) / 100.0,
                              vz=g(msg, "vz", 0.0) / 100.0,
                              lat=g(msg, "lat", 0.0) / 1e7,
                              lon=g(msg, "lon", 0.0) / 1e7)
        elif msg_type == "VFR_HUD":
            self.state.ingest(msg_type, ts,
                              groundspeed=g(msg, "groundspeed", 0.0),
                              airspeed=g(msg, "airspeed", 0.0),
                              climb=g(msg, "climb", 0.0))
        elif msg_type == "SCALED_PRESSURE":
            # Barometric altitude estimate from pressure (hPa -> m, ISA).
            press = g(msg, "press_abs", 0.0)
            if press and press > 0:
                baro = 44330.0 * (1.0 - (press / 1013.25) ** 0.190284)
                self.state.ingest(msg_type, ts, baro_alt=baro)
        elif msg_type == "GPS_RAW_INT":
            self.state.ingest(msg_type, ts,
                              gps_fix=g(msg, "fix_type", 0),
                              satellites=g(msg, "satellites_visible", 0))
        elif msg_type == "ATTITUDE":
            # rates in rad/s -> deg/s
            self.state.ingest(msg_type, ts,
                              roll_rate=g(msg, "rollspeed", 0.0),
                              pitch_rate=g(msg, "pitchspeed", 0.0),
                              yaw_rate=g(msg, "yawspeed", 0.0))
        # SYS_STATUS is informational; no numeric cross-check features here.

    # ------------------------------------------------------------------
    def check_command(self, command: str, xyz: Tuple[float, float, float],
                      now: float = 0.0) -> Optional[dict]:
        """
        Run every enabled physical check against the telemetry snapshot.

        Args:
            command: canonical command name.
            xyz: (x, y, z) raw coordinates from the command payload.
            now: current wall time (defaults to time.time()).

        Returns:
            Alert dict {severity, reason, rule_id, timestamp} or None.
        """
        import time as _t
        now = now or _t.time()
        if not self.enabled:
            return None

        if command == "COMPONENT_ARM_DISARM" and xyz and len(xyz) > 0:
            pass  # disarm flag handled by param; check alt/climb below
        c = self._checks

        # ---- disarm while airborne ----
        if command == "COMPONENT_ARM_DISARM":
            cfg = c.get("disarm_vs_airborne", {})
            if cfg.get("enabled", True):
                alt = self.state.get("relative_alt", now=now)
                climb = self.state.get("climb", now=now)
                if (self.state.fresh("relative_alt", now)
                        and alt > cfg.get("max_disarm_alt_m", 0.5)) or \
                        (self.state.fresh("climb", now)
                         and climb > cfg.get("max_disarm_climb_ms", 0.5)):
                    return {"severity": "high", "reason": "disarm_while_airborne",
                            "rule_id": "PHY-001", "timestamp": now}

        # ---- takeoff while already flying ----
        if command == "NAV_TAKEOFF":
            cfg = c.get("takeoff_vs_flying", {})
            if cfg.get("enabled", True):
                alt = self.state.get("relative_alt", now=now)
                if self.state.fresh("relative_alt", now) \
                        and alt > cfg.get("min_takeoff_alt_m", 1.0):
                    return {"severity": "high", "reason": "takeoff_while_flying",
                            "rule_id": "PHY-002", "timestamp": now}

        # ---- waypoint teleport (impossible step) ----
        if command == "NAV_WAYPOINT":
            cfg = c.get("waypoint_teleport", {})
            if cfg.get("enabled", True):
                lat, lon = self.state.get("lat", now=now), self.state.get("lon", now=now)
                if self.state.fresh("lat", now) and self.state.fresh("lon", now):
                    wx, wy = float(xyz[0]), float(xyz[1])
                    dist = _approx_meters(lat, lon, wx, wy)
                    if dist > cfg.get("max_step_m", 500.0):
                        return {"severity": "medium",
                                "reason": f"waypoint_teleport_{int(dist)}m",
                                "rule_id": "PHY-003", "timestamp": now}
                alt = self.state.get("relative_alt", now=now)
                wz = float(xyz[2]) if len(xyz) > 2 else 0.0
                if (self.state.fresh("relative_alt", now)
                        and abs(wz - alt) > cfg.get("max_alt_step_m", 50.0)):
                    return {"severity": "medium",
                            "reason": "waypoint_alt_step_too_large",
                            "rule_id": "PHY-004", "timestamp": now}

        # ---- altitude teleport (absolute command vs measured) ----
        if command in ("NAV_LAND", "NAV_TAKEOFF"):
            cfg = c.get("altitude_teleport", {})
            if cfg.get("enabled", True):
                alt = self.state.get("relative_alt", now=now)
                wz = float(xyz[2]) if len(xyz) > 2 else 0.0
                if (self.state.fresh("relative_alt", now)
                        and abs(wz - alt) > cfg.get("max_alt_step_m", 50.0)):
                    return {"severity": "medium",
                            "reason": "altitude_teleport_vs_telemetry",
                            "rule_id": "PHY-005", "timestamp": now}
        return None


def _approx_meters(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in meters (haversine, cheap O(1))."""
    import math
    R = 6371000.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * R * math.asin(min(1.0, math.sqrt(a)))


# ---------------------------------------------------------------------------
# Phase 4 — alert rate limiter + dedupe
# ---------------------------------------------------------------------------
class AlertRateLimiter:
    """
    Token-bucket per-second rate limit + time-window dedupe keyed by
    (rule_id, sysid, command). O(1) per call, bounded memory.
    """

    def __init__(
        self,
        max_per_sec: int = 10,
        dedupe_window_s: float = 30.0,
    ) -> None:
        self.max_per_sec = max_per_sec
        self.dedupe_window_s = dedupe_window_s
        self._per_sec: List[float] = []            # all alert timestamps (1s window)
        self._last_seen: Dict[Tuple[str, int, str], float] = {}  # (rule_id, sysid, cmd) -> ts

    def allow(self, rule_id: str, sysid: int, command: str, now: float) -> bool:
        """Return True if alert should be emitted, False if rate-limited/deduped."""
        # 1) per-second bucket
        self._per_sec = [t for t in self._per_sec if now - t < 1.0]
        if len(self._per_sec) >= self.max_per_sec:
            return False
        # 2) dedupe window
        key = (rule_id, sysid, command)
        last = self._last_seen.get(key, 0.0)
        if now - last < self.dedupe_window_s:
            return False
        # allowed
        self._per_sec.append(now)
        self._last_seen[key] = now
        return True

    def reset(self) -> None:
        self._per_sec.clear()
        self._last_seen.clear()


# ---------------------------------------------------------------------------
# High-level detector facade (what the pipeline calls)
# ---------------------------------------------------------------------------
class CommandInjectionDetector:
    """
    Facade combining the state-machine validator with per-source checks.

    Wraps StateMachineValidator and adds:
      - authorized-GCS-sysid enforcement (rejects commands from anywhere
        other than the configured GCS id, e.g. 255)
      - per-command rate limiting (brute-force / spamming detection)

    Policy sources (load_config validates AND fails loudly on bad config):
        config_path: path to a YAML policy file.
        policy:      pre-validated policy dict (mutually exclusive with path).
        profile:     name of a mission-profile override section to apply.

    Defaults to the module-level policy when neither is supplied, so
    existing callers keep working unchanged.
    """

    def __init__(
        self,
        initial_state: str = "DISARMED",
        authorized_sysid: Optional[int] = None,   # None -> use policy list
        max_commands_per_sec: Optional[int] = None,
        config_path: Optional[str] = None,
        policy: Optional[Dict[str, Any]] = None,
        profile: Optional[str] = None,
    ) -> None:
        if config_path is not None and policy is not None:
            raise ValueError("supply either config_path or policy, not both")

        if policy is not None:
            self._policy = policy
        elif config_path is not None:
            # load_config raises ConfigError loudly on invalid/missing config
            self._policy = load_config(config_path, profile=profile)
        else:
            # Back-compat: module-level default when no config given.
            pol = _module_policy()
            self._policy = pol

        self._fail_mode = get_fail_mode(self._policy)

        # authorized sysids from policy, unless an explicit override given
        pol_ids = set(get_authorized_sysids(self._policy))
        if authorized_sysid is not None:
            pol_ids = {authorized_sysid}
        self._authorized_ids = pol_ids

        # rate limit from policy, unless an explicit override given
        self._max_per_sec = self._policy["rate_limit"]["commands_per_sec"]
        if max_commands_per_sec is not None:
            self._max_per_sec = max_commands_per_sec

        self._validator = StateMachineValidator(initial_state, policy=self._policy)

        # For rate limiting: dict (sysid -> command-window timestamps)
        self._rate_windows: Dict[int, List[float]] = {}

        # Phase 2 wiring
        self._param_validator = ParameterValidator(self._policy)
        compids = self._policy.get("authorized_compids", [190])
        self._authorized_compids: set = set(compids if compids else [190])
        self._ack_tracker = AckTracker(
            self._policy.get("ack", {}).get("timeout_s", 3.0))
        self._mission_tracker = MissionTracker(self._policy)
        self._signing = SigningVerifier(self._policy)
        self._enforce_transitions = bool(self._policy.get("enforce_mode_transitions", False))
        self._mode_transitions = self._policy.get("mode_transitions", {})
        self._last_telemetry_mode: Optional[str] = None
        # Phase 3
        self._physical = PhysicalCrossChecker(self._policy)
        # Phase 4
        al = self._policy.get("alerting", {})
        self._alert_limiter = AlertRateLimiter(
            max_per_sec=al.get("rate_limit_per_sec", 10),
            dedupe_window_s=al.get("dedupe_window_s", 30.0),
        )
        self._include_mitre = al.get("include_mitre", True)

    # ------------------------------------------------------------------
    @property
    def fail_mode(self) -> str:
        """Current fail-safe mode: 'alert_and_pass' (default) or 'alert_and_block'."""
        return self._fail_mode

    @property
    def policy(self) -> Dict[str, Any]:
        """Read-only access to the validated policy in effect."""
        return self._policy

    # ------------------------------------------------------------------
    def update_state_from_telemetry(self, new_state: str) -> None:
        """Pipeline hook — ground-truth state updates only."""
        self._validator.update_state(new_state)

    # ------------------------------------------------------------------
    def process_command(self, msg) -> Optional[dict]:
        """
        Full command-injection analysis of one pymavlink message.

        Order of checks (cheapest first):
          1. Extract (command, sysid)
          2. If not a command message -> skip (fast path)
          3. Sysid authorization
          4. Rate limit
          5. State-machine legality

        Args:
            msg: pymavlink message object (or mock).

        Returns:
            Alert dict, or None if the command is clean.
        """
        command, sysid = parse_mavlink_command(msg)
        if command is None:
            return None   # not a command message — nothing to validate

        # --- 3. Source authorization --------------------------------
        if sysid is None:
            sysid = -1
        if sysid not in self._authorized_ids:
            alert = {
                "severity": "high",
                "reason": "unauthorized_command_source",
                "command": command,
                "state": self._validator.state,
                "timestamp": time.time(),
                "sysid": sysid,
            }
            logger.warning("ALERT %s", alert)
            return self._apply_fail_mode(self.emit_alert(alert))

        # --- 3b. Source component authorization ---------------------
        compid = getattr(msg, "compid", None) or getattr(msg, "get_srcComponent", lambda: None)()
        if compid is not None and compid not in self._authorized_compids:
            alert = {
                "severity": "high",
                "reason": "unauthorized_command_compid",
                "command": command,
                "state": self._validator.state,
                "timestamp": time.time(),
                "compid": compid,
            }
            logger.warning("ALERT %s", alert)
            return self._apply_fail_mode(self.emit_alert(alert))

        # --- 4. Rate limiting ---------------------------------------
        if self._rate_limit_exceeded(sysid):
            alert = {
                "severity": "medium",
                "reason": "command_rate_limit_exceeded",
                "command": command,
                "state": self._validator.state,
                "timestamp": time.time(),
                "sysid": sysid,
            }
            logger.warning("ALERT %s", alert)
            return self._apply_fail_mode(self.emit_alert(alert))

        # --- 4b. Parameter validation (bounds / geofence / enum) ----
        param_issue = self._validate_params(msg, command)
        if param_issue:
            alert = {
                "severity": "medium",
                "reason": f"command_param_out_of_bounds:{param_issue}",
                "command": command,
                "state": self._validator.state,
                "timestamp": time.time(),
                "detail": param_issue,
            }
            logger.warning("ALERT %s", alert)
            return self._apply_fail_mode(self.emit_alert(alert))

        # --- 4b2. Cyber-physical plausibility (needs telemetry) ----
        # For TAKEOFF/LAND, altitude is in param7; for waypoint it's z
        if command in ("NAV_TAKEOFF", "NAV_LAND"):
            altitude = float(getattr(msg, "param7", 0.0) or 0.0)
        else:
            altitude = float(getattr(msg, "z", 0.0) or 0.0)
        xyz = (float(getattr(msg, "x", 0.0) or 0.0),
               float(getattr(msg, "y", 0.0) or 0.0),
               altitude)
        phy = self._physical.check_command(command, xyz)
        if phy is not None:
            alert = {
                "severity": phy.get("severity", "high"),
                "reason": phy["reason"],
                "command": command,
                "state": self._validator.state,
                "timestamp": time.time(),
                "rule_id": phy.get("rule_id"),
            }
            logger.warning("ALERT %s", alert)
            return self._apply_fail_mode(self.emit_alert(alert))

        # --- 4c. ACK-side: note the command as in-flight -------------
        cmd_id = self._policy.get("command_ids", {}).get(command, 0)
        self._ack_tracker.note_command(
            sysid, compid or 0, cmd_id, time.time())

        # --- 5. State-machine legality ------------------------------
        alert = self._validator.check(command)
        return self._apply_fail_mode(alert)

    # ------------------------------------------------------------------
    def _validate_params(self, msg, command: str) -> Optional[str]:
        """Extract param1..7 + x/y/z from msg and run ParameterValidator."""
        params = {}
        for i in range(1, 8):
            if hasattr(msg, f"param{i}"):
                v = getattr(msg, f"param{i}")
                if v is not None:
                    params[i] = float(v)
        xyz = (float(getattr(msg, "x", 0.0) or 0.0),
               float(getattr(msg, "y", 0.0) or 0.0),
               float(getattr(msg, "z", 0.0) or 0.0))
        return self._param_validator.check_command_params(command, params, xyz)

    # ------------------------------------------------------------------
    def check_ack(self, msg) -> Optional[dict]:
        """
        Correlate an incoming COMMAND_ACK with an outstanding command.

        Returns an alert for unsolicited ACKs / mismatched ACKs; None if the
        ACK matches a pending command.
        """
        try:
            cmd = int(getattr(msg, "command", 0) or 0)
            result = int(getattr(msg, "result", 0) or 0)
            sysid = int(getattr(msg, "sysid", 0) or 0)
            compid = int(getattr(msg, "compid", 0) or 0)
        except (TypeError, ValueError):
            return self._apply_fail_mode({
                "severity": "high", "reason": "malformed_ack", "timestamp": time.time()})
        issue = self._ack_tracker.check_ack(sysid, compid, cmd, time.time(), result)
        if issue:
            return self._apply_fail_mode({
                "severity": "medium", "reason": issue,
                "command_id": cmd, "timestamp": time.time()})
        return None

    # ------------------------------------------------------------------
    def check_mission_item(self, msg) -> Optional[dict]:
        """Validate MISSION_ITEM / MISSION_ITEM_INT sequence + geofence."""
        try:
            seq_raw = getattr(msg, "seq", -1)
            seq = int(seq_raw if seq_raw is not None else -1)
            current = int(getattr(msg, "current", 0) or 0)
            x = float(getattr(msg, "x", 0.0) or 0.0)
            y = float(getattr(msg, "y", 0.0) or 0.0)
            z = float(getattr(msg, "z", 0.0) or 0.0)
        except (TypeError, ValueError):
            return self._apply_fail_mode({
                "severity": "high", "reason": "malformed_mission_item",
                "timestamp": time.time()})
        issue = self._mission_tracker.check_item(seq, is_last=(current == 2))
        if issue:
            return self._apply_fail_mode({
                "severity": "medium", "reason": issue,
                "seq": seq, "timestamp": time.time()})
        geo = self._param_validator.check_geofence(x, y, z)
        if geo:
            return self._apply_fail_mode({
                "severity": "medium", "reason": f"mission_geofence:{geo}",
                "seq": seq, "timestamp": time.time()})
        return None

    # ------------------------------------------------------------------
    def check_signing(self, raw_frame: bytes, now: float = 0.0) -> Optional[dict]:
        """Validate MAVLink 2.0 signing presence/signature on a raw frame."""
        return self._signing.check(raw_frame, now)

    def set_signing_key(self, key: bytes) -> None:
        """Configure the shared MAVLink signing secret (never logged)."""
        self._signing.set_signing_key(key)

    def clear_signing_key(self) -> None:
        self._signing.clear_key()

    # ------------------------------------------------------------------
    def update_mode_from_telemetry(self, mode) -> None:
        """
        Update the ArduPilot flight MODE from ground-truth HEARTBEAT (int
        custom_mode or mode-name str) and optionally enforce legal
        mode-to-mode transitions when enabled in policy.
        """
        # int custom_mode -> mode name via the policy's `modes` table
        if isinstance(mode, int):
            mode = self._policy.get("modes", {}).get(mode)
        elif isinstance(mode, str) and mode.isdigit():
            mode = self._policy.get("modes", {}).get(int(mode))
        mode = _canonical_mode(mode)
        if mode is None:
            return
        if self._enforce_transitions and self._last_telemetry_mode is not None:
            allowed = self._mode_transitions.get(self._last_telemetry_mode, [])
            if mode not in allowed and mode != self._last_telemetry_mode:
                logger.warning("ILLEGAL mode transition %s -> %s (telemetry)",
                               self._last_telemetry_mode, mode)
        self._last_telemetry_mode = mode
        phase = _MODE_TO_PHASE.get(mode)
        if phase:
            self._validator.update_state(phase)

    # ------------------------------------------------------------------
    def ingest_telemetry(self, msg) -> None:
        """
        Feed a pymavlink telemetry message into the cyber-physical fusion
        state. Accepts ATTITUDE, GLOBAL_POSITION_INT, VFR_HUD,
        SCALED_PRESSURE, GPS_RAW_INT, SYS_STATUS. Non-telemetry messages
        are ignored (fast path, O(1)).
        """
        try:
            mt = msg.get_type()
        except AttributeError:
            return
        if mt in ("ATTITUDE", "GLOBAL_POSITION_INT", "VFR_HUD",
                  "SCALED_PRESSURE", "GPS_RAW_INT", "SYS_STATUS"):
            self._physical.ingest_telemetry(mt, time.time(), msg)

    # ------------------------------------------------------------------
    def _apply_fail_mode(self, alert: Optional[dict]) -> Optional[dict]:
        """
        Apply the configured fail-safe mode to an alert (or None).

        'alert_and_pass' (default): return the alert unchanged — the caller
            (pipeline) forwards it, flight-critical traffic is NOT dropped.
        'alert_and_block':         return the alert marked with
            {"drop": True} so the pipeline can discard the frame.
        """
        if alert is None:
            return None
        if self._fail_mode == "alert_and_block":
            alert["drop"] = True
        else:
            alert["drop"] = False
        return alert

    # ------------------------------------------------------------------
    def make_alert(
        self,
        severity: str,
        reason: str,
        command: Optional[str] = None,
        sysid: Optional[int] = None,
        compid: Optional[int] = None,
        msg_id: Optional[int] = None,
        detail: Optional[str] = None,
        rule_id: Optional[str] = None,
        evidence: Optional[dict] = None,
        confidence: Optional[float] = None,
    ) -> IDSAlert:
        """Build a structured IDSAlert with MITRE ATT&CK tag attached."""
        return IDSAlert(
            timestamp=time.time(),
            severity=severity,
            reason=reason,
            rule_id=rule_id,
            mitre_attack=_MITRE_MAP.get(reason) if self._include_mitre else None,
            command=command,
            state=self._validator.state,
            sysid=sysid,
            compid=compid,
            msg_id=msg_id,
            detail=detail,
            evidence=evidence,
            confidence=confidence,
        )

    # ------------------------------------------------------------------
    def emit_alert(self, alert_dict: Optional[dict]) -> Optional[dict]:
        """
        Convert an internal alert dict into a structured, rate-limited alert.

        Rate-limits and dedupes by (reason, sysid, command). Returns the
        enriched dict (now including 'mitre_attack' and 'rule_id' when
        applicable), or None if suppressed by the limiter.
        """
        if alert_dict is None:
            return None
        reason = alert_dict.get("reason", "unknown")
        rule = alert_dict.get("rule_id")
        sysid = alert_dict.get("sysid", 0)
        command = alert_dict.get("command", "")
        if not self._alert_limiter.allow(str(rule or reason), int(sysid or 0),
                                         str(command or ""), time.time()):
            logger.debug("Alert suppressed (rate-limited/deduped): %s", reason)
            return None
        structured = self.make_alert(
            severity=alert_dict.get("severity", "medium"),
            reason=reason,
            command=alert_dict.get("command"),
            sysid=alert_dict.get("sysid"),
            compid=alert_dict.get("compid"),
            msg_id=alert_dict.get("msg_id"),
            detail=alert_dict.get("detail"),
            rule_id=alert_dict.get("rule_id"),
            evidence=alert_dict.get("evidence"),
            confidence=alert_dict.get("confidence"),
        )
        out = dict(alert_dict)
        out["mitre_attack"] = structured.mitre_attack
        out["rule_id"] = structured.rule_id
        return out

    # ------------------------------------------------------------------
    def _rate_limit_exceeded(self, sysid: int) -> bool:
        """Track commands per second per sysid; True if over limit.

        Bounded: only remembers timestamps from the last 1s window.
        """
        now = time.time()
        window = self._rate_windows.setdefault(sysid, [])
        # prune entries older than 1 second (window is inherently bounded:
        # at most max_per_sec entries survive, so no unbounded growth)
        while window and now - window[0] > 1.0:
            window.pop(0)
        window.append(now)
        return len(window) > self._max_per_sec

    # ------------------------------------------------------------------
    @property
    def state(self) -> str:
        """Current validated flight state (read-only)."""
        return self._validator.state


# ===========================================================================
# Self-test / demo
# ===========================================================================
if __name__ == "__main__":
    # Guard: Windows default console encoding (cp1252) can't print some
    # non-ASCII glyphs; force UTF-8 so the self-test is portable.
    try:
        import sys as _sys
        _sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    def make_cmd(msg_type: str, sysid: int, cmd: Optional[str] = None) -> MockCommandMessage:
        return MockCommandMessage(msg_type, sysid, cmd)

    # ---------------------------------------------------------------
    # Scenario (a): valid mission sequence — NO false alerts
    # DISARMED -> ARM -> ARMED -> TAKEOFF -> FLYING -> LAND -> LANDING
    # ---------------------------------------------------------------
    print("\n[Scenario A] Valid mission sequence (expect all PASS)")
    det = CommandInjectionDetector(initial_state="DISARMED", authorized_sysid=255)
    steps = [
        (CMD_ARM_DISARM, "ARMED"),      # arm command, telemetry confirms ARMED
        (CMD_TAKEOFF, "TAKING_OFF"),    # takeoff command, telemetry confirms
        (None, "FLYING"),               # no command — telemetry transition
        (CMD_LAND, "LANDING"),          # land command, telemetry confirms
    ]
    ok = True
    for cmd, after_state in steps:
        if cmd is not None:
            alert = det.process_command(make_cmd("COMMAND_LONG", 255, cmd))
            if alert is not None:
                ok = False
                print(f"  FAIL at {cmd}: {alert}")
        # telemetry transition (ground truth)
        det.update_state_from_telemetry(after_state)
    print(f"  Scenario A: {'PASS' if ok else 'FAIL'}  (no false alerts)")

    # ---------------------------------------------------------------
    # Scenario (b): injected invalid command — TAKEOFF while FLYING
    # ---------------------------------------------------------------
    print("\n[Scenario B] Injected NAV_TAKEOFF while FLYING (expect ALERT)")
    det2 = CommandInjectionDetector(initial_state="FLYING", authorized_sysid=255)
    alert = det2.process_command(make_cmd("COMMAND_LONG", 255, CMD_TAKEOFF))
    passed = alert is not None and alert["reason"] == "command_not_allowed_in_state"
    print(f"  Alert: {alert}")
    print(f"  Scenario B: {'PASS' if passed else 'FAIL'}")

    # ---------------------------------------------------------------
    # Scenario (c): unrecognized state — fail SAFELY, not crash
    # ---------------------------------------------------------------
    print("\n[Scenario C] Unknown state edge case (expect safe alert)")
    det3 = CommandInjectionDetector(initial_state="DISARMED")
    det3._validator.state = "INVALID_STATE"
    alert = det3.process_command(make_cmd("COMMAND_LONG", 255, CMD_ARM_DISARM))
    passed = alert is not None and alert["reason"] == "validator_state_unknown"
    print(f"  Alert: {alert}")
    print(f"  Scenario C: {'PASS' if passed else 'FAIL'}")

    # ---------------------------------------------------------------
    # Bonus: unauthorized sysid
    # ---------------------------------------------------------------
    print("\n[Scenario D] Command from sysid=7 (attacker) (expect ALERT)")
    det4 = CommandInjectionDetector(initial_state="DISARMED", authorized_sysid=255)
    alert = det4.process_command(make_cmd("COMMAND_LONG", 7, CMD_ARM_DISARM))
    passed = alert is not None and alert["reason"] == "unauthorized_command_source"
    print(f"  Alert: {alert}")
    print(f"  Scenario D: {'PASS' if passed else 'FAIL'}")

    # ---------------------------------------------------------------
    # Phase 1: load policy from YAML + profile merge
    # ---------------------------------------------------------------
    import os
    _CFG = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "configs", "command_injection.yaml")

    print(f"\n[Scenario E] Load YAML policy (path={_CFG})")
    try:
        det5 = CommandInjectionDetector(
            initial_state="DISARMED", config_path=_CFG)
        ok_e = det5.fail_mode == "alert_and_pass"
        # recon profile lowers rate limit to 10
        det5r = CommandInjectionDetector(
            initial_state="DISARMED", config_path=_CFG, profile="recon")
        ok_e = ok_e and det5r._max_per_sec == 10
        # delivery profile allows NAV_CONTINUE_AND_CHANGE_ALT in FLYING
        det5d = CommandInjectionDetector(
            initial_state="DISARMED", config_path=_CFG, profile="delivery")
        det5d.update_state_from_telemetry("FLYING")
        alert = det5d.process_command(
            make_cmd("COMMAND_LONG", 255, "NAV_CONTINUE_AND_CHANGE_ALT"))
        ok_e = ok_e and alert is None
        print(f"  policy applied, profile recon rate=10, delivery alt-cmd ok")
        print(f"  Scenario E: {'PASS' if ok_e else 'FAIL'}")
    except Exception as exc:
        ok_e = False
        print(f"  Scenario E: FAIL ({exc!r})")

    print("\n[Scenario F] Invalid YAML config must FAIL LOUDLY")
    import tempfile, yaml as _yaml
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
            _yaml.dump({"fail_mode": "bogus_mode", "states": {},
                        "rate_limit": {"commands_per_sec": -5},
                        "authorized_sysids": []}, fh)
            bad_path = fh.name
        try:
            CommandInjectionDetector(config_path=bad_path)
            ok_f = False
        except ConfigError:
            ok_f = True
        finally:
            os.unlink(bad_path)
        print(f"  Scenario F: {'PASS' if ok_f else 'FAIL'} (invalid config rejected)")
    except Exception as exc:
        ok_f = False
        print(f"  Scenario F: FAIL ({exc!r})")

    print("\n" + "=" * 70)
    print("Command Injection Detector self-test complete.")
    print("=" * 70)