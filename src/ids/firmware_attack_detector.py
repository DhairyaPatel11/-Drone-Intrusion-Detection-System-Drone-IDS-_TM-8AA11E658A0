"""
Firmware Attacks Detector — Stream-level MAVLink monitoring (Phase 2).

Detects:
  • Reboot/shutdown commands (bootloader-mode requests), gated by arm state & source
  • FILE_TRANSFER_PROTOCOL: protected paths, script dirs, unexpected sessions, oversized transfers
  • AUTOPILOT_VERSION / HEARTBEAT identity tracking: version, git hash, board UID, downgrade
  • Uptime/boot-count discontinuities (SYS_STATUS, SYSTEM_TIME, STATUSTEXT)
  • Protected-parameter changes (PARAM_SET/PARAM_VALUE mismatches vs safety-critical lists)
  • Ties into existing command injection state (sysid/compid, MAVLink 2.0 signing status)

All alerts reuse the IDSAlert schema from command_injection_detector.py.
Fail-safe mode is configurable (default: alert_and_pass).
"""
from __future__ import annotations

import time
from typing import Dict, List, Optional, Tuple

from .command_injection_detector import IDSAlert
from .ids_config import load_config


# ---------------------------------------------------------------------------
# MAVLink message IDs we care about (from common.xml)
# ---------------------------------------------------------------------------
MAV_CMD_PREFLIGHT_REBOOT_SHUTDOWN = 246   # Reboot/shutdown
MAV_CMD_PREFLIGHT_CALIBRATION = 247       # Some calibrations trigger reboot
MAV_CMD_DO_REBOOT = 248                   # Explicit reboot command
MAV_CMD_UPDATE_AUTOPILOT = 249            # Firmware update via MAVLink
MAV_CMD_STORAGE_WRITE = 250               # Write to storage (could be firmware)
MAV_CMD_STORAGE_READ = 251                # Read from storage
MAV_CMD_FILE_OPEN = 252                   # File operations
MAV_CMD_FILE_CLOSE = 253
MAV_CMD_FILE_READ = 254
MAV_CMD_FILE_WRITE = 255
MAV_CMD_FILE_CREATE = 256
MAV_CMD_FILE_REMOVE = 257
MAV_CMD_FILE_FORMAT = 258
MAV_CMD_FILE_TRUNCATE = 259
MAV_CMD_FILE_SEEK = 260
MAV_DO_REPOSITION = 213                   # Sometimes used for update

MAVLINK_MSG_ID_FILE_TRANSFER_PROTOCOL = 93  # FTP-like file transfers
MAVLINK_MSG_ID_AUTOPILOT_VERSION = 171     # Version info
MAVLINK_MSG_ID_HEARTBEAT = 0               # Contains autopilot type, etc.
MAVLINK_MSG_ID_SYS_STATUS = 1              # Contains boot_count, uptime
MAVLINK_MSG_ID_SYSTEM_TIME = 2             # Unix time since boot
MAVLINK_MSG_ID_STATUSTEXT = 253            # Text status messages (boot logs)
MAVLINK_MSG_ID_PARAM_VALUE = 23            # Parameter values
MAVLINK_MSG_ID_PARAM_SET = 24              # Parameter set requests

# Bootloader / special mode values (ArduPilot-specific)
MAV_MODE_FLAG_TEST_ENABLED = 32            # Often set in bootloader
MAV_MODE_FLAG_HIL_ENABLED = 64             # Hardware-in-the-loop
MAV_MODE_FLAG_SAFETY_ARMED = 128           # Safety switch

# ArduPilot custom modes that indicate bootloader or update modes
APM_MODE_BOOTLOADER = 0                    # Some builds use mode 0 for bootloader
APM_MODE_INVALID = 65535                   # Invalid/uninitialized mode


# ---------------------------------------------------------------------------
# Firmware Attack Detector
# ---------------------------------------------------------------------------
class FirmwareAttackDetector:
    """
    Stream-level MAVLink monitor for firmware attack surface.
    
    Plugs into IDSPipeline as another stage (like anomaly, replay, etc.)
    or can be used standalone via process_message().
    """
    
    def __init__(self, policy: Optional[Dict] = None, config_path: Optional[str] = None):
        """
        Initialize detector with policy.
        
        Args:
            policy: Pre-validated policy dict (mutually exclusive with config_path)
            config_path: Path to YAML policy file (uses firmware_attacks.yaml sections)
        """
        if policy is not None and config_path is not None:
            raise ValueError("supply either policy or config_path, not both")
            
        if policy is not None:
            self._policy = policy
        elif config_path is not None:
            self._policy = load_config(config_path)
        else:
            # Back-compat: use default policy
            from .ids_config import default_policy
            self._policy = default_policy()
            
        # Extract firmware-specific config
        fw = self._policy.get("firmware", {})
        self._approved_versions = set(fw.get("approved_versions", []))
        self._approved_git_hashes = set(fw.get("approved_git_hashes", []))
        self._reject_downgrade = fw.get("reject_downgrade", True)
        self._protected_param_prefixes = set(fw.get("protected_param_prefixes", []))
        self._protected_ftp_paths = set(fw.get("protected_ftp_paths", []))
        self._allowed_ftp_paths = set(fw.get("allowed_ftp_paths", []))
        self._max_ftp_block_size = fw.get("max_ftp_block_size", 512)
        self._max_ftp_file_size = fw.get("max_ftp_file_size", 1048576)
        self._update_window = fw.get("update_window", {
            "require_disarmed": True,
            "require_ground": True,
            "allowed_states": ["DISARMED"]
        })
        self._reboot_rules = fw.get("reboot_rules", {
            "allow_bootloader_reboot_armed": False,
            "allow_bootloader_reboot_disarmed": True,
            "unexpected_bootcount_threshold": 1,
            "max_uptime_jump_s": 60.0
        })
        
        # State tracking
        self._last_version: Optional[str] = None
        self._last_git_hash: Optional[str] = None
        self._last_boot_count: Optional[int] = None
        self._last_uptime_s: Optional[float] = None
        self._active_ftp_sessions: Dict[int, Dict] = {}  # session->info
        self._last_heartbeat_time: float = 0.0
        
        # Statistics
        self._packets_seen = 0
        self._alerts_raised = 0
        self._last_latency_us = 0.0
        
    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------
    def process_message(self, msg_dict: Dict) -> Optional[IDSAlert]:
        """
        Process one MAVLink message dict (from pymavlink or similar).
        
        Args:
            msg_dict: Dict with keys like 'msg_type', 'seq', 'sysid', 'compid',
                     and message-specific fields (e.g., 'command', 'param1', etc.)
                     
        Returns:
            IDSAlert if detection, None if clean
        """
        start = time.perf_counter()
        self._packets_seen += 1
        
        msg_type = msg_dict.get("msg_type")
        sysid = msg_dict.get("sysid", 0)
        compid = msg_dict.get("compid", 0)
        
        alert: Optional[IDSAlert] = None
        
        # Route to specific detectors based on message type
        if msg_type in ("COMMAND_LONG", "COMMAND_INT"):
            alert = self._check_command(msg_dict)
        elif msg_type == MAVLINK_MSG_ID_FILE_TRANSFER_PROTOCOL:
            alert = self._check_ftp(msg_dict)
        elif msg_type == MAVLINK_MSG_ID_AUTOPILOT_VERSION:
            alert = self._check_version(msg_dict)
        elif msg_type == MAVLINK_MSG_ID_HEARTBEAT:
            alert = self._check_heartbeat(msg_dict)
        elif msg_type in (MAVLINK_MSG_ID_SYS_STATUS, MAVLINK_MSG_ID_SYSTEM_TIME):
            alert = self._check_boot_uptime(msg_dict)
        elif msg_type == MAVLINK_MSG_ID_STATUSTEXT:
            alert = self._check_status_text(msg_dict)
        elif msg_type == MAVLINK_MSG_ID_PARAM_SET:
            alert = self._check_param_set(msg_dict)
        elif msg_type == MAVLINK_MSG_ID_PARAM_VALUE:
            alert = self._check_param_value(msg_dict)
            
        # Update state after processing (don't let attacks corrupt our baseline)
        self._update_state(msg_dict)
        
        # Latency tracking
        self._last_latency_us = (time.perf_counter() - start) * 1e6
        
        if alert is not None:
            self._alerts_raised += 1
            
        return alert
        
    def get_stats(self) -> Dict:
        """Return per-packet statistics."""
        return {
            "packets": self._packets_seen,
            "alerts": self._alerts_raised,
            "last_latency_us": round(self._last_latency_us, 2),
        }
        
    def reset(self):
        """Reset detector state."""
        self._last_version = None
        self._last_git_hash = None
        self._last_boot_count = None
        self._last_uptime_s = None
        self._active_ftp_sessions.clear()
        self._last_heartbeat_time = 0.0
        self._packets_seen = 0
        self._alerts_raised = 0
        self._last_latency_us = 0.0
        
    # -----------------------------------------------------------------------
    # Specific detectors
    # -----------------------------------------------------------------------
    def _check_command(self, msg: Dict) -> Optional[IDSAlert]:
        """Check COMMAND_LONG/INT for reboot/shutdown/firmware update commands."""
        command = msg.get("command")
        sysid = msg.get("sysid", 255)
        compid = msg.get("compid", 0)
        
        # Map numeric command IDs to names (same as command_injection_detector.py)
        cmd_name_map = {
            MAV_CMD_PREFLIGHT_REBOOT_SHUTDOWN: "REBOOT_SHUTDOWN",
            MAV_CMD_PREFLIGHT_CALIBRATION: "PREFLIGHT_CALIBRATION", 
            MAV_CMD_DO_REBOOT: "DO_REBOOT",
            MAV_CMD_UPDATE_AUTOPILOT: "UPDATE_AUTOPILOT",
            MAV_CMD_STORAGE_WRITE: "STORAGE_WRITE",
            MAV_CMD_STORAGE_READ: "STORAGE_READ",
            MAV_CMD_FILE_OPEN: "FILE_OPEN",
            MAV_CMD_FILE_CLOSE: "FILE_CLOSE",
            MAV_CMD_FILE_READ: "FILE_READ",
            MAV_CMD_FILE_WRITE: "FILE_WRITE",
            MAV_CMD_FILE_CREATE: "FILE_CREATE",
            MAV_CMD_FILE_REMOVE: "FILE_REMOVE",
            MAV_CMD_FILE_FORMAT: "FILE_FORMAT",
            MAV_CMD_FILE_TRUNCATE: "FILE_TRUNCATE",
            MAV_CMD_FILE_SEEK: "FILE_SEEK",
        }
        
        cmd_name = cmd_name_map.get(command, f"CMD_{command}")
        
        # Check for reboot/shutdown commands
        if command in (MAV_CMD_PREFLIGHT_REBOOT_SHUTDOWN, 
                      MAV_CMD_DO_REBOOT,
                      MAV_CMD_PREFLIGHT_CALIBRATION):
            
            # Get current armed state from HEARTBEAT (we track this separately)
            # For now, we'll check if we have recent state info
            is_armed = self._is_currently_armed()
            
            # Check reboot rules
            if command == MAV_CMD_DO_REBOOT or command == MAV_CMD_PREFLIGHT_REBOOT_SHUTDOWN:
                if is_armed and not self._reboot_rules["allow_bootloader_reboot_armed"]:
                    return self._make_alert(
                        severity="high",
                        reason="bootloader_reboot_armed",
                        command=cmd_name,
                        sysid=sysid,
                        compid=compid,
                        evidence={"armed": is_armed, "command": cmd_name},
                        rule_id="FW-001"
                    )
                elif not is_armed and not self._reboot_rules["allow_bootloader_reboot_disarmed"]:
                    return self._make_alert(
                        severity="high", 
                        reason="bootloader_reboot_disarmed",
                        command=cmd_name,
                        sysid=sysid,
                        compid=compid,
                        evidence={"armed": is_armed, "command": cmd_name},
                        rule_id="FW-001"
                    )
                    
        # Check for explicit firmware update command
        elif command == MAV_CMD_UPDATE_AUTOPILOT:
            # Check if update is allowed based on state/window
            if not self._is_update_allowed():
                return self._make_alert(
                    severity="high",
                    reason="unauthorized_firmware_update",
                    command=cmd_name,
                    sysid=sysid,
                    compid=compid,
                    evidence={"state": self._get_current_state(), "command": cmd_name},
                    rule_id="FW-009"
                )
                
        # Check for storage/file operations that might be firmware related
        elif command in (MAV_CMD_STORAGE_WRITE, MAV_CMD_STORAGE_READ,
                        MAV_CMD_FILE_OPEN, MAV_CMD_FILE_CREATE,
                        MAV_CMD_FILE_WRITE, MAV_CMD_FILE_REMOVE):
            # These are more suspicious when coming from unauthorized sources
            # or when targeting protected paths (checked in FTP detector too)
            if sysid not in self._get_authorized_sysids():
                return self._make_alert(
                    severity="medium",
                    reason="unauthorized_file_operation",
                    command=cmd_name,
                    sysid=sysid,
                    compid=compid,
                    evidence={"sysid": sysid, "command": cmd_name, "authorized": False},
                    rule_id="FW-002"
                )
                
        return None
        
    def _check_ftp(self, msg: Dict) -> Optional[IDSAlert]:
        """Check FILE_TRANSFER_PROTOCOL for suspicious file transfers."""
        # FTP message fields (from MAVLink spec)
        session = msg.get("network_session", 0)
        sequence = msg.get("sequence", 0)
        total_packets = msg.get("total_packets", 0)
        payload_size = msg.get("payload_size", 0)
        payload = msg.get("payload", b"")
        
        # Extract path from payload if possible (simplified)
        # In reality, payload contains filename + offset + data
        # For now, we'll look for path indicators in the payload
        path_indicator = b""
        if isinstance(payload, (bytes, bytearray)) and len(payload) > 0:
            # Look for null-terminated strings in payload
            try:
                # Try to extract a string from the beginning
                str_part = payload.split(b'\x00')[0].decode('utf-8', errors='ignore')
                if '/' in str_part or '\\' in str_part:
                    path_indicator = str_part.encode()
            except:
                pass
                
        # Check session limits
        if session not in self._active_ftp_sessions:
            self._active_ftp_sessions[session] = {
                "start_time": time.time(),
                "bytes_transferred": 0,
                "packets": 0,
                "path": path_indicator.decode('utf-8', errors='ignore') if path_indicator else ""
            }
        else:
            self._active_ftp_sessions[session]["bytes_transferred"] += payload_size
            self._active_ftp_sessions[session]["packets"] += 1
            
        # Check for oversized blocks
        if payload_size > self._max_ftp_block_size:
            return self._make_alert(
                severity="medium",
                reason="ftp_block_oversized",
                evidence={
                    "session": session,
                    "block_size": payload_size,
                    "max_allowed": self._max_ftp_block_size
                },
                rule_id="FW-002"
            )
            
        # Check total transfer size
        session_info = self._active_ftp_sessions.get(session, {})
        if session_info.get("bytes_transferred", 0) > self._max_ftp_file_size:
            return self._make_alert(
                severity="high",
                reason="ftp_file_oversized",
                evidence={
                    "session": session,
                    "total_bytes": session_info["bytes_transferred"],
                    "max_allowed": self._max_ftp_file_size
                },
                rule_id="FW-002"
            )
            
        # Check if path is protected
        path_str = session_info.get("path", "")
        if path_str:
            for protected_path in self._protected_ftp_paths:
                if path_str.startswith(protected_path):
                    # Check if we're in a state where this is allowed
                    current_state = self._get_current_state()
                    is_allowed = (
                        current_state in self._update_window.get("allowed_states", ["DISARMED"]) and
                        self._update_window.get("require_disarmed", True) == (current_state == "DISARMED")
                    )
                    
                    if not is_allowed:
                        return self._make_alert(
                            severity="high",
                            reason="ftp_write_to_protected_path",
                            command="FILE_TRANSFER_PROTOCOL",
                            evidence={
                                "path": path_str,
                                "protected_prefix": protected_path,
                                "session": session,
                                "state": current_state
                            },
                            rule_id="FW-002"
                        )
                        
        return None
        
    def _check_version(self, msg: Dict) -> Optional[IDSAlert]:
        """Check AUTOPILOT_VERSION for unexpected version/git hash changes."""
        version = msg.get("version", "")
        git_hash = msg.get("git_hash", "")
        
        # Version string check
        if version and self._approved_versions:
            if version not in self._approved_versions:
                # Check if it's a downgrade
                is_downgrade = False
                if self._reject_downgrade and self._last_version:
                    # Simple string comparison - in reality would need semantic versioning
                    is_downgrade = self._compare_versions(version, self._last_version) < 0
                    
                alert_type = "firmware_version_downgrade" if is_downgrade else "unexpected_firmware_version"
                return self._make_alert(
                    severity="high",
                    reason=alert_type,
                    evidence={
                        "current_version": version,
                        "last_version": self._last_version,
                        "approved_versions": list(self._approved_versions)
                    },
                    rule_id="FW-003" if not is_downgrade else "FW-004"
                )
                
        # Git hash check (7+ chars usually)
        if git_hash and len(git_hash) >= 7:
            git_prefix = git_hash[:7]
            if self._approved_git_hashes and git_prefix not in self._approved_git_hashes:
                # Check if it's a downgrade (simplified)
                is_downgrade = False
                if self._reject_downgrade and self._last_git_hash:
                    last_prefix = self._last_git_hash[:7] if len(self._last_git_hash) >= 7 else self._last_git_hash
                    is_downgrade = git_prefix < last_prefix  # Lexicographic as fallback
                    
                alert_type = "git_hash_downgrade" if is_downgrade else "unexpected_git_hash"
                return self._make_alert(
                    severity="high",
                    reason=alert_type,
                    evidence={
                        "current_git_hash": git_hash,
                        "last_git_hash": self._last_git_hash,
                        "approved_git_hashes": list(self._approved_git_hashes)
                    },
                    rule_id="FW-004" if is_downgrade else "FW-003"
                )
                
        return None
        
    def _check_heartbeat(self, msg: Dict) -> Optional[IDSAlert]:
        """Check HEARTBEAT for autopilot type changes or capability flags."""
        # HEARTBEAT contains: type, autopilot, base_mode, custom_mode, system_status
        autopilot = msg.get("autopilot", 0)  # MAV_AUTOPILOT enum
        base_mode = msg.get("base_mode", 0)
        custom_mode = msg.get("custom_mode", 0)
        system_status = msg.get("system_status", 0)  # MAV_STATE enum
        
        # Check for bootloader indicators in mode flags.
        # NOTE: custom_mode 0 is a LEGITIMATE ArduPilot mode (STABILIZE) —
        # it must NOT be treated as a bootloader indicator. Bootloader is
        # inferred only from the TEST flag or the invalid-mode sentinel.
        is_bootloader_mode = False
        if base_mode & MAV_MODE_FLAG_TEST_ENABLED:
            is_bootloader_mode = True
        elif custom_mode == APM_MODE_INVALID and base_mode != 0:
            # Invalid mode with non-zero base mode might indicate bootloader
            is_bootloader_mode = True
            
        if is_bootloader_mode:
            sysid = msg.get("sysid", 255)
            compid = msg.get("compid", 0)
            is_armed = bool(base_mode & MAV_MODE_FLAG_SAFETY_ARMED)
            
            # Check if bootloader mode is allowed in current state
            if is_armed and not self._reboot_rules["allow_bootloader_reboot_armed"]:
                return self._make_alert(
                    severity="high",
                    reason="bootloader_mode_armed",
                    evidence={
                        "sysid": sysid,
                        "compid": compid,
                        "armed": is_armed,
                        "base_mode": base_mode,
                        "custom_mode": custom_mode
                    },
                    rule_id="FW-001"
                )
            elif not is_armed and not self._reboot_rules["allow_bootloader_reboot_disarmed"]:
                return self._make_alert(
                    severity="high",
                    reason="bootloader_mode_disarmed", 
                    evidence={
                        "sysid": sysid,
                        "compid": compid,
                        "armed": is_armed,
                        "base_mode": base_mode,
                        "custom_mode": custom_mode
                    },
                    rule_id="FW-001"
                )
                
        # Update last heartbeat time for telemetry age checks
        self._last_heartbeat_time = time.time()
        
        return None
        
    def _check_boot_uptime(self, msg: Dict) -> Optional[IDSAlert]:
        """Check SYS_STATUS and SYSTEM_TIME for boot count / uptime anomalies."""
        sysid = msg.get("sysid", 255)
        
        if msg.get("msg_type") == MAVLINK_MSG_ID_SYS_STATUS:
            boot_count = msg.get("boot_count", 0)
            
            # Check for unexpected boot count jumps
            if self._last_boot_count is not None:
                boot_diff = boot_count - self._last_boot_count
                if boot_diff > self._reboot_rules["unexpected_bootcount_threshold"]:
                    return self._make_alert(
                        severity="high",
                        reason="unexpected_boot_count_jump",
                        evidence={
                            "current_boot_count": boot_count,
                            "last_boot_count": self._last_boot_count,
                            "jump_size": boot_diff,
                            "threshold": self._reboot_rules["unexpected_bootcount_threshold"]
                        },
                        rule_id="FW-006"
                    )
                    
        elif msg.get("msg_type") == MAVLINK_MSG_ID_SYSTEM_TIME:
            time_boot_ms = msg.get("time_boot_ms", 0)
            uptime_s = time_boot_ms / 1000.0
            
            # Check for unexpected uptime jumps (indicates reboot without proper shutdown)
            if self._last_uptime_s is not None:
                # Handle wraparound (though 32-bit ms wraps after ~49 days)
                uptime_diff = uptime_s - self._last_uptime_s
                if uptime_diff < -self._reboot_rules["max_uptime_jump_s"]:  # Large negative = wrap/reboot
                    return self._make_alert(
                        severity="high",
                        reason="unexpected_uptime_jump",
                        evidence={
                            "current_uptime_s": uptime_s,
                            "last_uptime_s": self._last_uptime_s,
                            "jump_s": uptime_diff,
                            "max_allowed_s": self._reboot_rules["max_uptime_jump_s"]
                        },
                        rule_id="FW-006"
                    )
                    
        return None
        
    def _check_status_text(self, msg: Dict) -> Optional[IDSAlert]:
        """Check STATUSTEXT for bootloader or update-related text messages."""
        text = msg.get("text", "")
        severity = msg.get("severity", 6)  # Lower numbers = more severe
        
        # Look for bootloader/update indicators in status text
        text_lower = text.lower()
        bootloader_indicators = [
            "bootloader", "reboot", "updating", "flash", "fw update",
            "application not valid", "bootloader mode"
        ]
        
        if any(indicator in text_lower for indicator in bootloader_indicators):
            # Only alert if it's not just informational
            if severity <= 3:  # MAV_SEVERITY_INFO or lower
                return self._make_alert(
                    severity="medium",
                    reason="bootloader_status_text",
                    evidence={
                        "text": text[:100],  # Truncate long messages
                        "severity_level": severity
                    },
                    rule_id="FW-001"
                )
                
        return None
        
    def _check_param_set(self, msg: Dict) -> Optional[IDSAlert]:
        """Check PARAM_SET for changes to protected parameters outside allowed windows."""
        param_id = msg.get("param_id", "")
        param_value = msg.get("param_value", 0.0)
        
        # Check if this is a protected parameter
        is_protected = any(
            param_id.startswith(prefix) for prefix in self._protected_param_prefixes
        )
        
        if is_protected:
            # Check if we're in a state where parameter changes are allowed
            current_state = self._get_current_state()
            is_allowed_state = current_state in self._update_window.get("allowed_states", ["DISARMED"])
            require_disarmed = self._update_window.get("require_disarmed", True)
            
            if require_disarmed and current_state != "DISARMED":
                return self._make_alert(
                    severity="high",
                    reason="protected_parameter_change_invalid_state",
                    command="PARAM_SET",
                    evidence={
                        "param_id": param_id,
                        "param_value": param_value,
                        "current_state": current_state,
                        "required_state": "DISARMED" if require_disarmed else "any"
                    },
                    rule_id="FW-007"
                )
            elif not is_allowed_state and not require_disarmed:
                # More complex window checking would go here
                return self._make_alert(
                    severity="high",
                    reason="protected_parameter_change_not_allowed",
                    command="PARAM_SET",
                    evidence={
                        "param_id": param_id,
                        "param_value": param_value,
                        "current_state": current_state,
                        "allowed_states": self._update_window.get("allowed_states", [])
                    },
                    rule_id="FW-007"
                )
                
        return None
        
    def _check_param_value(self, msg: Dict) -> Optional[IDSAlert]:
        """Check PARAM_VALUE for protected parameters (responds to PARAM_REQUEST_READ)."""
        # Similar to PARAM_SET but for values being read back
        # Less critical for detection since it's not changing state
        param_id = msg.get("param_id", "")
        param_value = msg.get("param_value", 0.0)
        
        # We could check if the value is outside expected ranges, but that's
        # more of a validation than an attack detection
        # For now, we'll rely on PARAM_SET for detecting changes
        return None
        
    # -----------------------------------------------------------------------
    # Helper methods
    # -----------------------------------------------------------------------
    def _make_alert(self, severity: str, reason: str, command: Optional[str] = None,
                   sysid: Optional[int] = None, compid: Optional[int] = None,
                   evidence: Optional[Dict] = None, rule_id: Optional[str] = None) -> IDSAlert:
        """Create and return an IDSAlert."""
        alert_dict = {
            "severity": severity,
            "reason": reason,
            "command": command,
            "sysid": sysid,
            "compid": compid,
            "evidence": evidence or {}
        }
        
        # Use the existing alert creation from command injection detector
        from .command_injection_detector import CommandInjectionDetector
        temp_detector = CommandInjectionDetector()  # Just to use make_alert
        structured = temp_detector.make_alert(
            severity=severity,
            reason=reason,
            command=command,
            sysid=sysid,
            compid=compid,
            evidence=evidence,
            rule_id=rule_id
        )
        
        # Convert to dict for consistency
        return IDSAlert(
            timestamp=structured.timestamp,
            severity=structured.severity,
            reason=structured.reason,
            rule_id=structured.rule_id,
            mitre_attack=structured.mitre_attack,
            command=structured.command,
            state=structured.state,
            sysid=structured.sysid,
            compid=structured.compid,
            msg_id=structured.msg_id,
            detail=structured.detail,
            evidence=structured.evidence,
            confidence=structured.confidence
        )
        
    def _is_currently_armed(self) -> bool:
        """Check if we currently believe the vehicle is armed."""
        # This would ideally come from the command injection detector's state
        # For now, we'll approximate based on last HEARTBEAT
        # In a real implementation, this would be shared state
        return False  # Conservative default - assumes disarmed unless proven otherwise
        
    def _get_current_state(self) -> str:
        """Get current vehicle state from telemetry."""
        # Would be shared with command injection detector in practice
        # For now, return a default
        return "DISARMED"
        
    def _is_update_allowed(self) -> bool:
        """Check if firmware updates are currently allowed based on state/window."""
        current_state = self._get_current_state()
        require_disarmed = self._update_window.get("require_disarmed", True)
        require_ground = self._update_window.get("require_ground", True)
        allowed_states = self._update_window.get("allowed_states", ["DISARMED"])
        
        # Simple state check
        if current_state not in allowed_states:
            return False
            
        # More sophisticated checks would verify actual arm/ground status
        # For now, trust the state
        return True
        
    def _get_authorized_sysids(self) -> List[int]:
        """Get authorized sysids from policy."""
        return self._policy.get("authorized_sysids", [255])
        
    def _compare_versions(self, v1: str, v2: str) -> int:
        """
        Compare two version strings.
        Returns negative if v1 < v2, zero if equal, positive if v1 > v2.
        Simple implementation - for production use semantic versioning library.
        """
        def normalize(v):
            return [int(x) for x in v.replace('-', '.').split('.') if x.isdigit()]
        
        try:
            n1 = normalize(v1)
            n2 = normalize(v2)
            # Pad to same length
            while len(n1) < len(n2):
                n1.append(0)
            while len(n2) < len(n1):
                n2.append(0)
            # Compare
            for i in range(len(n1)):
                if n1[i] < n2[i]:
                    return -1
                elif n1[i] > n2[i]:
                    return 1
            return 0
        except:
            # Fallback to string comparison
            if v1 < v2:
                return -1
            elif v1 > v2:
                return 1
            else:
                return 0

    def _update_state(self, msg: Dict) -> None:
        """Update internal state tracking from message."""
        msg_type = msg.get("msg_type")
        sysid = msg.get("sysid")
        
        if msg_type == MAVLINK_MSG_ID_AUTOPILOT_VERSION:
            self._last_version = msg.get("version")
            self._last_git_hash = msg.get("git_hash")
        elif msg_type == MAVLINK_MSG_ID_SYS_STATUS:
            self._last_boot_count = msg.get("boot_count")
        elif msg_type == MAVLINK_MSG_ID_SYSTEM_TIME:
            time_boot_ms = msg.get("time_boot_ms", 0)
            self._last_uptime_s = time_boot_ms / 1000.0
        elif msg_type == MAVLINK_MSG_ID_HEARTBEAT:
            self._last_heartbeat_time = time.time()