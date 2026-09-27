"""
Tests for FirmwareAttackDetector (Phase 2 stream-level detectors).

Each detection rule has positive (attack detected) and negative (benign traffic) tests.
"""
import os
import sys
import time


import pytest
from ids.firmware_attack_detector import FirmwareAttackDetector


# ---------------------------------------------------------------------------
# Helper to build MAVLink-like message dicts
# ---------------------------------------------------------------------------
def make_command_msg(command_id: int, sysid: int = 255, compid: int = 1,
                    param1: float = 0.0, param2: float = 0.0, param3: float = 0.0,
                    param4: float = 0.0, param5: float = 0.0, param6: float = 0.0,
                    param7: float = 0.0) -> dict:
    """Build a COMMAND_LONG message dict."""
    return {
        "msg_type": "COMMAND_LONG",
        "seq": 0,
        "sysid": sysid,
        "compid": compid,
        "command": command_id,
        "param1": param1,
        "param2": param2,
        "param3": param3,
        "param4": param4,
        "param5": param5,
        "param6": param6,
        "param7": param7
    }


def make_ftp_msg(session: int = 0, sequence: int = 0, total_packets: int = 1,
                payload_size: int = 100, payload: bytes = b"test",
                sysid: int = 255, compid: int = 1) -> dict:
    """Build a FILE_TRANSFER_PROTOCOL message dict."""
    return {
        "msg_type": 93,  # MAVLINK_MSG_ID_FILE_TRANSFER_PROTOCOL
        "seq": 0,
        "sysid": sysid,
        "compid": compid,
        "network_session": session,
        "sequence": sequence,
        "total_packets": total_packets,
        "payload_size": payload_size,
        "payload": payload
    }


def make_version_msg(version: str = "Copter-4.5.0", git_hash: str = "a1b2c3d4e5f",
                    sysid: int = 255, compid: int = 1) -> dict:
    """Build an AUTOPILOT_VERSION message dict."""
    return {
        "msg_type": 171,  # MAVLINK_MSG_ID_AUTOPILOT_VERSION
        "seq": 0,
        "sysid": sysid,
        "compid": compid,
        "version": version,
        "git_hash": git_hash,
        "flight_custom_version": 0,
        "flight_sha_version": 0,
        "os_custom_version": 0,
        "os_sha_version": 0,
        "board_version": 0,
        "board_sha": 0,
        "capabilities": 0
    }


def make_heartbeat_msg(custom_mode: int = 0, base_mode: int = 0,
                      sysid: int = 255, compid: int = 1,
                      type: int = 2, autopilot: int = 3,
                      system_status: int = 0) -> dict:
    """Build a HEARTBEAT message dict."""
    return {
        "msg_type": 0,  # MAVLINK_MSG_ID_HEARTBEAT
        "seq": 0,
        "sysid": sysid,
        "compid": compid,
        "type": type,
        "autopilot": autopilot,
        "base_mode": base_mode,
        "custom_mode": custom_mode,
        "system_status": system_status,
        "mavlink_version": 3
    }


def make_sys_status_msg(boot_count: int = 0, sysid: int = 255, compid: int = 1) -> dict:
    """Build a SYS_STATUS message dict."""
    return {
        "msg_type": 1,  # MAVLINK_MSG_ID_SYS_STATUS
        "seq": 0,
        "sysid": sysid,
        "compid": compid,
        "onboard_control_sensors_present": 0,
        "onboard_control_sensors_enabled": 0,
        "onboard_control_sensors_health": 0,
        "load": 0,
        "voltage_battery": 0,
        "current_battery": 0,
        "board_temperature": 0,
        "airspeed": 0,
        "airspeed2": 0,
        "altitude": 0,
        "vertical_speed": 0,
        "inds_temperature": 0,
        "power_status": 0,
        "error_count": 0,
        "count": 0,
        "drop_rate_comm": 0,
        "errors_comm": 0,
        "errors_count1": 0,
        "errors_count2": 0,
        "errors_count3": 0,
        "errors_count4": 0,
        "boot_count": boot_count,
        "ground_speed": 0
    }


def make_system_time_msg(time_boot_ms: int = 0, sysid: int = 255, compid: int = 1) -> dict:
    """Build a SYSTEM_TIME message dict."""
    return {
        "msg_type": 2,  # MAVLINK_MSG_ID_SYSTEM_TIME
        "seq": 0,
        "sysid": sysid,
        "compid": compid,
        "time_unix_usec": 0,
        "time_boot_ms": time_boot_ms
    }


def make_statustext_msg(severity: int = 6, text: str = "Test message",
                       sysid: int = 255, compid: int = 1) -> dict:
    """Build a STATUSTEXT message dict."""
    return {
        "msg_type": 253,  # MAVLINK_MSG_ID_STATUSTEXT
        "seq": 0,
        "sysid": sysid,
        "compid": compid,
        "severity": severity,
        "text": text,
        "id": 0,
        "chunk_seq": 0
    }


def make_param_set_msg(param_id: str = "TEST_PARAM", param_value: float = 1.0,
                      sysid: int = 255, compid: int = 1) -> dict:
    """Build a PARAM_SET message dict."""
    return {
        "msg_type": 24,  # MAVLINK_MSG_ID_PARAM_SET
        "seq": 0,
        "sysid": sysid,
        "compid": compid,
        "param_id": param_id,
        "param_value": param_value,
        "param_type": 9  # MAV_PARAM_TYPE_REAL32
    }


def make_param_value_msg(param_id: str = "TEST_PARAM", param_value: float = 1.0,
                        sysid: int = 255, compid: int = 1) -> dict:
    """Build a PARAM_VALUE message dict."""
    return {
        "msg_type": 23,  # MAVLINK_MSG_ID_PARAM_VALUE
        "seq": 0,
        "sysid": sysid,
        "compid": compid,
        "param_id": param_id,
        "param_value": param_value,
        "param_type": 9,  # MAV_PARAM_TYPE_REAL32
        "param_index": 0,
        "param_count": 0
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
class TestFirmwareAttackDetector:
    """Test suite for FirmwareAttackDetector."""
    
    def setup_method(self):
        """Create a fresh detector for each test."""
        self.detector = FirmwareAttackDetector()
        
    # -------------------------------------------------------------------
    # Reboot/shutdown command tests
    # -------------------------------------------------------------------
    def test_bootloader_reboot_armed_detected(self):
        """Bootloader reboot command while armed should trigger alert."""
        msg = make_command_msg(
            command_id=246,  # MAV_CMD_PREFLIGHT_REBOOT_SHUTDOWN
            sysid=255
        )
        # Simulate being armed (we'll patch the detector's state check)
        self.detector._is_currently_armed = lambda: True
        self.detector._reboot_rules["allow_bootloader_reboot_armed"] = False
        
        alert = self.detector.process_message(msg)
        assert alert is not None
        assert alert.reason == "bootloader_reboot_armed"
        assert alert.severity == "high"
        assert alert.rule_id == "FW-001"
        
    def test_bootloader_reboot_armed_allowed(self):
        """Bootloader reboot while armed should be allowed when permitted."""
        msg = make_command_msg(
            command_id=246,  # MAV_CMD_PREFLIGHT_REBOOT_SHUTDOWN
            sysid=255
        )
        self.detector._is_currently_armed = lambda: True
        self.detector._reboot_rules["allow_bootloader_reboot_armed"] = True  # Allow it
        
        alert = self.detector.process_message(msg)
        assert alert is None  # Should not alert
        
    def test_bootloader_reboot_disarmed_blocked(self):
        """Bootloader reboot while disarmed should trigger alert when not allowed."""
        msg = make_command_msg(
            command_id=246,  # MAV_CMD_PREFLIGHT_REBOOT_SHUTDOWN
            sysid=255
        )
        self.detector._is_currently_armed = lambda: False
        self.detector._reboot_rules["allow_bootloader_reboot_disarmed"] = False
        
        alert = self.detector.process_message(msg)
        assert alert is not None
        assert alert.reason == "bootloader_reboot_disarmed"
        assert alert.severity == "high"
        
    def test_bootloader_reboot_disarmed_allowed(self):
        """Bootloader reboot while disarmed should be allowed when permitted."""
        msg = make_command_msg(
            command_id=246,  # MAV_CMD_PREFLIGHT_REBOOT_SHUTDOWN
            sysid=255
        )
        self.detector._is_currently_armed = lambda: False
        self.detector._reboot_rules["allow_bootloader_reboot_disarmed"] = True  # Allow it
        
        alert = self.detector.process_message(msg)
        assert alert is None  # Should not alert
        
    def test_do_reboot_command_detected(self):
        """DO_REBOOT command should trigger similar checks."""
        msg = make_command_msg(
            command_id=248,  # MAV_CMD_DO_REBOOT
            sysid=255
        )
        self.detector._is_currently_armed = lambda: True
        self.detector._reboot_rules["allow_bootloader_reboot_armed"] = False
        
        alert = self.detector.process_message(msg)
        assert alert is not None
        assert alert.reason == "bootloader_reboot_armed"  # Same reason
        
    # -------------------------------------------------------------------
    # Firmware update command tests
    # -------------------------------------------------------------------
    def test_unauthorized_firmware_update_detected(self):
        """UPDATE_AUTOPILOT command when not in update window should alert."""
        msg = make_command_msg(
            command_id=249,  # MAV_CMD_UPDATE_AUTOPILOT
            sysid=255
        )
        # Make update not allowed (require disarmed but we're not tracking state properly)
        self.detector._is_update_allowed = lambda: False
        
        alert = self.detector.process_message(msg)
        assert alert is not None
        assert alert.reason == "unauthorized_firmware_update"
        assert alert.severity == "high"
        assert alert.rule_id == "FW-009"
        
    def test_firmware_update_allowed_no_alert(self):
        """UPDATE_AUTOPILOT when allowed should not alert."""
        msg = make_command_msg(
            command_id=249,  # MAV_CMD_UPDATE_AUTOPILOT
            sysid=255
        )
        self.detector._is_update_allowed = lambda: True
        
        alert = self.detector.process_message(msg)
        assert alert is None
        
    # -------------------------------------------------------------------
    # Version/git hash tests
    # -------------------------------------------------------------------
    def test_unexpected_version_detected(self):
        """Unexpected firmware version (not a downgrade) should trigger alert."""
        # Set last known version to something OLDER than test version
        # so it's NOT a downgrade but still unexpected (not in approved list)
        self.detector._last_version = "Copter-4.2.0"
         
        msg = make_version_msg(
            version="Copter-4.3.0",  # Unexpected AND not a downgrade from 4.2.0
            git_hash="a1b2c3d4e5f"
        )
         
        alert = self.detector.process_message(msg)
        assert alert is not None
        assert alert.reason == "unexpected_firmware_version"
        assert alert.severity == "high"
        assert alert.rule_id == "FW-003"
        
    def test_version_downgrade_detected(self):
        """Firmware version downgrade should trigger alert."""
        self.detector._last_version = "Copter-4.5.0"
        
        msg = make_version_msg(
            version="Copter-4.4.0",  # Downgrade
            git_hash="a1b2c3d4e5f"
        )
        
        alert = self.detector.process_message(msg)
        assert alert is not None
        assert alert.reason == "firmware_version_downgrade"
        assert alert.severity == "high"
        assert alert.rule_id == "FW-004"
        
    def test_approved_version_no_alert(self):
        """Approved version should not trigger alert."""
        self.detector._last_version = "Copter-4.5.0"
        
        msg = make_version_msg(
            version="Copter-4.5.0",  # Approved version
            git_hash="a1b2c3d4e5f"
        )
        
        alert = self.detector.process_message(msg)
        assert alert is None
        
    def test_unexpected_git_hash_detected(self):
        """Unexpected git hash should trigger alert."""
        # Set approved hashes in the policy
        self.detector._approved_git_hashes = {"a1b2c3d"}
        self.detector._last_git_hash = "a1b2c3d"
        
        msg = make_version_msg(
            version="Copter-4.5.0",
            git_hash="def4567"  # Unexpected hash (not in approved)
        )
        
        alert = self.detector.process_message(msg)
        assert alert is not None
        assert alert.reason == "unexpected_git_hash"
        assert alert.severity == "high"
        assert alert.rule_id == "FW-003"
        
    def test_git_hash_downgrade_detected(self):
        """Git hash downgrade should trigger alert."""
        # Set approved hashes
        self.detector._approved_git_hashes = {"def4567"}
        self.detector._last_git_hash = "def4567"
        
        msg = make_version_msg(
            version="Copter-4.5.0",
            git_hash="a1b2c3d"  # Lexicographically earlier = downgrade
        )
        
        alert = self.detector.process_message(msg)
        assert alert is not None
        assert alert.reason == "git_hash_downgrade"
        assert alert.severity == "high"
        assert alert.rule_id == "FW-004"
        
    def test_approved_git_hash_no_alert(self):
        """Approved git hash should not trigger alert."""
        self.detector._last_git_hash = "a1b2c3d"
        
        msg = make_version_msg(
            version="Copter-4.5.0",
            git_hash="a1b2c3d"  # Same as last
        )
        
        alert = self.detector.process_message(msg)
        assert alert is None
        
    # -------------------------------------------------------------------
    # FTP tests
    # -------------------------------------------------------------------
    def test_ftp_block_oversized_detected(self):
        """Oversized FTP block should trigger alert."""
        msg = make_ftp_msg(
            session=1,
            sequence=0,
            payload_size=1024,  # Larger than default 512
            payload=b"x" * 1024
        )
         
        alert = self.detector.process_message(msg)
        assert alert is not None
        assert alert.reason == "ftp_block_oversized"
        assert alert.severity == "medium"
        assert alert.rule_id == "FW-002"
        
    def test_ftp_block_normal_no_alert(self):
        """Normal sized FTP block should not alert."""
        msg = make_ftp_msg(
            session=1,
            sequence=0,
            payload_size=256,  # Smaller than 512
            payload=b"x" * 256
        )
         
        alert = self.detector.process_message(msg)
        assert alert is None
        
    def test_ftp_file_oversized_detected(self):
        """Oversized total file transfer should trigger alert."""
        # First packet - keep under block size limit
        msg1 = make_ftp_msg(
            session=1,
            sequence=0,
            payload_size=100,  # Under 512 byte block limit
            payload=b"x" * 100
        )
        self.detector.process_message(msg1)  # Process to update session state

        # Second packet - still under block size but puts total over file limit
        msg2 = make_ftp_msg(
            session=1,
            sequence=1,
            payload_size=100,  # Still under block limit
            payload=b"y" * 100
        )
        # Manually increment the byte count to simulate large file
        # We need to access the internal state to set it up properly
        session_info = self.detector._active_ftp_sessions.get(1, {})
        session_info["bytes_transferred"] = 1048576 - 50  # 50 bytes under limit
        session_info["packets"] = 1
        
        # Now this packet should put us over the limit
        alert = self.detector.process_message(msg2)
        assert alert is not None
        assert alert.reason == "ftp_file_oversized"
        assert alert.severity == "high"
        assert alert.rule_id == "FW-002"
        
    def test_ftp_write_to_protected_path_detected(self):
        """FTP write to protected path should alert when not allowed."""
        msg = make_ftp_msg(
            session=1,
            sequence=0,
            payload_size=25,
            payload=b"/APM/scripts/test.py\x00" + b"data"  # Simulate path in payload
        )
        # Make sure we're not in update window - set state to FLYING (not DISARMED)
        self.detector._get_current_state = lambda: "FLYING"
        
        alert = self.detector.process_message(msg)
        assert alert is not None
        assert alert.reason == "ftp_write_to_protected_path"
        assert alert.severity == "high"
        assert alert.rule_id == "FW-002"
        
    def test_ftp_to_allowed_path_no_alert(self):
        """FTP to allowed path should not alert."""
        msg = make_ftp_msg(
            session=1,
            sequence=0,
            payload_size=10,
            payload=b"/logs/flight.bin\x00" + b"data"
        )
         
        alert = self.detector.process_message(msg)
        assert alert is None
        
    # -------------------------------------------------------------------
    # Heartbeat / bootloader mode tests
    # -------------------------------------------------------------------
    def test_heartbeat_bootloader_mode_armed_detected(self):
        """HEARTBEAT showing bootloader mode while armed should alert."""
        msg = make_heartbeat_msg(
            base_mode=160,  # MAV_MODE_FLAG_TEST_ENABLED (32) + MAV_MODE_FLAG_SAFETY_ARMED (128)
            sysid=255
        )
        self.detector._reboot_rules["allow_bootloader_reboot_armed"] = False
         
        alert = self.detector.process_message(msg)
        assert alert is not None
        assert alert.reason == "bootloader_mode_armed"
        assert alert.severity == "high"
        assert alert.rule_id == "FW-001"
        
    def test_heartbeat_bootloader_mode_disarmed_detected(self):
        """HEARTBEAT showing bootloader mode while disarmed should alert when not allowed."""
        msg = make_heartbeat_msg(
            base_mode=32,  # MAV_MODE_FLAG_TEST_ENABLED set
            sysid=255
        )
        self.detector._reboot_rules["allow_bootloader_reboot_disarmed"] = False
         
        alert = self.detector.process_message(msg)
        assert alert is not None
        assert alert.reason == "bootloader_mode_disarmed"
        assert alert.severity == "high"
        assert alert.rule_id == "FW-001"
        
    # -------------------------------------------------------------------
    # Boot count / uptime tests
    # -------------------------------------------------------------------
    def test_unexpected_boot_count_jump_detected(self):
        """Sudden increase in boot count should trigger alert."""
        # Set last known boot count
        self.detector._last_boot_count = 10
        
        msg = make_sys_status_msg(boot_count=15)  # Jump of 5
        # Threshold is 1 by default
        
        alert = self.detector.process_message(msg)
        assert alert is not None
        assert alert.reason == "unexpected_boot_count_jump"
        assert alert.severity == "high"
        assert alert.rule_id == "FW-006"
        
    def test_normal_boot_count_increment_no_alert(self):
        """Small boot count increment should not alert."""
        self.detector._last_boot_count = 10
        
        msg = make_sys_status_msg(boot_count=11)  # Jump of 1
        # Threshold is 1, so equal should not alert (only > threshold)
        
        alert = self.detector.process_message(msg)
        assert alert is None
        
    def test_unexpected_uptime_jump_detected(self):
        """Large negative uptime jump (reboot) should trigger alert."""
        self.detector._last_uptime_s = 100.0  # 100 seconds uptime
        
        msg = make_system_time_msg(time_boot_ms=10000)  # 10 seconds = big jump backward
        
        alert = self.detector.process_message(msg)
        assert alert is not None
        assert alert.reason == "unexpected_uptime_jump"
        assert alert.severity == "high"
        assert alert.rule_id == "FW-006"
        
    def test_normal_uptime_progression_no_alert(self):
        """Normal uptime increase should not alert."""
        self.detector._last_uptime_s = 100.0
        
        msg = make_system_time_msg(time_boot_ms=150000)  # 150 seconds = normal increase
        
        alert = self.detector.process_message(msg)
        assert alert is None
        
    # -------------------------------------------------------------------
    # Status text tests
    # -------------------------------------------------------------------
    def test_bootloader_status_text_detected(self):
        """STATUSTEXT with bootloader indicators should alert."""
        msg = make_statustext_msg(
            severity=3,  # INFO level
            text="Entering bootloader mode"
        )
         
        alert = self.detector.process_message(msg)
        assert alert is not None
        assert alert.reason == "bootloader_status_text"
        assert alert.severity == "medium"
        assert alert.rule_id == "FW-001"
        
    def test_normal_status_text_no_alert(self):
        """Normal STATUSTEXT should not alert."""
        msg = make_statustext_msg(
            severity=6,  # DEBUG level (less severe)
            text="EKF2 OK"
        )
         
        alert = self.detector.process_message(msg)
        assert alert is None
        
    # -------------------------------------------------------------------
    # Protected parameter tests
    # -------------------------------------------------------------------
    def test_protected_parameter_change_detected(self):
        """PARAM_SET to protected parameter outside update window should alert."""
        msg = make_param_set_msg(
            param_id="ARMING_CHECK",
            param_value=0.0
        )
        # Not in update window - set state to FLYING (not in allowed_states which is ["DISARMED"])
        self.detector._get_current_state = lambda: "FLYING"
         
        alert = self.detector.process_message(msg)
        assert alert is not None
        assert alert.reason == "protected_parameter_change_invalid_state"
        assert alert.severity == "high"
        assert alert.rule_id == "FW-007"
        
    def test_protected_parameter_allowed_no_alert(self):
        """PARAM_SET to protected parameter in update window should not alert."""
        msg = make_param_set_msg(
            param_id="ARMING_CHECK",
            param_value=0.0
        )
        self.detector._is_update_allowed = lambda: True  # Allow updates
         
        alert = self.detector.process_message(msg)
        assert alert is None
        
    def test_unprotected_parameter_no_alert(self):
        """PARAM_SET to unprotected parameter should not alert."""
        msg = make_param_set_msg(
            param_id="SOME_RANDOM_PARAM",
            param_value=123.45
        )
         
        alert = self.detector.process_message(msg)
        assert alert is None
        
    # -------------------------------------------------------------------
    # Statistics tests
    # -------------------------------------------------------------------
    def test_get_stats_returns_correct_values(self):
        """get_stats should return accurate counts."""
        # Process a few clean messages
        for i in range(5):
            msg = make_heartbeat_msg()
            self.detector.process_message(msg)
             
        stats = self.detector.get_stats()
        assert stats["packets"] == 5
        assert stats["alerts"] == 0
        assert isinstance(stats["last_latency_us"], float)
        
    def test_reset_clears_state(self):
        """reset should clear all internal state."""
        # Set some state
        self.detector._last_version = "test"
        self.detector._last_git_hash = "hash"
        self.detector._last_boot_count = 5
        self.detector._packets_seen = 10
        self.detector._alerts_raised = 2
         
        self.detector.reset()
         
        assert self.detector._last_version is None
        assert self.detector._last_git_hash is None
        assert self.detector._last_boot_count is None
        assert self.detector._packets_seen == 0
        assert self.detector._alerts_raised == 0
        
    # -------------------------------------------------------------------
    # Integration tests - multiple message types
    # -------------------------------------------------------------------
    def test_multiple_attacks_in_sequence(self):
        """Processing multiple attack messages should generate multiple alerts."""
        alerts = []
         
        # Version attack - use a version that's unexpected but NOT a downgrade
        msg1 = make_version_msg(version="Copter-4.6.0")
        self.detector._last_version = "Copter-4.4.0"  # Older, so 4.6.0 is not a downgrade
        alert1 = self.detector.process_message(msg1)
        if alert1:
            alerts.append(alert1)
             
        # Reboot attack
        msg2 = make_command_msg(command_id=246)
        self.detector._is_currently_armed = lambda: True
        self.detector._reboot_rules["allow_bootloader_reboot_armed"] = False
        alert2 = self.detector.process_message(msg2)
        if alert2:
            alerts.append(alert2)
             
        # FTP attack
        msg3 = make_ftp_msg(payload_size=1024)
        alert3 = self.detector.process_message(msg3)
        if alert3:
            alerts.append(alert3)
             
        assert len(alerts) == 3
        # Check we got different types of alerts
        reasons = {a.reason for a in alerts}
        assert "unexpected_firmware_version" in reasons
        assert "bootloader_reboot_armed" in reasons
        assert "ftp_block_oversized" in reasons


# ---------------------------------------------------------------------------
# Negative tests - ensure benign traffic doesn't false positive
# ---------------------------------------------------------------------------
class TestFirmwareAttackDetectorNegative:
    """Test that benign traffic doesn't trigger false alerts."""
    
    def setup_method(self):
        self.detector = FirmwareAttackDetector()
        
    def test_benign_heartbeat_no_alert(self):
        """Normal HEARTBEAT should not alert."""
        msg = make_heartbeat_msg()
        alert = self.detector.process_message(msg)
        assert alert is None
         
    def test_benign_command_no_alert(self):
        """Normal COMMAND_LONG should not alert."""
        msg = make_command_msg(command_id=400)  # ARM/DISARM
        alert = self.detector.process_message(msg)
        assert alert is None
         
    def test_benign_ftp_no_alert(self):
        """Normal FTP transfer should not alert."""
        msg = make_ftp_msg(
            payload_size=100,
            payload=b"/logs/flight1.bin\x00" + b"data"  # Allowed path
        )
        alert = self.detector.process_message(msg)
        assert alert is None
         
    def test_benign_version_no_alert(self):
        """Expected version should not alert."""
        self.detector._last_version = "Copter-4.5.0"
        msg = make_version_msg(version="Copter-4.5.0")
        alert = self.detector.process_message(msg)
        assert alert is None
         
    def test_benign_boot_count_no_alert(self):
        """Normal boot count progression should not alert."""
        self.detector._last_boot_count = 5
        msg = make_sys_status_msg(boot_count=6)
        alert = self.detector.process_message(msg)
        assert alert is None
         
    def test_benign_uptime_no_alert(self):
        """Normal uptime progression should not alert."""
        self.detector._last_uptime_s = 100.0
        msg = make_system_time_msg(time_boot_ms=150000)  # 50 seconds later
        alert = self.detector.process_message(msg)
        assert alert is None
         
    def test_benign_param_no_alert(self):
        """Normal PARAM_SET should not alert."""
        msg = make_param_set_msg(param_id="TEST_PARAM", param_value=1.0)
        alert = self.detector.process_message(msg)
        assert alert is None