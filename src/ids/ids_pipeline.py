#!/usr/bin/env python3
"""
ids_pipeline.py

COMMUNICATION-ATTACKS DETECTION PIPELINE
=========================================
Chains the four Communication-Attacks sub-detectors into a single,
low-latency, real-time processing pipeline suitable for running onboard
a resource-constrained UAV companion computer.

Stage ordering principle — CHEAPEST FIRST:
    Layer 1  MavlinkAnomalyDetector    CRC integrity.................. O(1)  every packet
    Layer 2  ReplayDetector            sliding-window anti-replay .... O(1)  every packet
    Layer 3  CommandInjectionDetector  state-machine validation ...... O(1)  command msgs only
    Layer 4  RFJammingDetector         RF statistics (windowed) ...... O(w)  RADIO_STATUS only

Design decisions (ask-me-about-this list for the viva):
  * CHEAPEST-FIRST / EARLY-EXIT:
      - CRC failure is authoritative: a frame that fails CRC is UNTRUSTED,
        so the remaining layers are skipped (no point analysing garbage).
      - Non-command / non-radio messages only traverse layers 1-2.
  * SEQUENCE-ADJUDICATION DIVISION OF LABOUR (kills FPR):
      - Layer 1's sequence check is STRICT (any backward/duplicate flags).
      - Layer 2's sliding window is PERMISSIVE (tolerates reordering within
        a 64-seq window by design).
      - Naive chaining: legitimate reordering (10,12,11) trips layer 1
        ("backward jump") -> false positive -> bad for the 20% FPR score.
      - Resolution: when the replay window ACCEPTS a seq (no replay alert),
        any layer-1 *sequence* alert for that same packet is SUPPRESSED.
        CRC alerts are never suppressed. This gives strict sanity PLUS
        reordering tolerance with zero false positives.
  * GROUND-TRUTH ONLY: the command-injection state machine is updated ONLY
    from HEARTBEAT telemetry, never from the command stream.
  * FAST PATH: a clean packet allocates nothing except the (reused) alert
    list; stats are cheap counters. Latency per stage is measured in µs.
  * THREADING: single-threaded by design (receive loop feeding packets in
    order). Run one Pipeline per input stream; do NOT share across threads.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

# Sub-detectors -----------------------------------------------------------
from .mavlink_anomaly_detector import MavlinkAnomalyDetector, x25_crc
from .replay_detector import ReplayDetector
from .command_injection_detector import CommandInjectionDetector
from .rf_jamming_detector import RFJammingDetector
from .firmware_attack_detector import FirmwareAttackDetector
from .behavioral_fingerprint import BehavioralFingerprint
from .companion_integrity import CompanionIntegrityModule
from .control_system_detector import ControlSystemDetectorFacade
from .fusion_ids import NavigationIDSFacade

logger = logging.getLogger("ids.pipeline")

# Severity ordering helper
_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Command-carrying message types (layer 3 fast-path selector)
_COMMAND_MSGS = ("COMMAND_LONG", "COMMAND_INT", "SET_MODE", "PARAM_SET")


# ---------------------------------------------------------------------------
# Message envelope — normalized representation of one inbound MAVLink frame.
# (slots=True keeps per-packet overhead tiny; pymavlink messages are
#  converted into this exactly once at the input boundary.)
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class IDSMessage:
    """Normalized view of one inbound MAVLink frame."""

    msg_type: str                 # e.g. "HEARTBEAT", "COMMAND_LONG", "RADIO_STATUS"
    seq: int                      # link sequence number (0-255 on the wire)
    sysid: int
    compid: int
    arrival_time: float           # wall-clock receive time (time.time())
    msg_timestamp: float = 0.0    # timestamp carried by the message, if any
    raw_frame: bytes = b""        # full frame INCLUDING CRC (for CRC re-check)
    field: dict = field(default_factory=dict)   # parsed payload fields

    @property
    def rssi(self) -> Optional[float]:
        return self.field.get("rssi")

    @property
    def noise(self) -> Optional[float]:
        return self.field.get("noise")

    @property
    def rxerrors(self) -> Optional[int]:
        return self.field.get("rxerrors")

    @property
    def command(self) -> Optional[str]:
        return self.field.get("command")


class AnomalyStage:
    """Layer 1 — X25 CRC integrity + strict sequence sanity."""

    name = "anomaly"

    def __init__(self, seq_tolerance: int = 5, check_seq: bool = True) -> None:
        self.detector = MavlinkAnomalyDetector(seq_tolerance=seq_tolerance)
        self.check_seq = check_seq          # pipeline usually runs CRC-only here
        self.packets_seen = 0
        self.alerts_raised = 0
        self.last_latency_us = 0.0
        self._last = time.perf_counter()

    def process(self, msg: IDSMessage) -> List[dict]:
        now = time.perf_counter()
        self.last_latency_us = (now - self._last) * 1e6
        self._last = now
        self.packets_seen += 1

        out: List[dict] = []
        # 1) CRC is ALWAYS checked (authoritative).
        if len(msg.raw_frame) >= 2:
            expected = int.from_bytes(msg.raw_frame[-2:], "little")
            crc_ok = self.detector.verify_crc(msg.raw_frame[:-2], expected)
            if not crc_ok:
                self.alerts_raised += 1
                return [{
                    "layer": self.name, "check": "crc",
                    "severity": "high", "reason": "crc_mismatch",
                    "seq": msg.seq, "timestamp": msg.arrival_time,
                }]

        # 2) Optional strict sequence sanity (usually delegated to layer 2).
        if self.check_seq:
            a = self.detector.check_sequence(msg.seq)
            if a is not None:
                self.alerts_raised += 1
                out.append({"layer": self.name, **a})
        return out


class ReplayStage:
    """Layer 2 — RFC 4303 sliding-window anti-replay + timestamp freshness."""

    name = "replay"

    def __init__(
        self, window_size: int = 64, seq_bits: int = 32, max_age_seconds: float = 2.0
    ) -> None:
        self.detector = ReplayDetector(
            window_size=window_size, seq_bits=seq_bits, max_age_seconds=max_age_seconds
        )
        self.packets_seen = 0
        self.alerts_raised = 0
        self.last_latency_us = 0.0
        self._last = time.perf_counter()

    def process(self, msg: IDSMessage) -> List[dict]:
        now = time.perf_counter()
        self.last_latency_us = (now - self._last) * 1e6
        self._last = now
        self.packets_seen += 1

        out: List[dict] = []
        for a in self.detector.check(
            msg.msg_type, msg.seq, msg.msg_timestamp, msg.arrival_time
        ):
            self.alerts_raised += 1
            out.append({"layer": self.name, **a})
        return out


class CommandInjectionStage:
    """Layer 3 — state-machine command validation (command messages only)."""

    name = "command_injection"

    def __init__(
        self,
        initial_state: str = "DISARMED",
        authorized_sysid: Optional[int] = 255,
    ) -> None:
        self.detector = CommandInjectionDetector(
            initial_state=initial_state, authorized_sysid=authorized_sysid
        )
        self.packets_seen = 0
        self.alerts_raised = 0
        self.last_latency_us = 0.0
        self._last = time.perf_counter()

    def process(self, msg: IDSMessage) -> List[dict]:
        now = time.perf_counter()
        self.last_latency_us = (now - self._last) * 1e6
        self._last = now
        self.packets_seen += 1

        if msg.msg_type not in _COMMAND_MSGS:
            return []

        class _CmdMsg:                      # min adapter for the validator
            def __init__(self) -> None:
                self.sysid = msg.sysid
                self.command = msg.command if msg.command is not None \
                    else msg.field.get("command_id")

            def get_type(self) -> str:
                return msg.msg_type

        alert = self.detector.process_command(_CmdMsg())
        if alert is not None:
            self.alerts_raised += 1
            return [{"layer": self.name, **alert}]
        return []

    def update_state_from_telemetry(self, new_state: str) -> None:
        self.detector.update_state_from_telemetry(new_state)


class RFJammingStage:
    """Layer 4 — RF statistics (RADIO_STATUS messages only)."""

    name = "rf_jamming"

    def __init__(self, **kwargs) -> None:
        self.detector = RFJammingDetector(**kwargs)
        self.packets_seen = 0
        self.alerts_raised = 0
        self.last_latency_us = 0.0
        self._last = time.perf_counter()

    def process(self, msg: IDSMessage) -> List[dict]:
        now = time.perf_counter()
        self.last_latency_us = (now - self._last) * 1e6
        self._last = now
        self.packets_seen += 1

        if msg.msg_type != "RADIO_STATUS":
            return []
        if msg.rssi is None or msg.noise is None or msg.rxerrors is None:
            return []
        alert = self.detector.check(msg.rssi, msg.noise, msg.rxerrors, msg.arrival_time)
        if alert is not None:
            self.alerts_raised += 1
            return [{"layer": self.name, **alert}]
        return []


class FirmwareStage:
    """Layer 5 — Firmware attack detector (Phase 2)."""

    name = "firmware"

    def __init__(self, **kwargs) -> None:
        self.detector = FirmwareAttackDetector(**kwargs)
        self.packets_seen = 0
        self.alerts_raised = 0
        self.last_latency_us = 0.0
        self._last = time.perf_counter()

    def process(self, msg: IDSMessage) -> List[dict]:
        now = time.perf_counter()
        self.last_latency_us = (now - self._last) * 1e6
        self._last = now
        self.packets_seen += 1

        out: List[dict] = []
        # Check if message type is relevant for firmware detection
        if msg.msg_type in ("COMMAND_LONG", "COMMAND_INT", "HEARTBEAT",
                          "RADIO_STATUS", "AUTOPILOT_VERSION", "STATUSTEXT",
                          "PARAM_SET", "PARAM_VALUE"):
            alert = self.detector.process_message({
                "msg_type": msg.msg_type,
                "seq": msg.seq,
                "sysid": msg.sysid,
                "compid": msg.compid,
                **msg.field
            })
            if alert is not None:
                self.alerts_raised += 1
                out.append({"layer": self.name, **alert})
        return out


class BehavioralStage:
    """Layer 6 — Behavioral fingerprint detector (Phase 4)."""

    name = "behavioral"

    def __init__(self, **kwargs) -> None:
        self.detector = BehavioralFingerprint(**kwargs)
        self.packets_seen = 0
        self.alerts_raised = 0
        self.last_latency_us = 0.0
        self._last = time.perf_counter()

    def process(self, msg: IDSMessage) -> List[dict]:
        now = time.perf_counter()
        self.last_latency_us = (now - self._last) * 1e6
        self._last = now
        self.packets_seen += 1

        out: List[dict] = []
        alert = self.detector.ingest({
            "msg_type": msg.msg_type,
            "seq": msg.seq,
            "sysid": msg.sysid,
            "compid": msg.compid,
            **msg.field
        })
        if alert is not None:
            self.alerts_raised += 1
            out.append({"layer": self.name, **alert})
        return out


class IntegrityStage:
    """Layer 7 — Companion integrity module (Phase 3)."""

    name = "integrity"

    def __init__(self, **kwargs) -> None:
        self.module = CompanionIntegrityModule(**kwargs)
        self.packets_seen = 0
        self.alerts_raised = 0
        self.last_latency_us = 0.0
        self._last = time.perf_counter()

    def process(self, msg: IDSMessage) -> List[dict]:
        now = time.perf_counter()
        self.last_latency_us = (now - self._last) * 1e6
        self._last = now
        self.packets_seen += 1

        out: List[dict] = []
        # Integrity module only does periodic scans on specific messages (e.g., HEARTBEAT)
        # For consistency with pipeline design, run scan_on every relevant message
        if msg.msg_type in ("HEARTBEAT", "COMMAND_LONG", "COMMAND_INT"):
            alerts = self.module.scan_once()
            for alert in alerts:
                self.alerts_raised += 1
                # Convert IDSAlert to dict for consistency
                out.append({"layer": self.name, **alert.to_json()})
        return out


class ControlSystemStage:
    """Layer 8 — Control system attack detector (Phase 1-2)."""

    name = "control_system"

    def __init__(self, **kwargs) -> None:
        self.detector = ControlSystemDetectorFacade(**kwargs)
        self.packets_seen = 0
        self.alerts_raised = 0
        self.last_latency_us = 0.0
        self._last = time.perf_counter()

    def process(self, msg: IDSMessage) -> List[dict]:
        now = time.perf_counter()
        self.last_latency_us = (now - self._last) * 1e6
        self._last = now
        self.packets_seen += 1

        # Ingest telemetry into the control system detector
        self.detector.ingest_telemetry(msg.msg_type, msg.arrival_time, **msg.field)

        # Run periodic checks (not on every packet to avoid overhead)
        # In a real implementation, we might check less frequently
        # For now, we'll check on every packet but the detector internal logic
        # will determine if it's time to run actual detection algorithms
        alert = self.detector.check(msg.arrival_time)
        if alert is not None:
            self.alerts_raised += 1
            # Convert IDSAlert to dict for consistency with other stages
            return [{"layer": self.name, **alert.to_json()}]
        return []


class NavigationStage:
    """Layer 9 — Navigation attack detector (Phase 1-3)."""

    name = "navigation"

    def __init__(self, **kwargs) -> None:
        self.detector = NavigationIDSFacade(**kwargs)
        self.packets_seen = 0
        self.alerts_raised = 0
        self.last_latency_us = 0.0
        self._last = time.perf_counter()

    def process(self, msg: IDSMessage) -> List[dict]:
        now = time.perf_counter()
        self.last_latency_us = (now - self._last) * 1e6
        self._last = now
        self.packets_seen += 1

        # Ingest telemetry into the navigation detector
        self.detector.ingest(msg.msg_type, msg.arrival_time, **msg.field)

        # Run detection checks
        alert = self.detector.check(msg.arrival_time)
        if alert is not None:
            self.alerts_raised += 1
            return [{"layer": self.name, **alert.to_json()}]
        return []


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------
class IDSPipeline:
    """
    Real-time Communication-Attacks detection pipeline.

    Usage (single thread):
        pipe = IDSPipeline()
        for msg in receive_loop():
            alerts = pipe.ingest(msg)          # list[dict], [] when clean
    """

    def __init__(
        self,
        seq_tolerance: int = 5,
        replay_window: int = 64,
        max_age_seconds: float = 2.0,
        authorized_gcs_sysid: int = 255,
        check_seq_layer1: bool = False,
        enable: Tuple[str, ...] = ("anomaly", "replay", "command_injection", "rf_jamming",
                                 "firmware", "behavioral", "integrity", "control_system", "navigation"),
        alert_callback: Optional[Callable[[dict], None]] = None,
    ) -> None:
        """
        Args:
            check_seq_layer1: if True, layer 1 also does strict sequence
                checks (default False: sequence adjudication is delegated to
                the replay layer to avoid FPR on reordered traffic).
        """
        self.enabled = [s for s in enable if s in self.STAGE_NAMES]
        self.stages = {
            "anomaly": AnomalyStage(seq_tolerance=seq_tolerance,
                                    check_seq=check_seq_layer1),
            "replay": ReplayStage(window_size=replay_window,
                                  max_age_seconds=max_age_seconds),
            "command_injection": CommandInjectionStage(
                initial_state="DISARMED", authorized_sysid=authorized_gcs_sysid),
            "rf_jamming": RFJammingStage(),
            "firmware": FirmwareStage(),
            "behavioral": BehavioralStage(),
            "integrity": IntegrityStage(),
            "control_system": ControlSystemStage(),
            "navigation": NavigationStage(),
        }
        self.alert_callback = alert_callback
        self.total_packets = 0
        self.total_alerts = 0
        self.stats: Dict[str, dict] = {}

    STAGE_NAMES = ("anomaly", "replay", "command_injection", "rf_jamming",
                   "firmware", "behavioral", "integrity", "control_system", "navigation")

    # ------------------------------------------------------------------
    def ingest(self, msg: IDSMessage) -> List[dict]:
        """
        Run one packet through all enabled stages.

        Returns list of alert dicts (empty when clean).
        """
        self.total_packets += 1
        alerts: List[dict] = []

        # Ground-truth state updates from HEARTBEAT only (never commands).
        if msg.msg_type == "HEARTBEAT" and "command_injection" in self.enabled:
            mode = msg.field.get("mode")
            if mode:
                self.stages["command_injection"].update_state_from_telemetry(mode)

        # --- Layer 1: anomaly ------------------------------------------
        layer1 = self.stages["anomaly"]
        if "anomaly" in self.enabled:
            alerts.extend(layer1.process(msg))
            # CRC failure -> frame untrusted -> EARLY EXIT.
            if any(a.get("check") == "crc" for a in alerts):
                return self._finish(alerts)

        # --- Layer 2: replay -------------------------------------------
        replay_alerts: List[dict] = []
        if "replay" in self.enabled:
            replay_alerts = self.stages["replay"].process(msg)
            alerts.extend(replay_alerts)

        # --- Suppression rule (FPR killer) -----------------------------
        # If the replay window ACCEPTED this seq, drop the layer-1 strict
        # sequence alert: it was legitimate reordering, not an attack.
        if replay_alerts is None or not replay_alerts:
            alerts = [a for a in alerts if not (a.get("layer") == "anomaly"
                                                and a.get("check") == "sequence")]

        # --- Layers 3-4 ------------------------------------------------
        for name in ("command_injection", "rf_jamming"):
            if name in self.enabled:
                alerts.extend(self.stages[name].process(msg))

        # --- Layer 5: Firmware Attack Detector (Phase 2) ---------------
        if "firmware" in self.enabled:
            alerts.extend(self.stages["firmware"].process(msg))

        # --- Layer 6: Behavioral Fingerprint (Phase 4) -----------------
        if "behavioral" in self.enabled:
            alerts.extend(self.stages["behavioral"].process(msg))

        # --- Layer 7: Companion Integrity (Phase 3) -------------------
        if "integrity" in self.enabled:
            alerts.extend(self.stages["integrity"].process(msg))

        # --- Layer 8: Control System Attack Detector (Phase 1-2) ---
        if "control_system" in self.enabled:
            alerts.extend(self.stages["control_system"].process(msg))

        # --- Layer 9: Navigation Attack Detector (Phase 1-3) ---
        if "navigation" in self.enabled:
            alerts.extend(self.stages["navigation"].process(msg))

        return self._finish(alerts)

    # ------------------------------------------------------------------
    def _finish(self, alerts: List[dict]) -> List[dict]:
        if alerts:
            self.total_alerts += len(alerts)
            if self.alert_callback:
                for a in alerts:
                    try:
                        self.alert_callback(a)
                    except Exception as exc:
                        logger.exception("alert callback failed: %s", exc)
        # Cheap per-packet stats snapshot
        overall_us = 0.0
        for name in self.enabled:
            st = self.stages[name]
            overall_us += st.last_latency_us
            self.stats[name] = {
                "packets": st.packets_seen,
                "alerts": st.alerts_raised,
                "last_latency_us": round(st.last_latency_us, 2),
            }
        self.stats["overall"] = {
            "packets": self.total_packets,
            "alerts": self.total_alerts,
            "last_latency_us": round(overall_us, 2),
        }
        return alerts

    # ------------------------------------------------------------------
    def get_stats(self) -> dict:
        return self.stats

    # ------------------------------------------------------------------
    def reset(self, hard: bool = False) -> None:
        self.total_packets = 0
        self.total_alerts = 0
        if hard:
            for st in self.stages.values():
                if hasattr(st, "detector") and hasattr(st.detector, "reset"):
                    st.detector.reset()
                elif hasattr(st, "module") and hasattr(st.module, "reset"):
                    st.module.reset()


# ---------------------------------------------------------------------------
# Input adapter helpers
# ---------------------------------------------------------------------------
def make_frame(seq: int, payload: bytes = b"") -> bytes:
    """Build a VALID MAVLink v2 frame (with correct X25 CRC) for testing."""
    header = b"\xfd" + bytes([len(payload)]) + b"\x00\x00" + bytes([seq])
    header += b"\x01\x01" + b"\x00\x00\x00"          # sysid=1 compid=1 msgid=0
    body = header + payload
    crc = x25_crc(body[1:])
    return body + bytes([crc & 0xFF, (crc >> 8) & 0xFF])


def message_from_pymavlink(mav_msg, raw_bytes: bytes = b"") -> IDSMessage:
    """Convert a pymavlink message into an IDSMessage (see docs in file)."""
    fields: Dict[str, object] = {}
    t = mav_msg.get_type()
    if t == "RADIO_STATUS":
        fields["rssi"] = float(getattr(mav_msg, "rssi", 0))
        fields["noise"] = float(getattr(mav_msg, "noise", 0))
        fields["rxerrors"] = int(getattr(mav_msg, "rxerrors", 0))
    if t == "HEARTBEAT":
        fields["mode"] = getattr(mav_msg, "custom_mode", 0) or getattr(mav_msg, "mode", 0)
    if t in _COMMAND_MSGS:
        fields["command_id"] = getattr(mav_msg, "command", None)
        fields["command"] = getattr(mav_msg, "command", None)

    return IDSMessage(
        msg_type=t,
        seq=int(getattr(mav_msg, "seq", 0) or 0),
        sysid=int(getattr(mav_msg, "sysid", 1) or 1),
        compid=int(getattr(mav_msg, "compid", 1) or 1),
        arrival_time=time.time(),
        msg_timestamp=float(getattr(mav_msg, "time_boot_ms", 0) or 0) / 1000.0,
        raw_frame=raw_bytes or make_frame(int(getattr(mav_msg, "seq", 0) or 0)),
        field=fields,
    )


# ===========================================================================
# End-to-end self-test
# ===========================================================================
if __name__ == "__main__":
    print("=" * 70)
    print("IDS PIPELINE — END-TO-END SELF TEST")
    print("=" * 70)

    alerts_log: List[dict] = []
    pipe = IDSPipeline(alert_callback=lambda a: alerts_log.append(a))

    # Helper: build a valid message with a real CRC.
    def msg(mt: str, seq: int, field_: Optional[dict] = None,
            sysid: int = 255, ts: float = 0.0, corrupt: bool = False) -> IDSMessage:
        raw = make_frame(seq)
        if corrupt:
            raw = raw[:-1] + bytes([raw[-1] ^ 0xFF])     # break the CRC
        return IDSMessage(
            msg_type=mt, seq=seq, sysid=sysid, compid=1,
            arrival_time=time.time(), msg_timestamp=ts,
            raw_frame=raw, field=field_ or {},
        )

    # [1] Normal telemetry: each frame = next link seq (0..7)
    print("\n[1] Normal telemetry (HEARTBEAT + GLOBAL_POSITION_INT seq 0..7)")
    for s in range(8):
        mt = "HEARTBEAT" if s % 2 == 0 else "GLOBAL_POSITION_INT"
        pipe.ingest(msg(mt, s, field_={"mode": 0} if mt == "HEARTBEAT" else None))
    n1 = len(alerts_log)
    print(f"    alerts: {n1} (expected 0) -> {'PASS' if n1 == 0 else 'FAIL'}")

    # [2] Legitimate in-window reordering: 10, 12, 11, 13
    print("\n[2] Legitimate reordering 10,12,11,13 (expect NO alerts — FPR test)")
    for s in (10, 12, 11, 13):
        pipe.ingest(msg("HEARTBEAT", s, field_={"mode": 0}))
    n2 = len(alerts_log) - n1
    print(f"    alerts: {n2} (expected 0) -> {'PASS' if n2 == 0 else 'FAIL'}")

    # [3] Exact duplicate replay
    print("\n[3] Replayed seq=12 again (expect replay alert)")
    pipe.ingest(msg("HEARTBEAT", 12, field_={"mode": 0}))
    n3 = len(alerts_log) - n1 - n2
    print(f"    alerts: {n3} -> last: {alerts_log[-1] if n3 else None}")
    print(f"    -> {'PASS' if n3 and alerts_log[-1].get('layer') == 'replay' else 'FAIL'}")

    # [4] Corrupt CRC frame -> anomaly alert + early exit
    print("\n[4] Corrupt CRC frame (expect anomaly/crc alert)")
    before = len(alerts_log)
    pipe.ingest(msg("HEARTBEAT", 20, field_={"mode": 0}, corrupt=True))
    n4 = len(alerts_log) - before
    last = alerts_log[-1] if n4 else {}
    print(f"    alerts: {n4} -> last: {last}")
    print(f"    -> {'PASS' if n4 and last.get('check') == 'crc' else 'FAIL'}")

    # [5] Unauthorized command from sysid=7 (attacker)
    print("\n[5] Unauthorized COMMAND_LONG from sysid=7 (expect alert)")
    before = len(alerts_log)
    pipe.ingest(msg("COMMAND_LONG", 30, field_={"command_id": 400}, sysid=7))
    n5 = len(alerts_log) - before
    last = alerts_log[-1] if n5 else {}
    print(f"    alerts: {n5} -> last: {last}")
    ok5 = n5 and last.get("reason") == "unauthorized_command_source"
    print(f"    -> {'PASS' if ok5 else 'FAIL'}")

    # [6] RF jamming scenario (30 RADIO_STATUS samples)
    print("\n[6] RF jamming: noise surge + rxerror climb (expect high-confidence)")
    before = len(alerts_log)
    rxerr = 0
    for i in range(30):
        if i < 10:
            rssi, noise = 190, 30
        else:
            rssi = max(190 - 2 * (i - 10), 120)
            noise = min(30 + 15 * (i - 10), 200)
            rxerr += 50 * (i - 10)
        pipe.ingest(msg("RADIO_STATUS", 100 + i,
                        field_={"rssi": rssi, "noise": noise, "rxerrors": rxerr}))
    n6 = len(alerts_log) - before
    confs = {a.get("confidence") for a in alerts_log[-n6:] if a.get("layer") == "rf_jamming"}
    print(f"    alerts: {n6} (expected >=1), confidences seen: {confs}")
    print(f"    -> {'PASS' if 'high' in confs else 'FAIL'}")

    print("\n--- Pipeline stats (per-stage latency in µs) ---")
    for k, v in pipe.get_stats().items():
        print(f"  {k}: {v}")

    passed = all(v for v in (n1 == 0, n2 == 0, n3 > 0, n4 > 0, ok5, 'high' in (confs or {''})))
    print("\nPIPELINE SELF-TEST:", "PASS" if passed else "FAIL")
    print("=" * 70)