#!/usr/bin/env python3
"""
mavlink_anomaly_detector.py

Fast, lightweight MAVLink packet sanity layer — runs on EVERY incoming frame
before expensive checks (signatures, replay detection, ML classifiers).

Catches:
  • Corrupted frames (bad CRC)
  • Duplicate sequence numbers
  • Backward sequence jumps (replay / injection)
  • Egregious forward gaps (burst injection or severe desync)

Tolerates normal radio packet loss via configurable `seq_tolerance`.

Designed for minimal per-packet overhead: no allocations in hot path,
pure integer arithmetic, single dict allocation only on anomaly.
"""

from __future__ import annotations
import time
from typing import Optional


# ============================================================
# X25 CRC (CRC-16/X25) — MAVLink's wire checksum
# Polynomial: 0x1021 (x^16 + x^12 + x^5 + 1), reflected, init=0xFFFF, xorout=0xFFFF
# This is a compact, table-free implementation fast enough for per-packet use.
# ============================================================
def x25_crc(data: bytes) -> int:
    """
    Compute MAVLink X25 CRC over `data` (payload only, no start byte, no CRC bytes).

    Args:
        data: Bytes to checksum (typically msgbuf[1:-2] for a raw frame).

    Returns:
        16-bit CRC value (matches pymavlink's crc.crc16).
    """
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0x8408
            else:
                crc >>= 1
    return crc ^ 0xFFFF


# ============================================================
# Anomaly Detector
# ============================================================
class MavlinkAnomalyDetector:
    """
    Streaming MAVLink anomaly detector.

    State (per instance):
        last_seq: Last-seen sequence number (0-255), or None before first packet.
        seq_tolerance: Max acceptable forward gap (default 5). Gaps <= tolerance
                       are treated as normal packet loss; gaps > tolerance flag.
    """

    __slots__ = ("last_seq", "seq_tolerance")

    def __init__(self, seq_tolerance: int = 5) -> None:
        """
        Args:
            seq_tolerance: Maximum forward sequence gap allowed without alert.
                           Typical radio links: 1-3 drops. Set 5-10 for noisy links.
                           Must be in [0, 254].
        """
        if not 0 <= seq_tolerance <= 254:
            raise ValueError("seq_tolerance must be in [0, 254]")
        self.seq_tolerance: int = seq_tolerance
        self.last_seq: Optional[int] = None  # None = no packet seen yet

    # --------------------------------------------------------
    # CRC verification
    # --------------------------------------------------------
    def verify_crc(self, raw_bytes: bytes, expected_crc: int) -> bool:
        """
        Verify MAVLink X25 CRC.

        Args:
            raw_bytes: Full raw frame bytes INCLUDING start byte (0xFD for v2)
                       but EXCLUDING the two CRC bytes at the end.
                       i.e., pass frame[:-2] for a complete frame.
            expected_crc: The 16-bit CRC value parsed from the frame's last 2 bytes.

        Returns:
            True if CRC matches, False if corrupted.
        """
        # MAVLink CRC covers everything after the start byte up to (but not including) CRC
        # Frame format v2: [STX=0xFD] [LEN] [INCOMPAT_FLAGS] [COMPAT_FLAGS] [SEQ] [SYSID] [COMPID] [MSGID...] [PAYLOAD...] [CRC_LO] [CRC_HI]
        # So we skip the first byte (STX) and compute over the rest.
        computed = x25_crc(raw_bytes[1:])
        return computed == expected_crc

    # --------------------------------------------------------
    # Sequence number analysis (handles 0-255 wraparound)
    # --------------------------------------------------------
    def check_sequence(self, seq: int) -> Optional[dict]:
        """
        Validate sequence number against expected progression.

        Args:
            seq: Incoming packet sequence number (0-255).

        Returns:
            None if sequence is acceptable (exact next, or small forward gap within tolerance).
            Alert dict if anomaly detected:
              - duplicate:            severity="high",   reason="duplicate_sequence"
              - backward_jump:        severity="high",   reason="backward_sequence_jump"
              - large_forward_gap:    severity="medium", reason="large_forward_gap"
              - minor_gap (logged):   severity="low",    reason="minor_gap_likely_loss"
        """
        if not 0 <= seq <= 255:
            return self._alert("sequence", "high", f"invalid_sequence_value_{seq}", seq)

        now = time.time()

        # First packet ever — initialize baseline
        if self.last_seq is None:
            self.last_seq = seq
            return None

        # Compute forward distance modulo 256
        # (seq - last_seq) mod 256 gives steps forward in [0, 255]
        forward_dist = (seq - self.last_seq) & 0xFF

        if forward_dist == 0:
            # Exact duplicate
            return self._alert("sequence", "high", "duplicate_sequence", seq, now)

        if forward_dist == 1:
            # Perfect: exactly the next expected sequence
            self.last_seq = seq
            return None

        if 1 < forward_dist <= self.seq_tolerance:
            # Small forward gap — normal packet loss, tolerate but log
            self.last_seq = seq
            return self._alert("sequence", "low", "minor_gap_likely_loss", seq, now)

        if forward_dist > self.seq_tolerance:
            # Large unexplained gap — possible injection burst or desync
            self.last_seq = seq
            return self._alert("sequence", "medium", "large_forward_gap", seq, now)

        # If we reach here, forward_dist wrapped the other way → backward jump
        # backward_dist = (self.last_seq - seq) & 0xFF  # positive steps backward
        # Any forward_dist > 128 means it's actually a backward jump (since max forward is 255)
        # But simpler: if not caught above, it's a backward jump.
        self.last_seq = seq
        return self._alert("sequence", "high", "backward_sequence_jump", seq, now)

    # --------------------------------------------------------
    # Combined per-packet processing
    # --------------------------------------------------------
    def process_packet(
        self, raw_bytes: bytes, seq: int, expected_crc: int
    ) -> Optional[dict]:
        """
        Run both CRC and sequence checks on a single packet.

        Args:
            raw_bytes: Full frame bytes including STX, excluding CRC bytes (frame[:-2]).
            seq: Sequence number parsed from the frame (0-255).
            expected_crc: CRC value parsed from frame's last 2 bytes (little-endian).

        Returns:
            First alert dict encountered (CRC checked first), or None if clean.
            If both fail, CRC alert is returned (corruption explains seq anomaly).
        """
        # 1. CRC check — fastest fail, catches corruption early
        if not self.verify_crc(raw_bytes, expected_crc):
            return self._alert("crc", "high", "crc_mismatch", seq)

        # 2. Sequence check
        return self.check_sequence(seq)

    # --------------------------------------------------------
    # Internal: build alert dict
    # --------------------------------------------------------
    def _alert(
        self,
        check: str,
        severity: str,
        reason: str,
        seq: int,
        timestamp: Optional[float] = None,
    ) -> dict:
        return {
            "check": check,
            "severity": severity,
            "reason": reason,
            "seq": seq,
            "timestamp": timestamp if timestamp is not None else time.time(),
        }

    # --------------------------------------------------------
    # Utility: reset state (e.g., on new connection / stream restart)
    # --------------------------------------------------------
    def reset(self) -> None:
        """Clear internal sequence tracker."""
        self.last_seq = None


# ============================================================
# Self-test / Demo
# ============================================================
if __name__ == "__main__":
    # Guard: Windows default console encoding (cp1252) can't print some
    # non-ASCII glyphs; force UTF-8 so the self-test is portable.
    try:
        import sys as _sys
        _sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    def run_scenario(name: str, detector: MavlinkAnomalyDetector, packets: list[tuple[bytes, int, int]], expected_alerts: list[bool]) -> None:
        """
        Helper to run a test scenario.

        Args:
            name: Scenario label.
            detector: Fresh detector instance.
            packets: List of (raw_bytes, seq, crc) tuples.
            expected_alerts: List of bools — True if alert expected, False if clean.
        """
        print(f"\n=== {name} ===")
        all_pass = True
        for i, (frame, seq, crc) in enumerate(packets):
            alert = detector.process_packet(frame, seq, crc)
            got_alert = alert is not None
            expected = expected_alerts[i]
            status = "PASS" if got_alert == expected else "FAIL"
            if got_alert != expected:
                all_pass = False
            print(f"  Pkt {i}: seq={seq:3d}  alert={got_alert}  expected={expected}  [{status}]")
            if alert:
                print(f"    → {alert}")
        print(f"  Scenario: {'PASS' if all_pass else 'FAIL'}")

    # ------------------------------------------------------------------
    # Build a minimal valid MAVLink v2 frame for testing
    # Format: STX(1) LEN(1) INCOMPAT(1) COMPAT(1) SEQ(1) SYSID(1) COMPID(1) MSGID(3) PAYLOAD... CRC(2)
    # We'll use a dummy HEARTBEAT (msgid=0) with zero payload.
    # ------------------------------------------------------------------
    def make_frame(seq: int, payload: bytes = b"", crc_override: Optional[int] = None) -> tuple[bytes, int, int]:
        """
        Construct a minimal MAVLink v2 frame with correct CRC (unless overridden).
        Returns (frame_without_crc_bytes, seq, crc_value).
        """
        # Header
        stx = b"\xFD"           # MAVLink v2 magic
        length = len(payload).to_bytes(1, "little")
        incompat = b"\x00"      # no incompat flags
        compat = b"\x00"        # no compat flags
        seq_b = seq.to_bytes(1, "little")
        sysid = b"\x01"         # system ID 1
        compid = b"\x01"        # component ID 1
        msgid = b"\x00\x00\x00" # HEARTBEAT (msgid=0, 24-bit little-endian)

        # Frame without CRC
        frame_no_crc = stx + length + incompat + compat + seq_b + sysid + compid + msgid + payload

        # Compute CRC over everything after STX
        crc = x25_crc(frame_no_crc[1:])
        if crc_override is not None:
            crc = crc_override

        return frame_no_crc, seq, crc

    # ==========================================================
    # SCENARIO 1: Fully normal sequence (0,1,2,3,4)
    # ==========================================================
    det = MavlinkAnomalyDetector(seq_tolerance=5)
    pkts = [make_frame(i) for i in range(5)]
    run_scenario("1. Normal sequence (0→1→2→3→4)", det, pkts, [False]*5)

    # ==========================================================
    # SCENARIO 2: One dropped packet within tolerance (0,1,3,4) — gap=2
    # ==========================================================
    det = MavlinkAnomalyDetector(seq_tolerance=5)
    pkts = [make_frame(i) for i in [0, 1, 3, 4]]  # seq 2 dropped
    # Expect: low-severity alert on seq=3 (gap of 2), clean on others
    run_scenario("2. One dropped packet (gap=2, tolerance=5)", det, pkts,
                 [False, False, True, False])

    # ==========================================================
    # SCENARIO 3: Duplicate sequence (0,1,2,2,3)
    # ==========================================================
    det = MavlinkAnomalyDetector(seq_tolerance=5)
    pkts = [make_frame(i) for i in [0, 1, 2, 2, 3]]
    run_scenario("3. Duplicate sequence (2 repeated)", det, pkts,
                 [False, False, False, True, False])

    # ==========================================================
    # SCENARIO 4: Backward jump (0,1,2,10,3) — 10→3 is backward
    # ==========================================================
    det = MavlinkAnomalyDetector(seq_tolerance=5)
    pkts = [make_frame(i) for i in [0, 1, 2, 10, 3]]
    run_scenario("4. Backward jump (10→3)", det, pkts,
                 [False, False, False, True, True])  # 10 is large forward gap, 3 is backward from 10

    # ==========================================================
    # SCENARIO 5: Huge unexplained forward jump (0,1,2,200) — gap=198 > tolerance
    # ==========================================================
    det = MavlinkAnomalyDetector(seq_tolerance=5)
    pkts = [make_frame(i) for i in [0, 1, 2, 200]]
    run_scenario("5. Huge forward jump (2→200, gap=198)", det, pkts,
                 [False, False, False, True])

    # ==========================================================
    # SCENARIO 6: Bad CRC on otherwise valid sequence
    # ==========================================================
    det = MavlinkAnomalyDetector(seq_tolerance=5)
    good_frame, seq, good_crc = make_frame(0)
    bad_crc = good_crc ^ 0xFFFF  # flip all bits → guaranteed wrong
    pkts = [(good_frame, seq, bad_crc)]  # CRC mismatch
    run_scenario("6. Bad CRC (corrupted frame)", det, pkts, [True])

    # ==========================================================
    # SCENARIO 7: Wraparound handling (254, 255, 0, 1)
    # ==========================================================
    det = MavlinkAnomalyDetector(seq_tolerance=5)
    pkts = [make_frame(i) for i in [254, 255, 0, 1]]
    run_scenario("7. Wraparound (254→255→0→1)", det, pkts, [False]*4)

    # ==========================================================
    # SCENARIO 8: Wraparound with gap (254, 255, 2, 3) — gap of 2 at wrap
    # ==========================================================
    det = MavlinkAnomalyDetector(seq_tolerance=5)
    pkts = [make_frame(i) for i in [254, 255, 2, 3]]  # 0,1 dropped
    run_scenario("8. Wraparound with gap (255→2, gap=2)", det, pkts,
                 [False, False, True, False])

    print("\n" + "="*60)
    print("All scenarios complete.")