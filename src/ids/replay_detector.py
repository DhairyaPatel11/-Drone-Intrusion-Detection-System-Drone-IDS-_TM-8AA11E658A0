#!/usr/bin/env python3
"""
replay_detector.py

REPLAY ATTACK DETECTOR — 64-BIT SLIDING-WINDOW ANTI-REPLAY (RFC 4303 / IPsec)
============================================================================
Layer 3 of the Communication-Attacks IDS pipeline.

A replay attack: attacker records a legitimately-valid MAVLink frame
(e.g. an ARM or RTL command) and re-sends it later to trigger unwanted
behaviour. The naive "is this seq newer than the last one" check breaks
under normal conditions because legitimate packets CAN arrive slightly out
of order (reordering, jitter). We need something that tolerates reordering
within a window but rejects duplicates and stale replays outside it.

Sliding-window technique (RFC 4303, section 3.4.3):
  * Maintain:
      - highest_seq: the highest sequence number accepted so far
      - bitmask:      a 64-bit mask; bit i == 1 means "sequence
                      (highest_seq - i) has already been accepted"
  * A new packet seq is ACCEPTED when either:
      - seq > highest_seq      -> window slides forward, bitmask shifts
      - seq within [highest_seq - 63, highest_seq] and its bit is NOT set
  * A new packet seq is REJECTED (flagged replay) when either:
      - seq within the window and its bit IS already set  (duplicate/replay)
      - seq < highest_seq - 63 (too old — replay from long ago)

Correctness note for the viva: this is the same anti-replay algorithm used
by IPsec ESP/AH to defeat message replay, adapted to MAVLink's per-link
sequence counters. It is O(1) per packet — no scanning, only bitwise ops.

A second INDEPENDENT signal — per-message-type timestamp freshness — is
implemented in TimestampFreshnessChecker. Both are merged by ReplayDetector.
"""

from __future__ import annotations

import time
from collections import deque
from typing import Deque, Dict, List, Optional

# ---------------------------------------------------------------------------
# Sliding-window anti-replay core
# ---------------------------------------------------------------------------
class SlidingWindowAntiReplay:
    """
    RFC 4303-style sliding-window anti-replay for sequence numbers.

    Attributes:
        highest_seq: Highest sequence number accepted so far (unwrapped).
        bitmask:     Python int used as a bit-array (LSB == most recent).
        window_size: Number of sequence positions tracked (default 64).
        seq_bits:    Width of the native sequence field (default 32, wraps
                     at 2**32). MAVLink wire seq is 8-bit (seq_bits=8);
                     higher layers often use 32-bit timestamps or 16-bit
                     counters — this stays configurable.
    """

    __slots__ = ("window_size", "seq_bits", "seq_mod", "highest_seq", "bitmask")

    def __init__(self, window_size: int = 64, seq_bits: int = 32) -> None:
        assert 1 <= window_size <= 64, "window_size must be in [1, 64]"
        assert 1 <= seq_bits <= 32, "seq_bits must be in [1, 32]"
        self.window_size = window_size
        self.seq_bits = seq_bits
        self.seq_mod = 1 << seq_bits          # wrap modulus, e.g. 2**32
        self.highest_seq: Optional[int] = None   # unwrapped: not modulo-limited
        self.bitmask: int = 0                     # LSB == highest_seq slot

    # ------------------------------------------------------------------
    # --- Modular helpers ----------------------------------------------
    # ------------------------------------------------------------------
    def _unwrap(self, seq: int) -> int:
        """
        Convert a wrapped sequence number to a monotonically increasing
        "unwrapped" value so the window logic never sees a wraparound.

        Given the current highest_seq, we find the multiple of seq_mod
        that makes `seq` closest to highest_seq (within +/- seq_mod/2).
        This is exactly how IPsec handles 32-bit counter wraparound.

        Returns the unwrapped value.
        """
        if self.highest_seq is None:
            return seq

        # Signed distance from highest_seq's raw residue:
        raw_high = self.highest_seq % self.seq_mod
        diff = (seq - raw_high) % self.seq_mod      # 0..seq_mod-1
        if diff > self.seq_mod // 2:                 # treat as negative jump
            diff -= self.seq_mod                     # now -seq_mod/2..seq_mod/2
        return self.highest_seq + diff

    # ------------------------------------------------------------------
    # --- Core check ----------------------------------------------------
    # ------------------------------------------------------------------
    def check(self, seq: int) -> Optional[dict]:
        """
        Validate one incoming sequence number against the window.

        Args:
            seq: raw incoming sequence number (0..seq_mod-1).

        Returns:
            None if ACCEPTED.
            Alert dict if REJECTED:
                {"reason": "replay_detected"|"stale_packet",
                 "seq": int, "window_position": int, "timestamp": float}
              - window_position: distance below highest_seq (0 = most
                recent slot). For stale packets this is >= window_size.
        """
        now = time.time()
        observed = self._unwrap(seq)

        # --- First packet ever: initialise window ---------------------
        if self.highest_seq is None:
            self.highest_seq = observed
            self.bitmask = 1 << 0                  # slot 0 (highest) accepted
            return None

        # --- Case 1: seq HIGHER than window top -> slide window --------
        if observed > self.highest_seq:
            gap = observed - self.highest_seq
            if gap >= self.window_size:
                # Everything older than the window: fresh window, only this seq
                self.bitmask = 1 << 0
            else:
                # Shift existing accepted bits left by `gap` positions and
                # set slot 0. Keep only window_size LSBs.
                self.bitmask = ((self.bitmask << gap) | 1) & ((1 << self.window_size) - 1)
            self.highest_seq = observed
            return None

        # --- Case 2: seq BELOW the window -> stale replay --------------
        if observed <= self.highest_seq - self.window_size:
            return {
                "reason": "stale_packet",
                "seq": seq,
                "window_position": self.highest_seq - observed,
                "timestamp": now,
            }

        # --- Case 3: inside the window -> check the bit ----------------
        position = self.highest_seq - observed      # 0..window_size-1
        bit = 1 << position
        if self.bitmask & bit:
            # Bit already set -> this exact packet was seen before
            return {
                "reason": "replay_detected",
                "seq": seq,
                "window_position": position,
                "timestamp": now,
            }
        # Not seen -> accept and mark the slot
        self.bitmask |= bit
        return None

    # ------------------------------------------------------------------
    def reset(self) -> None:
        """Clear state (e.g. MAVLink restart / new link)."""
        self.highest_seq = None
        self.bitmask = 0


# ---------------------------------------------------------------------------
# Per-message-type timestamp freshness (second, independent signal)
# ---------------------------------------------------------------------------
class TimestampFreshnessChecker:
    """
    Tracks the last-seen timestamp PER message type and flags:
      - timestamps that are NOT strictly newer than the last seen for that
        type (replayed/stale timestamps)
      - packets whose age (arrival_time - msg_timestamp) exceeds max age.

    Why per-type? Because different message families carry timestamps from
    different clocks/rates (e.g. SYS_STATUS vs GLOBAL_POSITION_INT vs
    RADIO_STATUS feed at different rates), a single global clock would
    generate false positives.
    """

    def __init__(self, max_age_seconds: float = 2.0) -> None:
        self.max_age_seconds = max_age_seconds
        self._last_seen: Dict[str, float] = {}

    # ------------------------------------------------------------------
    def check(
        self,
        msg_type: str,
        msg_timestamp: float,
        arrival_time: float,
    ) -> Optional[dict]:
        """
        Args:
            msg_type: MAVLink message type name, e.g. "HEARTBEAT".
            msg_timestamp: timestamp carried inside the message (seconds).
            arrival_time: wall-clock arrival time (time.time()).

        Returns:
            None if fresh; alert dict otherwise:
                {"reason": "timestamp_not_newer" | "stale_timestamp",
                 "msg_type": str, "timestamp": float}
        """
        now = arrival_time if arrival_time else time.time()

        # --- Case A: not strictly newer than last seen for this type ---
        last = self._last_seen.get(msg_type)
        if last is not None and msg_timestamp <= last:
            return {
                "reason": "timestamp_not_newer",
                "msg_type": msg_type,
                "timestamp": now,
            }

        # --- Case B: age exceeds max allowed ---------------------------
        age = now - msg_timestamp
        if age > self.max_age_seconds:
            return {
                "reason": "stale_timestamp",
                "msg_type": msg_type,
                "timestamp": now,
            }

        # Fresh — record and accept
        self._last_seen[msg_type] = msg_timestamp
        return None

    # ------------------------------------------------------------------
    def reset(self) -> None:
        self._last_seen.clear()


# ---------------------------------------------------------------------------
# Combined facade used by the pipeline
# ---------------------------------------------------------------------------
class ReplayDetector:
    """
    Runs BOTH anti-replay signals for each packet:
      1. SlidingWindowAntiReplay      (sequence-based)
      2. TimestampFreshnessChecker    (time-based)

    Returns a merged list of alerts (empty when clean).
    """

    def __init__(
        self,
        window_size: int = 64,
        seq_bits: int = 32,
        max_age_seconds: float = 2.0,
    ) -> None:
        self.sequence_checker = SlidingWindowAntiReplay(window_size, seq_bits)
        self.freshness_checker = TimestampFreshnessChecker(max_age_seconds)

    # ------------------------------------------------------------------
    def check(
        self,
        msg_type: str,
        seq: int,
        msg_timestamp: float,
        arrival_time: Optional[float] = None,
    ) -> List[dict]:
        """
        Full replay analysis of one packet.

        Args:
            msg_type: MAVLink message type.
            seq: sequence number (wraps at 2**seq_bits).
            msg_timestamp: message-carrying timestamp (s), 0 if none.
            arrival_time: wall clock at receive; defaults to time.time().

        Returns:
            List of alert dicts. Empty list == clean.
        """
        now = arrival_time if arrival_time is not None else time.time()
        alerts: List[dict] = []

        # 1. Sequence-based anti-replay
        seq_alert = self.sequence_checker.check(seq)
        if seq_alert is not None:
            alerts.append(seq_alert)

        # 2. Timestamp freshness (skip messages with no timestamp field)
        if msg_timestamp and msg_timestamp > 0:
            ts_alert = self.freshness_checker.check(msg_type, msg_timestamp, now)
            if ts_alert is not None:
                alerts.append(ts_alert)

        return alerts

    # ------------------------------------------------------------------
    def reset(self) -> None:
        self.sequence_checker.reset()
        self.freshness_checker.reset()


# ===========================================================================
# Self-test / demo
# ===========================================================================
if __name__ == "__main__":
    print("=" * 70)
    print("REPLAY DETECTOR — SLIDING-WINDOW SELF TEST")
    print("=" * 70)

    def show_result(name: str, alerts_expected_none: bool, alerts: List[dict]) -> None:
        status = "PASS" if (alerts_expected_none == (len(alerts) == 0)) else "FAIL"
        print(f"  [{status}] {name:45s} -> alerts={len(alerts)}")
        for a in alerts:
            print(f"          {a}")
        return status

    def check_rf(rd, mt, seq, ts, arr):
        """Helper: pass matching arrival time so the freshness check does
        not inject a spurious 'stale_timestamp' into pure-sequence tests."""
        return rd.check(mt, seq, ts, arrival_time=arr)

    # --- a) Normal in-order sequence: no alerts -------------------------
    # Use a real now-baseline so message timestamps are internally consistent
    # with arrival time (test isolates the SEQUENCE logic, not freshness).
    print("\n[a] Normal in-order sequence (no alerts expected)")
    rd = ReplayDetector(seq_bits=8)          # use 8-bit wrap to keep test short
    base = time.time()
    for i in range(5):
        show_result(f"seq={i}", True, check_rf(rd, "HEARTBEAT", i, base + i, base + i))

    # --- b) Reordering 10, 12, 11, 13 -> no false alerts ----------------
    print("\n[b] Legitimate reordering 10,12,11,13 (no alerts expected)")
    rd = ReplayDetector(seq_bits=8)
    base = time.time()
    order = [10, 12, 11, 13]
    for j, s in enumerate(order):
        show_result(f"seq={s}", True, check_rf(rd, "HEARTBEAT", s, base + j, base + j))

    # --- c) Exact duplicate -> replay_detected --------------------------
    print("\n[c] Exact duplicate seq=12 twice (alert expected on 2nd)")
    rd = ReplayDetector(seq_bits=8)
    base = time.time()
    for s in (10, 11, 12):
        check_rf(rd, "HEARTBEAT", s, base + s, base + s)
    res = show_result("duplicate 12", False, check_rf(rd, "HEARTBEAT", 12, base + 12, base + 12))
    assert res == "PASS"

    # --- d) Very old seq outside window -> stale_packet -----------------
    print("\n[d] Old seq=3 after window slid to 100 (stale expected)")
    rd = ReplayDetector(window_size=64, seq_bits=32)
    base = time.time()
    for s in range(95, 101):
        check_rf(rd, "HEARTBEAT", s, base + s, base + s)
    res = show_result("stale seq=3", False, check_rf(rd, "HEARTBEAT", 3, base + 200, base + 200))
    assert res == "PASS"

    # --- e) Wraparound: 254,255,0,1 (8-bit) -> no false alerts ----------
    print("\n[e] Sequence wraparound 254,255,0,1 (no alerts expected)")
    rd = ReplayDetector(seq_bits=8)
    base = time.time()
    for j, s in enumerate((254, 255, 0, 1)):
        show_result(f"seq={s}", True, check_rf(rd, "HEARTBEAT", s, base + j, base + j))

    # --- Bonus: stale timestamp ------------------------------------------
    print("\n[f] Old timestamp replay (freshness alert expected)")
    rd = ReplayDetector(seq_bits=8, max_age_seconds=2.0)
    now = time.time()
    check_rf(rd, "HEARTBEAT", 1, now, now)          # fresh
    res = show_result("old ts", False, check_rf(rd, "HEARTBEAT", 2, now - 30.0, now))
    assert res == "PASS"

    print("\n" + "=" * 70)
    print("Replay Detector self-test complete.")
    print("=" * 70)