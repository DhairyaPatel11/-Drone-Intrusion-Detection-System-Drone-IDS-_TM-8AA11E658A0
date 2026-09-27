#!/usr/bin/env python3
"""
rf_jamming_detector.py

RF JAMMING / SIGNAL DoS DETECTOR (PHYSICAL LAYER)
=================================================
Layer 4 of the Communication-Attacks IDS pipeline.

This is a PHYSICAL-LAYER detector, fundamentally different from the
packet-content checks (CRC, sequence, signing) used elsewhere — it looks
at signal-quality metrics reported by ArduPilot's RADIO_STATUS message
(msg id 109): rssi, remrssi, noise, remnoise, rxerrors, fixed.
RADIO_STATUS is emitted by SiK-style telemetry radios and IS available in
SITL simulation (a simulated radio with stable, healthy metrics).

Detection principle
--------------------
  1. SNR = rssi - noise            (rssi: received signal strength; noise:
                                     background noise floor, same units)
  2. A sudden, SUSTAINED drop in SNR below the rolling baseline suggests
     jamming or interference.
  3. To keep false positives low, require a SECOND corroborating signal:
     a RISING TREND in rxerrors (receive errors) over the same window.

Why require BOTH signals? (key explainability point for the viva)
  - A lone SNR dip can be innocent: temporary obstruction (a bird, tower),
    distance changes, antenna orientation, multipath fading.
  - A lone rxerror climb can be protocol noise/retransmission.
  - Jamming typically degrades BOTH: the jammer raises the noise floor,
    which collapses SNR, AND corrupts frames, which grows rxerrors.
  So "high" confidence is reserved for the intersection; either alone
  raises a "low" confidence observation worth logging but NOT enough to
  trigger an autonomous defensive response.

Statistics: classical only (no ML). We use a rolling window with
mean/std-dev based anomaly detection (Shewhart control-chart style),
not a fixed hardcoded threshold, so the detector adapts to each flight's
own baseline noise floor.
"""

from __future__ import annotations

import math
import time
from collections import deque
from typing import Deque, Optional


class RFJammingDetector:
    """
    Detects RF jamming / signal DoS from RADIO_STATUS statistics.

    Arguments:
        window_size: number of recent samples kept for statistics.
        snr_std_threshold: how many std-dev below the rolling mean counts
            as an SNR anomaly (Shewhart-style rule; 3.0 is the classic
            control-chart limit).
        min_snr_floor_db: hard backstop — if SNR drops below this absolute
            level it is anomalous regardless of trend (guards against a
            baseline that has already been suppressed by a slow ramp).
        rxerror_slope_threshold: rxerrors slope (per-sample growth) above
            which we flag "rxerror_rising". (last-first)/window_size.
    """

    def __init__(
        self,
        window_size: int = 20,
        snr_std_threshold: float = 3.0,
        min_snr_floor_db: float = 10.0,
        rxerror_slope_threshold: float = 0.5,
    ) -> None:
        assert window_size >= 2, "window_size must be >= 2 for stats"
        self.window_size = window_size
        self.snr_std_threshold = snr_std_threshold
        self.min_snr_floor_db = min_snr_floor_db
        self.rxerror_slope_threshold = rxerror_slope_threshold

        # Rolling windows (classical control-chart style)
        self._snr_window: Deque[float] = deque(maxlen=window_size)
        self._rxerror_window: Deque[int] = deque(maxlen=window_size)

        # Rolling statistics cache (recomputed each check; trivial cost)
        self.rolling_mean_snr: float = 0.0
        self.rolling_std_snr: float = 0.0
        self.rxerror_slope: float = 0.0

    # ------------------------------------------------------------------
    # --- SNR computation ------------------------------------------------
    # ------------------------------------------------------------------
    @staticmethod
    def compute_snr(rssi: float, noise: float) -> float:
        """
        SNR = rssi - noise.

        Units caveat: MAVLink RADIO_STATUS reports rssi/noise as raw
        relative units on a 0-255 scale (per the Mavlink spec), which are
        roughly dBm-like on SiK radios but are NOT absolute dBm. For the
        delta (subtraction) the unit offsets cancel, so SNR computed this
        way is a valid RELATIVE signal-quality metric; absolute
        thresholds (min_snr_floor_db) must be calibrated per radio in use.
        """
        return rssi - noise

    # ------------------------------------------------------------------
    # --- Core check ------------------------------------------------------
    # ------------------------------------------------------------------
    def check(
        self,
        rssi: float,
        noise: float,
        rxerrors: int,
        timestamp: float,
    ) -> Optional[dict]:
        """
        Process one RADIO_STATUS sample and return an alert if jamming
        is suspected.

        Args:
            rssi: received signal strength from RADIO_STATUS (0-255).
            noise: noise floor from RADIO_STATUS (0-255).
            rxerrors: cumulative receive-error counter (monotonic).
            timestamp: wall-clock receive time.

        Returns:
            None when the link looks healthy.
            Alert dict when suspicious:
              {"type": "rf_jamming_suspected",
               "confidence": "high"|"low",
               "snr_db": float,
               "rolling_mean_snr": float,
               "rxerror_slope": float,
               "timestamp": float}
        """
        snr = self.compute_snr(rssi, noise)
        now = timestamp if timestamp else time.time()

        # 1) Update rolling windows -----------------------------------
        self._snr_window.append(snr)
        self._rxerror_window.append(rxerrors)

        # Need enough samples for meaningful statistics
        if len(self._snr_window) < self.window_size:
            return None

        # 2) Rolling mean / std of SNR (Shewhart style) --------------
        mean = sum(self._snr_window) / len(self._snr_window)
        var = sum((x - mean) ** 2 for x in self._snr_window) / len(self._snr_window)
        std = math.sqrt(var)

        # 3) rxerrors trend: simple slope (last - first)/window_size ..
        first = self._rxerror_window[0]
        last = self._rxerror_window[-1]
        slope = (last - first) / self.window_size

        # cache stats for diagnostics/demo output
        self.rolling_mean_snr = mean
        self.rolling_std_snr = std
        self.rxerror_slope = slope

        # 4) SNR anomaly ----------------------------------------------
        #   - hard floor backstop (below absolute level regardless of trend)
        #   - OR statistical: more than N std-dev below the rolling mean
        below_floor = snr < self.min_snr_floor_db
        below_statistical = (std > 1e-9) and (snr < mean - self.snr_std_threshold * std)
        snr_anomaly = below_floor or below_statistical

        # 5) rxerror rising trend -------------------------------------
        rxerror_rising = slope > self.rxerror_slope_threshold

        # 6) Combine ------------------------------------------------
        if not snr_anomaly and not rxerror_rising:
            return None

        # Both together = high confidence; either alone = low
        confidence = "high" if (snr_anomaly and rxerror_rising) else "low"

        return {
            "type": "rf_jamming_suspected",
            "confidence": confidence,
            "snr_db": round(snr, 2),
            "rolling_mean_snr": round(mean, 2),
            "rxerror_slope": round(slope, 3),
            "timestamp": now,
        }

    # ------------------------------------------------------------------
    def reset(self) -> None:
        self._snr_window.clear()
        self._rxerror_window.clear()
        self.rolling_mean_snr = 0.0
        self.rolling_std_snr = 0.0
        self.rxerror_slope = 0.0


# ===========================================================================
# Self-test / demo
# ===========================================================================
if __name__ == "__main__":
    print("=" * 70)
    print("RF JAMMING DETECTOR — SELF TEST")
    print("=" * 70)

    def run_clean_link() -> None:
        """a) Stable link over 30 samples — no alerts."""
        print("\n[a] Clean, stable RF link (expect NO alerts)")
        det = RFJammingDetector()
        alerts = 0
        t = 1000.0
        rxerr = 0                       # healthy radio: errors stay ~0
        for i in range(30):
            rssi = 189 + (i % 3)          # tiny natural wobble
            noise = 30 + (i % 2)
            a = det.check(rssi, noise, rxerr, t + i)
            if a:
                alerts += 1
        print(f"  alerts={alerts}  rolling_mean_snr={det.rolling_mean_snr}")
        print(f"  Scenario a: {'PASS' if alerts == 0 else 'FAIL'}")

    def run_jamming() -> None:
        """b) Jamming: noise floor surges, SNR collapses, rxerrors climb
        -> HIGH confidence partway through."""
        print("\n[b] Jamming: SNR collapse + rxerror climb (expect HIGH partway)")
        det = RFJammingDetector()
        t = 2000.0
        rxerr = 0
        saw_high = False
        for i in range(30):
            # Phase 1 (first 10): clean link. Phase 2: jammer raises the
            # noise floor sharply (SNR -> below hard floor) while rxerrors
            # explode — the "both signals" case.
            if i < 10:
                rssi, noise = 190, 30
                rxerr += 0
            else:
                # Jammer: signal fades a little, noise floor surges.
                # Keep all values inside RADIO_STATUS's 0-255 range.
                rssi = max(190 - 2 * (i - 10), 120)
                noise = min(30 + 15 * (i - 10), 200)
                rxerr += 50 * (i - 10)         # receive errors explode
            a = det.check(rssi, noise, rxerr, t + i)
            if a:
                print(f"  t+{i:2d}: snr={a['snr_db']:6.1f} "
                      f"mean={a['rolling_mean_snr']:6.1f} "
                      f"slope={a['rxerror_slope']:5.2f} conf={a['confidence']}")
                if a["confidence"] == "high":
                    saw_high = True
        print(f"  Scenario b: {'PASS' if saw_high else 'FAIL'} (saw high-confidence alert)")

    def run_obstruction() -> None:
        """c) Brief isolated SNR dip, rxerrors STABLE -> never 'high'."""
        print("\n[c] Brief isolated SNR dip + stable rxerrors (expect low/None, never high)")
        det = RFJammingDetector()
        t = 3000.0
        rxerr = 100                     # constant — no error trend at all
        saw_high = False
        max_conf = "none"
        for i in range(30):
            rssi, noise = 190, 30
            if 12 <= i <= 14:                    # 3-sample obstruction
                rssi = 150                       # 10 dB SNR dip
            a = det.check(rssi, noise, rxerr, t + i)
            if a:
                max_conf = a["confidence"]
                if a["confidence"] == "high":
                    saw_high = True
                print(f"  t+{i:2d}: snr={a['snr_db']:6.1f} "
                      f"mean={a['rolling_mean_snr']:6.1f} "
                      f"slope={a['rxerror_slope']:5.2f} conf={a['confidence']}")
        print(f"  max confidence seen: {max_conf}")
        print(f"  Scenario c: {'PASS' if not saw_high else 'FAIL'} (never reached high)")

    run_clean_link()
    run_jamming()
    run_obstruction()

    print("\n" + "=" * 70)
    print("RF Jamming Detector self-test complete.")
    print("=" * 70)