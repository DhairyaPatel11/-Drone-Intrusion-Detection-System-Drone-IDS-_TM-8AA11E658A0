#!/usr/bin/env python3
"""
Demo attack injector — feeds synthetic attack packets into the IDS pipeline
and prints alerts in real time. No SITL, no network, no firewall issues.

Usage:
    python scripts/inject_attacks.py                    # all attacks, 2s each
    python scripts/inject_attacks.py --list             # show available attacks
    python scripts/inject_attacks.py --attack gps_spoofing --duration 10
    python scripts/inject_attacks.py --loop             # cycle forever
    python scripts/inject_attacks.py --rate 20          # packets per second
    python scripts/inject_attacks.py --connect udp:0.0.0.0:14550  # live MAVLink (optional)
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

# Ensure repo root is on path when run from scripts/
REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from benchmark import attacks
from ids.ids_pipeline import IDSPipeline, message_from_pymavlink

try:
    from pymavlink import mavutil
    HAVE_PYMAVLINK = True
except ImportError:
    HAVE_PYMAVLINK = False


ATTACK_GENERATORS = {
    # Communication attacks
    "crc": attacks.crc_attack,
    "replay": attacks.replay_attack,
    "unauthorized": attacks.unauthorized_attack,
    "state_violation": attacks.state_violation_attack,
    "rf_jam": attacks.rf_jam_attack,

    # Navigation attacks (subset that work offline)
    "gps_spoofing": attacks.gps_spoofing_attack,
    "baro_spoofing": attacks.baro_spoofing_attack,
    "optical_flow_anomaly": attacks.optical_flow_anomaly_attack,
    "ekf_innovation_error": attacks.ekf_innovation_error_attack,
    "attitude_tracking_error": attacks.attitude_tracking_error_attack,
    "actuator_asymmetry": attacks.actuator_asymmetry_attack,
    "geofence_violation": attacks.geofence_violation_attack,
    "rtl_no_gps_lock": attacks.rtl_no_gps_lock_attack,
}


def make_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Inject attacks into Drone IDS pipeline")
    p.add_argument("--list", action="store_true", help="List available attacks and exit")
    p.add_argument("--attack", choices=sorted(ATTACK_GENERATORS.keys()),
                   help="Single attack to run (default: cycle all)")
    p.add_argument("--duration", type=float, default=3.0,
                   help="Seconds per attack (default: 3)")
    p.add_argument("--rate", type=int, default=10,
                   help="Packets per second (default: 10)")
    p.add_argument("--loop", action="store_true",
                   help="Cycle attacks forever (Ctrl-C to stop)")
    p.add_argument("--run-all", action="store_true",
                   help="Run each attack once sequentially, then exit")
    p.add_argument("--report", type=str, metavar="FILE",
                   help="Save detailed detection report to FILE (JSON)")
    p.add_argument("--connect", type=str,
                   help="Live MAVLink connection string (e.g. udp:0.0.0.0:14550)")
    p.add_argument("--benign-ratio", type=float, default=0.3,
                   help="Fraction of benign packets mixed in (default: 0.3)")
    p.add_argument("--quiet", action="store_true",
                   help="Suppress DEBUG logs from detectors")
    return p


def run_live_capture(conn_str: str, pipe: IDSPipeline, rate: int, stop_event=None):
    """Capture live MAVLink and feed into pipeline."""
    if not HAVE_PYMAVLINK:
        print("pymavlink not installed; cannot use --connect", file=sys.stderr)
        return

    print(f"Connecting to {conn_str}...")
    m = mavutil.mavlink_connection(conn_str)
    m.wait_heartbeat()
    print(f"Heartbeat from system {m.target_system}")

    interval = 1.0 / rate if rate else 0
    next_t = time.time()
    try:
        while stop_event is None or not stop_event.is_set():
            msg = m.recv_match(blocking=True, timeout=1)
            if msg:
                pipe.ingest(message_from_pymavlink(msg))
            if rate:
                next_t += interval
                time.sleep(max(0, next_t - time.time()))
    except KeyboardInterrupt:
        pass


def run_synthetic(pipe: IDSPipeline, attack_name: str | None,
                  duration: float, rate: int, benign_ratio: float, loop: bool,
                  collect_report: bool = False):
    """Generate synthetic attacks and feed into pipeline."""
    import random

    generators = [ATTACK_GENERATORS[attack_name]] if attack_name else list(ATTACK_GENERATORS.values())
    names = [attack_name] if attack_name else list(ATTACK_GENERATORS.keys())

    interval = 1.0 / rate if rate else 0
    print(f"Starting synthetic injection: {len(generators)} attack(s), "
          f"{duration}s each, {rate} pkt/s, {benign_ratio:.0%} benign")
    print("Press Ctrl-C to stop.\n")

    report_data = [] if collect_report else None

    try:
        while True:
            for gen, name in zip(generators, names):
                print(f"\n{'='*60}")
                print(f">>> ATTACK: {name.upper()} ({duration}s)")
                print(f"{'='*60}")

                attack_start = time.time()
                pkt_count = 0
                alert_count = 0
                first_detection_time = None
                detections = [] if collect_report else None

                while time.time() - attack_start < duration:
                    # Mix benign packets
                    if random.random() < benign_ratio:
                        frames = attacks.benign_stream(1)
                    else:
                        frames, _ = gen()

                    for frame in frames:
                        res = pipe.ingest(frame)
                        pkt_count += 1
                        if res:
                            alert_count += len(res)
                            for a in res:
                                attack_class = a.get('attack_class', '?')
                                reason = a.get('reason', '?')
                                severity = a.get('severity', '?')
                                layer = a.get('layer', '?')
                                print(f"  [ALERT] {attack_class}: {reason} "
                                      f"| severity={severity} | layer={layer}")
                                if collect_report:
                                    elapsed = (time.time() - attack_start) * 1000  # ms
                                    if first_detection_time is None:
                                        first_detection_time = elapsed
                                    detections.append({
                                        "attack_class": attack_class,
                                        "reason": reason,
                                        "severity": severity,
                                        "layer": layer,
                                        "detection_time_ms": round(elapsed, 2)
                                    })

                    if rate:
                        time.sleep(interval)

                print(f"  Packets: {pkt_count} | Alerts fired: {alert_count}")
                if first_detection_time is not None:
                    print(f"  First detection: {first_detection_time:.1f} ms after attack start")

                if collect_report:
                    report_data.append({
                        "attack_name": name,
                        "duration_s": duration,
                        "rate_pkt_s": rate,
                        "benign_ratio": benign_ratio,
                        "packets_sent": pkt_count,
                        "alerts_fired": alert_count,
                        "first_detection_ms": round(first_detection_time, 1) if first_detection_time else None,
                        "detections": detections
                    })

            if not loop:
                break

    except KeyboardInterrupt:
        print("\n[Stopped by user]")

    return report_data


def main():
    args = make_parser().parse_args()

    if args.quiet:
        import logging
        logging.disable(logging.CRITICAL)

    if args.list:
        print("Available attacks:")
        for k in sorted(ATTACK_GENERATORS.keys()):
            print(f"  {k}")
        return 0

    pipe = IDSPipeline()

    if args.connect:
        run_live_capture(args.connect, pipe, args.rate)
    elif args.run_all:
        report = run_synthetic(pipe, None, args.duration, args.rate,
                               args.benign_ratio, loop=False,
                               collect_report=args.report is not None)
        if args.report and report:
            write_report(args.report, report)
    else:
        run_synthetic(pipe, args.attack, args.duration, args.rate,
                      args.benign_ratio, args.loop)

    return 0


def write_report(path: str, report_data: list):
    """Write detailed detection report to JSON file."""
    import json
    summary = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_attacks_tested": len(report_data),
        "attacks": report_data
    }
    with open(path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\n[REPORT] Detailed report saved to: {path}")


if __name__ == "__main__":
    sys.exit(main())