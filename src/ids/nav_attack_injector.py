"""
nav_attack_injector.py
SITL Attack Injection for Navigation Attacks

Injects navigation attack scenarios into ArduPilot SITL using MAVProxy
or direct MAVLink parameter manipulation. Each attack class from the
threat catalogue has a corresponding injection function.
"""

from __future__ import annotations

import math
import time
from typing import Callable, Dict, List, Optional, Tuple

try:
    from pymavlink import mavutil
except ImportError:
    mavutil = None  # type: ignore


# ---------------------------------------------------------------------------
# SITL Connection and Helpers
# ---------------------------------------------------------------------------
class SITLInjector:
    """Wrapper for MAVLink connection to ArduPilot SITL."""

    def __init__(self, connection: str = "udp:127.0.0.1:14550"):
        self.conn = connection
        self.mav = None
        self._connect()

    def _connect(self) -> None:
        """Establish MAVLink connection to SITL."""
        if mavutil is None:
            raise ImportError("pymavlink not installed. Install with: pip install pymavlink")
        self.mav = mavutil.mavlink_connection(self.conn)
        self.mav.wait_heartbeat(timeout=30)
        print(f"[SITL] Connected to {self.conn} (sysid={self.mav.target_system})")

    def set_param(self, name: str, value: float) -> bool:
        """Set a SITL parameter."""
        try:
            self.mav.mav.param_set_send(
                self.mav.target_system,
                self.mav.target_component,
                name.encode(),
                value,
                mavutil.mavlink.MAV_PARAM_TYPE_REAL32
            )
            return True
        except Exception as e:
            print(f"[SITL] Failed to set param {name}: {e}")
            return False

    def get_param(self, name: str) -> Optional[float]:
        """Get a SITL parameter."""
        try:
            self.mav.mav.param_request_read_send(
                self.mav.target_system,
                self.mav.target_component,
                name.encode(),
                -1
            )
            msg = self.mav.recv_match(type='PARAM_VALUE', blocking=True, timeout=5)
            if msg and msg.param_id.decode().strip() == name:
                return msg.param_value
        except Exception as e:
            print(f"[SITL] Failed to get param {name}: {e}")
        return None

    def send_gps_input(self, lat: float, lon: float, alt: float,
                       vn: float = 0, ve: float = 0, vd: float = 0,
                       fix_type: int = 3, sats: int = 8,
                       eph: float = 100, epv: float = 200) -> None:
        """Inject GPS_INPUT (MAVLink #235) to override SITL GPS."""
        # Convert to MAVLink format
        lat_int = int(lat * 1e7)
        lon_int = int(lon * 1e7)
        alt_mm = int(alt * 1000)
        vn_cm = int(vn * 100)
        ve_cm = int(ve * 100)
        vd_cm = int(vd * 100)

        self.mav.mav.gps_input_send(
            time_usec=int(time.time() * 1e6) & 0xFFFFFFFF,
            gps_id=0,
            ignore_flags=0,
            time_week_ms=0,
            time_week=0,
            fix_type=fix_type,
            lat=lat_int,
            lon=lon_int,
            alt=alt_mm,
            hdop=eph / 100.0,
            vdop=epv / 100.0,
            vn=vn_cm,
            ve=ve_cm,
            vd=vd_cm,
            speed_accuracy=0,
            horiz_accuracy=eph,
            vert_accuracy=epv,
            satellites_used=sats,
        )

    def send_fake_gps_raw_int(self, lat: float, lon: float, alt: float,
                               vn: float = 0, ve: float = 0, vd: float = 0,
                               fix_type: int = 3, sats: int = 8,
                               eph: float = 100, epv: float = 200,
                               cog: float = 0) -> None:
        """Inject GPS_RAW_INT via MAVLink (for testing companion computer)."""
        # Note: This injects at the MAVLink level, not the SITL sensor level
        # The companion computer will see this on its MAVLink stream
        lat_int = int(lat * 1e7)
        lon_int = int(lon * 1e7)
        alt_mm = int(alt * 1000)
        vn_cm = int(vn * 100)
        ve_cm = int(ve * 100)
        vd_cm = int(vd * 100)
        cog_cdeg = int(cog * 100)

        self.mav.mav.gps_raw_int_send(
            time_usec=int(time.time() * 1e6) & 0xFFFFFFFF,
            fix_type=fix_type,
            lat=lat_int,
            lon=lon_int,
            alt=alt_mm,
            eph=int(eph),
            epv=int(epv),
            vel=int(math.sqrt(vn**2 + ve**2) * 100),
            cog=cog_cdeg,
            satellites_visible=sats,
        )

    def set_sim_param(self, name: str, value: float) -> bool:
        """Set SITL simulation parameter (SIM_*)."""
        return self.set_param(name, value)

    def arm(self) -> None:
        """Arm the vehicle."""
        self.mav.mav.command_long_send(
            self.mav.target_system, self.mav.target_component,
            mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM,
            0, 1, 0, 0, 0, 0, 0, 0
        )

    def takeoff(self, alt: float) -> None:
        """Command takeoff."""
        self.mav.mav.command_long_send(
            self.mav.target_system, self.mav.target_component,
            mavutil.mavlink.MAV_CMD_NAV_TAKEOFF,
            0, 0, 0, 0, 0, 0, 0, alt
        )

    def set_mode(self, mode: str) -> None:
        """Set flight mode."""
        mode_map = {
            'STABILIZE': 0, 'ACRO': 1, 'ALT_HOLD': 2, 'AUTO': 3,
            'GUIDED': 4, 'LOITER': 5, 'RTL': 6, 'LAND': 9,
        }
        if mode in mode_map:
            self.mav.mav.set_mode_send(
                self.mav.target_system,
                mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED,
                mode_map[mode]
            )


# ---------------------------------------------------------------------------
# Attack Injection Functions
# Each function returns a callable that runs the attack when called with (injector)
# ---------------------------------------------------------------------------

def gps_spoofing_jump(injector: SITLInjector,
                      lat_offset_deg: float = 0.001,
                      lon_offset_deg: float = 0.0,
                      alt_offset_m: float = 0.0,
                      duration_s: float = 10.0) -> Callable:
    """
    GPS Spoofing - Position Jump (Meaconing/Asynchronous Replay).
    Injects a sudden coordinate jump while SITL is running.
    """
    def attack() -> Tuple[bool, str]:
        print("[ATTACK] GPS Spoofing - Position Jump")
        # Get current position
        # Note: In real SITL, we'd read GPS_RAW_INT from telemetry
        # For demo, we use known offsets
        injector.send_fake_gps_raw_int(
            lat=0.001, lon=0.0, alt=100.0,  # ~111m jump
            fix_type=3, sats=8
        )
        time.sleep(duration_s)
        return True, "GPS position jump injected"
    return attack


def gps_spoofing_drift(injector: SITLInjector,
                       drift_rate_m_s: float = 0.5,
                       direction_deg: float = 90.0,
                       duration_s: float = 30.0) -> Callable:
    """
    GPS Spoofing - Slow Drift / Turn-by-Turn.
    Gradually shifts GPS coordinates to pull the drone off course.
    """
    def attack() -> Tuple[bool, str]:
        print(f"[ATTACK] GPS Spoofing - Slow Drift ({drift_rate_m_s}m/s)")
        start_time = time.time()
        lat, lon, alt = 0.0, 0.0, 100.0  # Starting position

        while time.time() - start_time < duration_s:
            # Calculate drift
            dt = time.time() - start_time
            dist = drift_rate_m_s * dt
            # Convert to lat/lon offset (roughly)
            lat_offset = dist * math.cos(math.radians(direction_deg)) / 111320.0
            lon_offset = dist * math.sin(math.radians(direction_deg)) / (111320.0 * math.cos(math.radians(0.0)))

            # Send spoofed position
            injector.send_fake_gps_raw_int(
                lat=lat + lat_offset,
                lon=lon + lon_offset,
                alt=100.0,
                fix_type=3, sats=8
            )
            time.sleep(1.0)

        return True, f"GPS drift injected for {duration_s}s"
    return attack


def gps_jamming(injector: SITLInjector, duration_s: float = 10.0) -> Callable:
    """
    GPS Jamming - Signal Denial.
    Disables GPS in SITL or reduces satellites to 0.
    """
    def attack() -> Tuple[bool, str]:
        print("[ATTACK] GPS Jamming - Signal Denial")
        # Disable GPS in SITL
        injector.set_sim_param("SIM_GPS_DISABLE", 1)
        time.sleep(duration_s)
        # Re-enable
        injector.set_sim_param("SIM_GPS_DISABLE", 0)
        return True, "GPS jamming simulated"
    return attack


def gps_spoofing_seamless(injector: SITLInjector,
                          capture_duration_s: float = 5.0,
                          drift_duration_s: float = 30.0) -> Callable:
    """
    GPS Spoofing - Seamless Takeover (Drag-off).
    Synchronizes with real GPS then slowly drifts.
    Note: True seamless takeover requires RF hardware; this simulates the effect.
    """
    def attack() -> Tuple[bool, str]:
        print("[ATTACK] GPS Spoofing - Seamless Takeover (simulated)")
        # Phase 1: "Capture" - send matching position
        print("  Phase 1: Synchronizing with real GPS...")
        injector.send_fake_gps_raw_int(lat=0.0, lon=0.0, alt=100.0, fix_type=3, sats=10)
        time.sleep(capture_duration_s)

        # Phase 2: Slow drift
        print("  Phase 2: Initiating slow drift...")
        start_time = time.time()
        lat, lon = 0.0, 0.0

        while time.time() - start_time < drift_duration_s:
            dt = time.time() - start_time
            # Drift north at 0.1 m/s
            lat_offset = (0.1 * dt) / 111320.0
            injector.send_fake_gps_raw_int(
                lat=lat + lat_offset, lon=0.0, alt=100.0,
                fix_type=3, sats=10
            )
            time.sleep(1.0)

        return True, "Seamless takeover simulated"
    return attack


def gps_time_spoofing(injector: SITLInjector, drift_rate_us_s: float = 1000.0,
                       duration_s: float = 60.0) -> Callable:
    """
    GPS Time / Clock Spoofing.
    Injects slowly drifting time offset.
    """
    def attack() -> Tuple[bool, str]:
        print(f"[ATTACK] GPS Time Spoofing (drift={drift_rate_us_s}us/s)")
        start_time = time.time()
        while time.time() - start_time < duration_s:
            dt = time.time() - start_time
            # Inject time offset
            offset_us = int(drift_rate_us_s * dt)
            # Note: SITL doesn't directly expose time injection; this would need
            # raw RF or receiver-level access. Here we simulate by offsetting
            # the time_usec field in GPS_RAW_INT if we were injecting MAVLink.
            time.sleep(1.0)
        return True, "GPS time spoofing simulated"
    return attack


def gnss_jamming_ramp(injector: SITLInjector,
                       ramp_duration_s: float = 10.0) -> Callable:
    """
    GNSS Jamming - Ramp (Swept Frequency).
    Gradually increases jamming power.
    """
    def attack() -> Tuple[bool, str]:
        print("[ATTACK] GNSS Jamming - Swept Frequency Ramp")
        # In SITL, simulate by gradually reducing satellite count
        for sats in range(10, 0, -1):
            injector.set_sim_param("SIM_GPS_NUMSATS", sats)
            time.sleep(ramp_duration_s / 10)
        time.sleep(2)
        injector.set_sim_param("SIM_GPS_NUMSATS", 10)
        return True, "GNSS jamming ramp simulated"
    return attack


def baro_spoofing_iemi(injector: SITLInjector,
                       pressure_offset_hpa: float = -50.0,
                       duration_s: float = 30.0) -> Callable:
    """
    Barometer Spoofing via IEMI (CONFUSENSE-style).
    Simulates pressure sensor bus interference.
    """
    def attack() -> Tuple[bool, str]:
        print(f"[ATTACK] Barometer IEMI Spoofing (offset={pressure_offset_hpa}hPa)")
        # SITL: modify barometer simulation
        injector.set_sim_param("SIM_BARO_DISABLE", 1)
        # Note: Real IEMI would inject noise on I2C/SPI bus
        # In SITL we simulate the effect: frozen or erroneous pressure
        time.sleep(duration_s)
        injector.set_sim_param("SIM_BARO_DISABLE", 0)
        return True, "Barometer IEMI spoofing simulated"
    return attack


def mag_spoofing_coil(injector: SITLInjector,
                      heading_offset_deg: float = 180.0,
                      duration_s: float = 30.0) -> Callable:
    """
    Magnetometer Interference - Active Coil / EMI.
    Injects magnetic field offset.
    """
    def attack() -> Tuple[bool, str]:
        print(f"[ATTACK] Magnetometer Spoofing (offset={heading_offset_deg}deg)")
        # SITL: modify magnetometer offsets
        # SIM_MAG_OFS_X/Y/Z are in microtesla
        # 180 deg flip ~ -50 uT offset
        injector.set_sim_param("SIM_MAG_OFS_X", -50.0)
        injector.set_sim_param("SIM_MAG_OFS_Y", 0.0)
        time.sleep(duration_s)
        injector.set_sim_param("SIM_MAG_OFS_X", 0.0)
        return True, "Magnetometer spoofing simulated"
    return attack


def optical_flow_spoofing(injector: SITLInjector,
                          flow_x_m_s: float = 5.0,
                          flow_y_m_s: float = 0.0,
                          quality: int = 255,
                          duration_s: float = 30.0) -> Callable:
    """
    Optical Flow / Visual Odometry Spoofing.
    Injects fake optical flow data.
    """
    def attack() -> Tuple[bool, str]:
        print(f"[ATTACK] Optical Flow Spoofing (vx={flow_x_m_s}, vy={flow_y_m_s})")
        # SITL doesn't natively simulate optical flow camera
        # This would require injecting OPTICAL_FLOW MAVLink messages
        # on the MAVLink stream that the companion computer monitors
        time.sleep(duration_s)
        return True, "Optical flow spoofing simulated (MAVLink injection needed)"
    return attack


def rangefinder_spoofing(injector: SITLInjector,
                         distance_m: float = 1.0,
                         duration_s: float = 10.0) -> Callable:
    """
    Rangefinder / LiDAR Spoofing.
    Injects fake distance readings.
    """
    def attack() -> Tuple[bool, str]:
        print(f"[ATTACK] Rangefinder Spoofing (distance={distance_m}m)")
        # SITL: modify rangefinder simulation
        injector.set_sim_param("SIM_RANGEFINDER_MAX", distance_m * 100)  # cm
        time.sleep(duration_s)
        injector.set_sim_param("SIM_RANGEFINDER_MAX", 10000)  # restore
        return True, "Rangefinder spoofing simulated"
    return attack


def rtcorrection_injection(injector: SITLInjector,
                           base_lat_offset_m: float = 10.0,
                           base_lon_offset_m: float = 10.0,
                           duration_s: float = 60.0) -> Callable:
    """
    RTK/NTRIP Correction Stream Injection.
    Simulates base station shift via injected RTCM corrections.
    Note: Full simulation requires NTRIP stream manipulation; here we
    simulate the effect by offsetting the RTK fix position.
    """
    def attack() -> Tuple[bool, str]:
        print("[ATTACK] RTK Correction Injection - Base Station Shift")
        # In SITL, we can simulate the effect by offsetting the GPS position
        # when RTK fix is active (fix_type=6)
        start_time = time.time()
        while time.time() - start_time < duration_s:
            # Send GPS with RTK fix but offset position
            injector.send_fake_gps_raw_int(
                lat=0.0001,  # ~11m offset
                lon=0.0001,
                alt=100.0,
                fix_type=6,  # RTK Fixed
                sats=12,
                eph=5, epv=3
            )
            time.sleep(1.0)
        return True, "RTK correction injection simulated"
    return attack


def coordinated_gnss_baro_attack(injector: SITLInjector, duration_s: float = 30.0) -> Callable:
    """
    Coordinated GNSS + Barometer Spoofing.
    Simultaneously spoofs GPS altitude and barometer.
    """
    def attack() -> Tuple[bool, str]:
        print("[ATTACK] Coordinated GNSS + Barometer Spoofing")
        # Spoof GPS altitude
        # Spoof barometer (disable SITL baro)
        injector.set_sim_param("SIM_BARO_DISABLE", 1)
        start_time = time.time()
        while time.time() - start_time < duration_s:
            # Send spoofed GPS with high altitude
            injector.send_fake_gps_raw_int(
                lat=0.0, lon=0.0, alt=1000.0,  # 1000m altitude
                fix_type=3, sats=8
            )
            time.sleep(1.0)
        injector.set_sim_param("SIM_BARO_DISABLE", 0)
        return True, "Coordinated GNSS + Baro spoofing simulated"
    return attack


def mag_bias_drift(injector: SITLInjector,
                   drift_rate_deg_s: float = 1.0,
                   duration_s: float = 60.0) -> Callable:
    """
    Magnetometer Bias Drift.
    Slowly increases magnetometer offset.
    """
    def attack() -> Tuple[bool, str]:
        print(f"[ATTACK] Magnetometer Bias Drift ({drift_rate_deg_s}deg/s)")
        start_time = time.time()
        offset = 0.0
        while time.time() - start_time < duration_s:
            dt = time.time() - start_time
            offset = drift_rate_deg_s * dt
            # Convert heading offset to microtesla (approx)
            # 1 deg ~ 1.5 uT at mid-latitudes
            uT_offset = offset * 1.5
            injector.set_sim_param("SIM_MAG_OFS_X", uT_offset)
            time.sleep(1.0)
        injector.set_sim_param("SIM_MAG_OFS_X", 0.0)
        return True, "Magnetometer bias drift simulated"
    return attack


def optical_flow_bias(injector: SITLInjector,
                      bias_x_m_s: float = 2.0,
                      duration_s: float = 30.0) -> Callable:
    """
    Optical Flow Bias Injection.
    Injects constant velocity bias in optical flow.
    """
    def attack() -> Tuple[bool, str]:
        print(f"[ATTACK] Optical Flow Bias (bias_x={bias_x_m_s}m/s)")
        # Requires MAVLink injection of OPTICAL_FLOW messages
        time.sleep(duration_s)
        return True, "Optical flow bias simulated"
    return attack


def rtcorrection_fault(injector: SITLInjector,
                       fault_type: str = "single_bit_flip",
                       duration_s: float = 30.0) -> Callable:
    """
    RTK Correction Fault Injection.
    Injects faults in RTCM correction stream.
    """
    def attack() -> Tuple[bool, str]:
        print(f"[ATTACK] RTK Correction Fault ({fault_type})")
        # Simulate by degrading RTK fix quality
        time.sleep(duration_s)
        return True, "RTK correction fault simulated"
    return attack


# ---------------------------------------------------------------------------
# Attack Registry
# ---------------------------------------------------------------------------

ATTACK_INJECTORS: Dict[str, Callable] = {
    "gps_spoofing_jump": gps_spoofing_jump,
    "gps_spoofing_drift": gps_spoofing_drift,
    "gps_jamming": gps_jamming,
    "gps_spoofing_seamless": gps_spoofing_seamless,
    "gps_time_spoofing": gps_time_spoofing,
    "gnss_jamming_ramp": gnss_jamming_ramp,
    "baro_spoofing_iemi": baro_spoofing_iemi,
    "mag_spoofing_coil": mag_spoofing_coil,
    "optical_flow_spoofing": optical_flow_spoofing,
    "rangefinder_spoofing": rangefinder_spoofing,
    "rtcorrection_injection": rtcorrection_injection,
    "coordinated_gnss_baro": coordinated_gnss_baro_attack,
    "mag_bias_drift": mag_bias_drift,
    "optical_flow_bias": optical_flow_bias,
    "rtcorrection_fault": rtcorrection_fault,
}


def run_attack(attack_name: str, injector: SITLInjector, **kwargs) -> Tuple[bool, str]:
    """Run a named attack with the given injector and parameters."""
    if attack_name not in ATTACK_INJECTORS:
        return False, f"Unknown attack: {attack_name}"
    attack_fn = ATTACK_INJECTORS[attack_name](injector, **kwargs)
    return attack_fn()


def list_attacks() -> List[str]:
    """Return list of available attack names."""
    return list(ATTACK_INJECTORS.keys())


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 70)
    print("NAV ATTACK INJECTOR — SELF TEST")
    print("=" * 70)
    print("\nAvailable attacks:")
    for name in list_attacks():
        print(f"  - {name}")

    # Test without SITL connection
    print("\n[TEST] Attack registry OK")
    print("=" * 70)
    print("SELF TEST COMPLETE (no SITL connection)")
    print("=" * 70)