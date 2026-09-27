"""Drone IDS benchmark package (Phases 5 (evaluation) and 6 (performance).

Offline, deterministic replay harness. The SITL/hardware numbers are filled in
on-target runs of the same code; every hardware figure is reported as
"TO MEASURE" until a Pi/Jetson/Pixhawk run.
"""

import os
import sys

# Make the repo root importable when a module in this package is executed
# directly (``python benchmark/run_benchmark.py``) rather than via the package.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)