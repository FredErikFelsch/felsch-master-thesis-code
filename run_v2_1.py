"""Entry point for the V2.1 booking experiment (P2.1 plus the lying-world scenarios).

Run from the repository root:
    python3 run_v2_1.py

Writes the results to results_v2_1/results.json and results_v2_1/results.md. The run manifest
in the results comes from booking_v4.manifest, so this script needs the packages of
requirements-offline.txt.
"""

from booking_v2.experiment import main_v2_1

if __name__ == "__main__":
    main_v2_1()
