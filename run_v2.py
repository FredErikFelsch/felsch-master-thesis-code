"""Entry point for the V2 booking experiment.

Run from the repository root:
    python3 run_v2.py

Runs the frozen V2 scenarios against Policy P2 and writes the results to
results_v2/results.json and results_v2/results.md. The run manifest in the results comes from
booking_v4.manifest, so this script needs the packages of requirements-offline.txt.
"""

from booking_v2.experiment import main

if __name__ == "__main__":
    main()
