"""Entry point for the V1.2 booking experiment.

Run from the repository root:
    python3 run_v1.py

Runs the frozen V1.2 scenarios against Policy P1 and writes the results to
results_v1_2/results.json and results_v1_2/results.md.
"""

from booking_v1.experiment import main

if __name__ == "__main__":
    main()
