"""Entry point for the V0 booking experiment.

Run from the repository root:
    python3 run.py

Runs the frozen V0 scenarios against Policy P0 and writes the results to
results/results.json and results/results.md.
"""

from booking_v0.experiment import main

if __name__ == "__main__":
    main()
