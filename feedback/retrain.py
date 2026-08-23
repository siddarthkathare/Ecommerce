"""
FEEDBACK LOOP
-------------
Maps to the "FEEDBACK LOOP" box in the architecture diagram:

    New data and results continuously improve the AI model.

Every time app.py finishes a scan, it appends one row per finding to
feedback/feedback_log.csv (see log_feedback() in app.py). This script folds
that accumulated real-world data back into ml_model/train_model.py's
training set and re-fits the model, so the AI model that is deployed next
has learned from every scan the pipeline has run so far.

Run manually:
    python feedback/retrain.py

Or trigger it from Jenkins (see the "Dataset-Driven Learning Update" stage
in the Jenkinsfile) after every N pipeline runs.
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from ml_model.train_model import train, FEEDBACK_PATH  # noqa: E402


def count_feedback_rows():
    if not os.path.exists(FEEDBACK_PATH):
        return 0
    with open(FEEDBACK_PATH, "r", encoding="utf-8") as f:
        # minus 1 for the header row
        return max(0, sum(1 for _ in f) - 1)


if __name__ == "__main__":
    rows = count_feedback_rows()
    print(f"Found {rows} new feedback rows logged from real pipeline runs.")
    print("Retraining the risk-priority model...")
    train()
    print("Retraining complete. The updated model is now live for the next scan.")
