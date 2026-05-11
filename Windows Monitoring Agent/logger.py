import csv
from datetime import datetime
import os

LOG_FILE = "logs/report.csv"

# create logs folder if not exists
os.makedirs("logs", exist_ok=True)

def log_event(level, name, pid, parent, reason):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    file_exists = os.path.isfile(LOG_FILE)

    with open(LOG_FILE, mode="a", newline="") as file:
        writer = csv.writer(file)

        if not file_exists:
            writer.writerow(["Timestamp", "Level", "Process", "PID", "Parent", "Reason"])

        writer.writerow([timestamp, level, name, pid, parent, reason])