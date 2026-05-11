from whitelist import TRUSTED_PROCESSES
from logger import log_event
from service_audit import audit_services
import psutil
import time
from datetime import datetime

# ✅ Trusted system paths
TRUSTED_PATHS = [
    "C:\\Windows\\System32",
    "C:\\Windows",
    "C:\\Program Files",
    "C:\\Program Files (x86)",
    "C:\\ProgramData\\Microsoft\\Windows Defender"
]

# ✅ Safe user app paths
SAFE_USER_PATHS = [
    "C:\\Users\\HP\\AppData\\Local\\Programs",
    "C:\\Users\\HP\\AppData\\Roaming",
    "C:\\Users\\HP\\AppData\\Local\\Microsoft"
]

# ✅ Safe dev tools
SAFE_SHELL_PROCESSES = [
    "python.exe", "node.exe", "npm.exe", "code.exe", "openconsole.exe", "conhost.exe"
]

# ✅ Suspicious folders
SUSPICIOUS_DIRS = [
    "\\AppData\\Local\\Temp",
    "\\Temp"
]


# -------------------------------
# 🔍 Check path safely
# -------------------------------
def is_suspicious_path(path):
    if not path:
        return True

    for trusted in TRUSTED_PATHS:
        if path.startswith(trusted):
            return False

    for safe in SAFE_USER_PATHS:
        if path.startswith(safe):
            return False

    return True


# -------------------------------
# 🔍 Analyze process
# -------------------------------
def analyze_process(proc):
    try:
        name = proc.name().lower()
        pid = proc.pid
        path = proc.exe()
        parent = proc.parent().name().lower() if proc.parent() else "unknown"

        risk = "SAFE"
        reason = []

        # ✅ Rule 1: Whitelist check
        if name not in TRUSTED_PROCESSES:
            risk = "LOW"
            reason.append("Untrusted process")

        # ✅ Rule 2: Suspicious path
        if is_suspicious_path(path):
            if name not in TRUSTED_PROCESSES:
                if risk != "HIGH":
                    risk = "MEDIUM"
                reason.append("Unknown app from unusual path")

        # ✅ Rule 3: Shell spawn
        if parent in ["powershell.exe", "cmd.exe"]:
            if name not in SAFE_SHELL_PROCESSES:
                risk = "HIGH"
                reason.append("Suspicious process spawned by shell")
            else:
                reason.append("Dev tool execution")

        # ✅ Rule 4: TEMP execution
        if path:
            for folder in SUSPICIOUS_DIRS:
                if folder.lower() in path.lower():
                    if name not in SAFE_SHELL_PROCESSES:
                        risk = "HIGH"
                        reason.append("Running from TEMP directory")
                    else:
                        reason.append("Dev tool in TEMP (normal)")
                    break

        return {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "name": name,
            "pid": pid,
            "parent": parent,
            "path": path,
            "risk": risk,
            "reason": ", ".join(reason)
        }

    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None


# -------------------------------
# 🚀 Monitor loop
# -------------------------------
def monitor():
    print("🚀 Monitoring started...\n")

    while True:
        high = medium = low = 0

        for proc in psutil.process_iter():
            data = analyze_process(proc)
            if not data:
                continue

            if data["risk"] == "HIGH":
                high += 1

                print(f"[HIGH] {data['name']} (PID: {data['pid']})")
                print(f"Parent: {data['parent']}")
                print(f"Reason: {data['reason']}\n")

                # 🔥 LOG TO CSV
                log_event("HIGH", data['name'], data['pid'], data['parent'], data['reason'])

            elif data["risk"] == "MEDIUM":
                medium += 1
                log_event("MEDIUM", data['name'], data['pid'], data['parent'], data['reason'])

            elif data["risk"] == "LOW":
                low += 1

        print(f"🔎 Summary → HIGH:{high} MEDIUM:{medium} LOW:{low}\n")
        time.sleep(5)


# -------------------------------
# ▶ Run
# -------------------------------
if __name__ == "__main__":
    try:
        audit_services()   # 🔥 service scan first
        monitor()          # 🔥 then monitoring
    except KeyboardInterrupt:
        print("\n🛑 Monitoring stopped.")