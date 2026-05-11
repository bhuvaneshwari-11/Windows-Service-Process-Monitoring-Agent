import wmi
from logger import log_event


def is_service_suspicious(path):
    if not path:
        return False

    path = path.lower()

    # ✅ Allow core Windows services
    if "svchost.exe" in path:
        return False

    if "c:\\windows\\system32" in path:
        return False

    if "c:\\windows" in path:
        return False

    if "c:\\program files" in path:
        return False

    # 🔥 ADD THIS (VERY IMPORTANT FIX)
    if "c:\\programdata\\microsoft\\windows defender" in path:
        return False

    # 🚨 Suspicious locations
    if "temp" in path or "appdata" in path:
        return True

    return True

def audit_services():
    print("\n🔍 Scanning Windows Services...\n")

    c = wmi.WMI()
    suspicious_count = 0

    for service in c.Win32_Service():
        name = service.Name
        path = service.PathName
        state = service.State
        start_mode = service.StartMode

        if is_service_suspicious(path):
            suspicious_count += 1

            print(f"[HIGH] Service: {name}")
            print(f"Path: {path}")
            print(f"State: {state} | Startup: {start_mode}")
            print("Reason: Suspicious path or unknown executable\n")

            # 🔥 LOG TO CSV
            log_event("HIGH", name, "-", "Service", "Suspicious path or unknown executable")

    print(f"✅ Service Audit Completed → Suspicious Services: {suspicious_count}\n")