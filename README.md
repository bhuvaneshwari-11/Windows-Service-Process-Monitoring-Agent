# Windows Service & Process Monitoring Agent

## Overview

The Windows Service & Process Monitoring Agent is a cybersecurity-based monitoring system developed using Python to detect suspicious, unauthorized, or potentially malicious activities in Windows environments.

The project continuously monitors active processes, analyzes parent–child process relationships, audits startup services, and identifies risky applications using whitelist and blacklist techniques.

The system generates alerts, maintains logs, and exports detection reports for security analysis.

---

# Features

* Real-time Windows process monitoring
* Parent–child process relationship analysis
* Startup service auditing
* Unauthorized process detection
* Whitelist and blacklist verification
* Risk score generation
* Alert generation for suspicious activity
* CSV report generation
* Logging and monitoring summary

---

# Technologies Used

## Programming Language

* Python

## Libraries and Modules

* psutil
* wmi
* csv
* os
* time

## Platform

* Windows Operating System
* Visual Studio Code
* PowerShell / Command Prompt

---

# Project Workflow

1. Enumerate running processes
2. Capture process information:

   * Process Name
   * PID
   * Parent PID
   * Executable Path
3. Analyze parent–child relationships
4. Detect suspicious or unauthorized processes
5. Audit startup services
6. Generate alerts and risk scores
7. Export logs and reports

---

# Detection Techniques

* Parent–child process behavior analysis
* Whitelist and blacklist verification
* Detection of applications running from AppData or Temp directories
* Suspicious process chain detection
* Startup service auditing
* Rule-based risk scoring

---

# Example Detection

Suspicious Process:

cmd.exe → powershell.exe

Reason:

* Suspicious parent–child relationship
* Untrusted process execution

---

# Output

The monitoring agent generates:

* Real-time monitoring logs
* Suspicious process alerts
* Risk level summaries
* CSV detection reports

---

# Learning Outcomes

* Understanding Windows process architecture
* Real-time process monitoring techniques
* Service auditing and security analysis
* Rule-based threat detection
* Practical cybersecurity monitoring using Python

---

# Conclusion

The Windows Service & Process Monitoring Agent successfully detects suspicious and unauthorized activities in Windows systems using real-time process and service monitoring techniques. The project demonstrates practical cybersecurity monitoring, alert generation, and reporting using Python.

---


