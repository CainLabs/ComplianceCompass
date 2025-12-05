# Compliance Compass v2.3

**By CainCyberLabs**

The **Compliance Compass** is a unified security auditing tool designed to simplify compliance checks for **PCI DSS**, **CMMC**, and **HIPAA**. It combines a static configuration auditor with a behavioral file activity monitor in a single, portable executable.

  

-----

## 🚀 Key Features

### 1\. Multi-Framework Configuration Audit

Audit your system against three major compliance frameworks simultaneously with a single click.

  * **PCI DSS v4.0:** Checks password policies, firewall status, and TLS protocols.
  * **CMMC 2.0 (Level 2):** Verifies access control and system integrity settings.
  * **HIPAA:** Audits technical safeguards and audit controls.
  * **Output:** Generates color-coded HTML and detailed CSV reports.

### 2\. File Activity Monitor (Behavioral Audit)

A dedicated module to detect suspicious access to sensitive data (PHI/CUI).

  * **After-Hours Detection:** Flags file access occurring outside standard business hours (6 PM - 7 AM).
  * **Unauthorized User Detection:** Flags access by users not in your specified "Authorized Groups."
  * **Event Log Scanning:** Queries Windows Security Logs directly—no agents required.

### 3\. Portable & Agentless

  * **Zero Installation:** Runs as a single standalone `.exe` file.
  * **No Dependencies:** Does not require installing modules or external files.
  * **Read-Only:** Performs checks without modifying system settings.

-----

## 📋 System Requirements

  * **OS:** Windows 10, Windows 11, or Windows Server 2016+
  * **Privileges:** **Administrator** rights are required to read Security Event Logs and Registry keys.
  * **PowerShell:** Version 5.1 or newer (Default on Windows 10/11).

-----

## 🛠️ How to Use

### Step 1: Launch the Tool

Double-click `CCSPCI_Standalone.exe`.

  * *Note:* The tool will automatically request Administrator privileges. Click "Yes" on the UAC prompt.

### Step 2: Configuration Audit

1.  Go to the **Configuration Audit** tab.
2.  The **Target** will default to your local computer (localhost).
3.  Click **Run Config Audit**.
4.  Review the Pass/Fail status in the grid.
5.  Click **Export HTML** for a client-ready, color-coded report.

### Step 3: File Activity Monitor

1.  Go to the **File Activity Monitor** tab.
2.  **Monitor Path:** Click "Browse" (...) to select a folder containing sensitive data (e.g., `C:\PatientRecords`).
3.  **Auth Groups:** Enter the Active Directory groups allowed to access this folder (e.g., `Domain Admins, HR_Staff`).
4.  Click **Scan Activity**.
5.  The tool will list user access events found in the logs over the last 24 hours.

-----

## ⚠️ Troubleshooting

**Issue: "Scan Complete. Found 0 events."**

  * This is often normal if no one has accessed files recently.
  * **Check Audit Policy:** Windows does not log file access by default. You must enable it:
    1.  Open `secpol.msc` (Local Security Policy).
    2.  Navigate to: `Advanced Audit Policy -> System Audit Policies -> Object Access`.
    3.  Double-click **Audit File System**.
    4.  Check boxes for **Success** and **Failure**.

**Issue: "A required privilege is not held by the client"**

  * The tool must be run as Administrator to read the Security Event Log. The app tries to auto-elevate, but if you denied the request, simply restart the app as Admin.

-----

## ⚖️ Disclaimer

*This software is provided "as is" without warranty of any kind. While it assists with compliance auditing, passing these checks does not guarantee full legal compliance with PCI DSS, CMMC, or HIPAA regulations. Always consult a qualified QSA or compliance officer for official certification.*


**Copyright © 2025 CainCyberLabs**
