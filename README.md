# Compliance Compass v2.3 🛡️

**By CainCyberLabs**

**Compliance Compass** is an enterprise-grade security auditing tool designed to streamline compliance validation for Windows environments. It unifies static configuration auditing and behavioral monitoring into a single, portable executable, verifying systems against **PCI DSS**, **CMMC**, and **HIPAA** standards simultaneously.

  

-----

## 🚀 Key Features

### 1\. Unified Compliance Engine

Stop running separate audits for every regulation. Compliance Compass maps technical realities to regulatory requirements automatically in a single scan.

  * **PCI DSS v4.0:** Audits password policies, TLS protocols, firewall configurations, and insecure services.
  * **CMMC 2.0 (Level 2):** Verifies access control (AC), system integrity (SI), and audit accountability (AU) controls.
  * **HIPAA:** Validates technical safeguards including audit controls, transmission security, and authentication.

### 2\. File Activity Monitor (Behavioral Audit)

A dedicated module designed to meet HIPAA §164.312(b) and CMMC Audit requirements.

  * **Unauthorized Access Detection:** Flags file access by users not in your specified "Authorized Groups."
  * **After-Hours Alerting:** Automatically flags file access events occurring outside standard business hours (6 PM - 7 AM).
  * **Forensic Visibility:** Queries Windows Security Event Logs directly to reconstruct access history.

### 3\. Portable & Secure

  * **Zero Footprint:** Runs as a standalone `.exe` file. No installation required.
  * **Agentless:** Does not require background agents, services, or cloud connections. Ideal for air-gapped networks.
  * **Auto-Elevation:** Intelligently handles Administrator privileges to ensure deep visibility into system logs and registry keys.

-----

## 📋 System Requirements

  * **Operating System:** Windows 10, Windows 11, or Windows Server 2016/2019/2022.
  * **Privileges:** **Administrator** rights are required to read Security Event Logs and HKLM Registry hives.
  * **Dependencies:** None. (Requires standard PowerShell 5.1+, pre-installed on all modern Windows OS).

-----

## 📦 Installation & Setup

**Compliance Compass** is distributed as a portable application suite.

1.  **Purchase & Download:** Acquire your licensed copy from [caincyberlabs.com](https://caincyberlabs.com).
2.  **Extract:** Unzip the downloaded package to a folder on the target machine or a USB drive.
3.  **Run:** Double-click `ComplianceCompass.exe`.
      * *Note:* You must accept the User Account Control (UAC) prompt to allow the tool to read system security settings.

-----

## 🛠️ User Guide

### 1\. Running a Configuration Audit

This module checks static settings (Registry, GPO, Services) against compliance frameworks.

1.  Navigate to the **Configuration Audit** tab.
2.  **Target:** Defaults to `localhost`. You can enter a remote hostname if WinRM is enabled.
3.  **Role:** The tool automatically detects if the system is a Domain Controller or Standalone Server.
4.  Click **Run Config Audit**.
5.  **Review Results:** The grid will display Pass/Fail status for each check.
6.  **Export:** Click **Export HTML** to generate a color-coded, auditor-ready report.

### 2\. Monitoring File Activity

This module scans the Windows Security Log for access to sensitive data.

1.  Navigate to the **File Activity Monitor** tab.
2.  **Monitor Path:** Click **"..."** to browse for the folder containing sensitive data (e.g., `C:\PatientData` or `D:\Confidential`).
3.  **Authorized Groups:** Enter the names of Active Directory groups allowed to access this data (comma-separated).
      * *Example:* `Domain Admins, HR_Staff, Billing_Dept`
4.  **Hours Back:** Define how far back to scan (Default: 24 hours).
5.  Click **Scan Activity**.
6.  **Review Alerts:**
      * **WARNING:** Indicates access by an unauthorized user OR access during off-hours.
      * **PASS:** Indicates normal access by an authorized user during business hours.

-----

## ⚠️ Troubleshooting

**"Scan Complete. Found 0 events."**
If the tool finds no events, ensure Windows Auditing is enabled on the target machine:

1.  Open **Local Security Policy** (`secpol.msc`).
2.  Go to `Advanced Audit Policy Configuration` -\> `System Audit Policies` -\> `Object Access`.
3.  Double-click **Audit File System**.
4.  Ensure **Success** and **Failure** are checked.

**"A required privilege is not held by the client" (Error 0x522)**
The tool requires elevated privileges to read the Security Event Log.

  * **Fix:** Restart the application and click "Yes" when prompted to Run as Administrator.

-----

## ⚖️ License & Support

**Commercial License**
This software is licensed, not sold. Unauthorized copying, distribution, or reverse engineering is strictly prohibited. See `LICENSE.txt` for full terms.

**Support**
For technical support or to renew your license, please contact:

  * **Email:** support@caincyberlabs.com
  * **Web:** [caincyberlabs.com](https://caincyberlabs.com)

**Disclaimer**
*This software is a tool to assist with compliance auditing. Passing these checks does not guarantee legal compliance with PCI DSS, CMMC, or HIPAA regulations. Always consult a qualified QSA or compliance officer for official certification.*

Copyright © 2025 CainCyberLabs. All rights reserved.
