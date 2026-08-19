# SOC Home Lab: Splunk + Sysmon Detection Pipeline

A home-built Security Operations Center (SOC) lab demonstrating end-to-end log collection, parsing, and threat detection using Splunk Enterprise and Sysmon.

## Architecture

- **splunk0-server** (Ubuntu Server, VirtualBox) — runs Splunk Enterprise 10.4.2, indexes and stores all log data
- **windows11-client** (Windows 11 Enterprise Evaluation, VirtualBox) — runs Sysmon (SwiftOnSecurity config) for detailed system telemetry, forwards logs via Splunk Universal Forwarder
- Both VMs connected via VirtualBox host-only network (192.168.56.0/24)

## Pipeline

1. Sysmon captures Windows system events (process creation, file creation, network connections, etc.) on windows11-client
2. Splunk Universal Forwarder ships those events to splunk0-server
3. Splunk Enterprise indexes the data (sourcetype: `XmlWinEventLog`, Channel: `Microsoft-Windows-Sysmon/Operational`)
4. Custom SPL searches parse and correlate events into a multi-panel dashboard

## Dashboard Panels

- **Process Creation Events** — all Sysmon EventID 1 events (process launches)
- **PowerShell Activity** — filtered view of `powershell.exe`/`pwsh.exe` executions
- **File Creation Events** — Sysmon EventID 11 (files written to disk)
- **MITRE ATT&CK Detections** — SPL logic mapping suspicious command-line patterns to MITRE technique IDs (e.g., T1059.001 - PowerShell, T1218 - Signed Binary Proxy Execution, T1087 - Account Discovery, T1047 - WMI Execution, T1140 - Deobfuscate/Decode Files)

## Tools Used

- Splunk Enterprise
- Sysmon (SwiftOnSecurity config)
- Splunk Universal Forwarder
- Splunk Add-on for Sysmon
- Splunk Add-on for Microsoft Windows
- VirtualBox

## Key Learnings

- How Sysmon's XML-rendered event logs require both a base Windows TA and a Sysmon-specific TA for full field extraction
- Real-world troubleshooting of a broken log pipeline (disabled event log channel, sourcetype naming mismatches)
- Writing SPL `eval`/`case` logic to map raw telemetry to MITRE ATT&CK techniques
