# 🎣 Phishing Incident Response Lab

> **End-to-end phishing simulation and incident response** — attack execution, evidence collection, IOC extraction, Wireshark packet analysis, and professional IR documentation mapped to MITRE ATT&CK.

---

## 📋 Overview

This project demonstrates the complete phishing incident response lifecycle from a SOC analyst perspective. A controlled phishing campaign was executed using GoPhish, delivering a credential harvesting email to a Windows 10 victim endpoint. The full attack chain was detected, investigated, and documented using industry-standard tools.

**Built by:** Lalith Vardhan Boddala | MSc Cybersecurity
**Purpose:** SOC Analyst L1 portfolio project  
**Focus:** Incident Response, IOC Extraction, Email Forensics, Packet Analysis

---

## ⚔️ Attack Chain — Full Kill Chain Executed

| Phase | Event | Timestamp (UTC) | Evidence |
|---|---|---|---|
| Delivery | Phishing email sent | 2026-06-15 09:18:06 | GoPhish DB |
| Reconnaissance | Email opened by victim | 2026-06-15 09:20:08 | GoPhish tracking pixel |
| Execution | Phishing link clicked (x6) | 2026-06-15 09:25:53 | GoPhish DB + Sysmon EID=22 |
| Exfiltration | Credentials submitted (x3) | 2026-06-15 10:42:05 | GoPhish DB + Wireshark PCAP |

---

## 🏗️ Lab Architecture

```
MacBook Air M2
├── GoPhish Server (native)
│     Sends phishing email via Gmail SMTP
│     Hosts fake Microsoft login page on port 80
│     Tracks: Sent → Opened → Clicked → Submitted
└── Kali Linux (UTM) — not used in this project

Windows PC (VirtualBox)
└── Windows 10 VM — VICTIM
      Microsoft Edge (opened phishing link)
      Thunderbird (received phishing email)
      Sysmon v15 (endpoint telemetry)
      Splunk Universal Forwarder → Mac Splunk

MacBook Air M2
└── Splunk Enterprise (native) — SIEM
      Sysmon EventCode=22 — 146 DNS events captured
      Detection alert saved for T1566
```

---

## 🔍 Tools Used

| Tool | Purpose |
|---|---|
| GoPhish | Phishing campaign simulation and tracking |
| Gmail SMTP | Email delivery infrastructure |
| Thunderbird | Victim email client on Windows VM |
| Microsoft Edge | Victim browser — opened phishing link |
| Wireshark | Packet capture — HTTP POST with credentials |
| Splunk + Sysmon | SIEM detection — DNS queries during attack |
| SQLite3 | GoPhish database forensics |

---

## 📧 Email Header Forensics — Key Findings

| Header Field | Value | Significance |
|---|---|---|
| X-Mailer | gophish | Immediate phishing tool indicator |
| Message-ID | @Boddalas-MacBook-Air.local | Reveals local machine origin |
| Received from | IPv6: 2405:201:c01b:f0f8:... | Traceable to sending machine |
| Phishing link | http://SIEM_SERVER:80?rid=z6QPCo3 | Raw IP — no domain, no HTTPS |
| Tracking pixel | /track?rid=z6QPCo3 | Hidden 1x1 image — records email open |
| TLS version | TLS 1.3 (SMTP transport only) | Credentials still sent plaintext over HTTP |

---

## 🌐 Wireshark Analysis

Packet capture confirmed credentials transmitted in **plaintext over HTTP**:

```
POST /?rid=z6QPCo3 HTTP/1.1
Host: SIEM_SERVER:80
Content-Type: application/x-www-form-urlencoded
User-Agent: Microsoft Edge

email=victim%40gmail.com&password=captured_password
```

**Key Finding:** No encryption on the phishing landing page — credentials
visible in plain text in any packet capture on the network path.

---

## 📊 Splunk Detection

```spl
index=main source="C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx"
EventCode=22
| search QueryName!="*.microsoft.com" QueryName!="*.windows.com"
    QueryName!="wpad" QueryName!="WINDOWS"
| stats count by QueryName, Image, User
| sort -count
```

**Result:** 146 DNS events during attack window — Microsoft Edge (msedge.exe)
captured making queries consistent with phishing page navigation.

**Saved as Alert:** T1566 — Suspicious DNS Query — Potential Phishing  
**Severity:** High | **Schedule:** Every hour

---

## 📁 Repository Structure

```
phishing-incident-response/
├── README.md                      ← this file
├── incident-report.md             ← full IR report — 10 sections
├── ioc-list.md                    ← all IOCs with confidence levels
├── email-header-analysis.md       ← forensic header breakdown
├── IR-playbook.md                 ← reusable 6-phase response playbook
├── evidence/
│   └── phishing-capture.pcap      ← Wireshark packet capture
└── screenshots/
    ├── gophish-campaign-results.png
    ├── phishing-email-thunderbird.png
    ├── fake-login-page.png
    ├── captured-credentials-gophish.png
    ├── wireshark-post-credentials.png
    ├── wireshark-http-stream.png
    └── gophish-database-evidence.png
```

---

## 🗺️ MITRE ATT&CK Mapping

| Technique | ID | Evidence |
|---|---|---|
| Spearphishing Link | T1566.002 | GoPhish email delivered and clicked |
| User Execution: Malicious Link | T1204.001 | Link clicked 6 times from WINDOWS_TARGET |
| Credentials from Web Browsers | T1056 | Credentials submitted 3 times — captured in GoPhish |
| Exfiltration over HTTP | T1041 | Plaintext POST confirmed in Wireshark PCAP |

---

## 🔑 Key Findings

- Standard email authentication (SPF/DKIM/DMARC) **all passed** — email bypassed gateway controls because it was sent through a legitimate Gmail account
- Credentials transmitted in **plaintext over HTTP** — visible in Wireshark without any decryption
- Victim clicked the link **6 times** and submitted credentials **3 times** — demonstrates effectiveness of urgency-based social engineering
- `X-Mailer: gophish` header present — would be caught by any email gateway with header inspection rules
- 5-minute gap between email open and first click — victim read carefully but still clicked

---

## 🛡️ Defensive Recommendations

| Priority | Control |
|---|---|
| Critical | Enforce MFA — stolen credentials become useless |
| Critical | Deploy Secure Email Gateway with URL sandboxing |
| High | Block outbound HTTP POST from workstations |
| High | Implement DMARC policy: p=reject |
| Medium | Phishing awareness training programme |
| Medium | Alert on X-Mailer: gophish in email headers |

---

## 🎯 Skills Demonstrated

`GoPhish` `Phishing Simulation` `Incident Response` `Email Forensics`  
`IOC Extraction` `Wireshark` `Packet Analysis` `Splunk SPL`  
`Sysmon` `MITRE ATT&CK` `IR Documentation` `Header Analysis`  
`SQLite3 Forensics` `Threat Detection` `Security Monitoring`

---

## 🔗 Related Projects

- [Splunk SIEM Home Lab](https://github.com/lalithvardhan434/splunk-siem-homelab) — Project 1: Brute force and port scan detection

---

