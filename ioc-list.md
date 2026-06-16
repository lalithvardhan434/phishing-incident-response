# IOC List — Phishing Incident Simulation
## Project: Phishing Incident Response | MITRE T1566
## Author: Lalith Vardhan Boddala
## Date: 2026-06-15

---

## Incident Summary
| Field | Value |
|---|---|
| Incident ID | PHI-2026-001 |
| Date | 2026-06-15 |
| Attack Type | Phishing — Credential Harvesting |
| MITRE Technique | T1566.002 — Spearphishing Link |
| Victim | victoria1119995@gmail.com |
| Attacker Infrastructure | SIEM_SERVER (GoPhish on MacBook M2) |
| Victim Machine | WINDOWS_TARGET (Windows 10 VM) |
| Victim Browser | Microsoft Edge |
| Outcome | Credentials submitted 3 times |

---

## IOC Table

### Network IOCs
| IOC Type | Value | Description | Confidence |
|---|---|---|---|
| Source IP | 192.168.29.219 (WINDOWS_TARGET) | Victim machine IP — made HTTP POST | High |
| Destination IP | 192.168.29.191 (SIEM_SERVER) | GoPhish server — hosted fake login page | High |
| Destination Port | 80 | GoPhish serving phishing page over HTTP | High |
| Protocol | HTTP | Unencrypted — credentials sent in plaintext | High |
| HTTP Method | POST | Credential submission request | High |

### Email IOCs
| IOC Type | Value | Description | Confidence |
|---|---|---|---|
| Sender Email | victoria1119995@gmail.com | GoPhish sending address | High |
| Recipient Email | victoria1119995@gmail.com | Victim email address | High |
| Email Subject | [Action Required] Reset Your Password Immediately | Phishing lure subject line | High |
| SMTP Server | smtp.gmail.com:587 | GoPhish SMTP relay | High |

### Timeline IOCs
| Event | Timestamp (UTC) | Detail |
|---|---|---|
| Campaign Created | 2026-06-15 09:18:02 | GoPhish campaign initiated |
| Email Sent | 2026-06-15 09:18:06 | Phishing email delivered |
| Email Opened | 2026-06-15 09:20:08 | Victim opened email — 2 min after delivery |
| First Link Click | 2026-06-15 09:25:53 | Victim clicked phishing link |
| Link Clicked x6 | 2026-06-15 09:25 – 10:36 | Multiple clicks recorded |
| Data Submitted | 2026-06-15 10:42:05 | Credentials entered and captured |
| Total Submissions | 3 | Victim submitted credentials 3 times |

### Host IOCs
| IOC Type | Value | Description | Confidence |
|---|---|---|---|
| Victim Browser | Microsoft Edge (msedge.exe) | Browser used to open phishing link | High |
| Sysmon EID | 22 (DNS Query) | 146 DNS events during attack window | High |
| DNS Query | wpad | Browser proxy auto-detection triggered | Medium |
| DNS Query | cdn.onenote.net | Edge browser background activity | Low |
| Victim OS | Windows 10 | WINDOWS_TARGET operating system | High |

### Wireshark IOCs
| IOC Type | Value | Description |
|---|---|---|
| HTTP POST URI | /[campaign-path] | Credential submission endpoint on GoPhish |
| Content-Type | application/x-www-form-urlencoded | POST body encoding — credentials in plaintext |
| User-Agent | Microsoft Edge | Browser fingerprint in HTTP headers |
| Captured Fields | email, password | Form fields submitted by victim |

---

## Defensive Recommendations
| Recommendation | Priority |
|---|---|
| Block HTTP (port 80) for credential submission — enforce HTTPS only | Critical |
| Deploy email gateway filtering for urgent/action-required subject lines | High |
| Enable MFA on all accounts — stolen credentials become useless | Critical |
| Train users to verify sender domain before clicking links | High |
| Deploy DNS filtering to block known phishing domains | High |
| Alert on unusual outbound HTTP POST from workstations | Medium |

---
