# Incident Report — PHI-2026-001
## Phishing Attack: Credential Harvesting via Spearphishing Link
### Author: Lalith Vardhan Boddala
### Classification: Portfolio / Lab Simulation
### Date: 2026-06-15

---

## 1. Executive Summary

On 2026-06-15, a simulated phishing attack was executed against a Windows
10 endpoint (WINDOWS_TARGET) as part of a controlled SOC home lab exercise.
The attack successfully delivered a credential harvesting email, induced the
victim to click a malicious link, and captured submitted credentials — all
within a 90-minute window.

The full attack lifecycle was detected and documented using GoPhish campaign
telemetry, Sysmon endpoint logs, Wireshark packet capture, and Splunk SIEM
analysis. No real credentials or production systems were involved.

**Outcome:** Attack detected across all phases. Full kill chain documented
with evidence at each stage.

---

## 2. Incident Details

| Field | Value |
|---|---|
| Incident ID | PHI-2026-001 |
| Date | 2026-06-15 |
| Severity | Critical (credentials submitted) |
| Attack Type | Phishing — Credential Harvesting |
| MITRE Technique | T1566.002 — Spearphishing Link |
| Attacker Machine | SIEM_SERVER (GoPhish — MacBook M2) |
| Victim Machine | WINDOWS_TARGET (Windows 10 VM) |
| Victim Account | victoria1119995@gmail.com |
| Victim Browser | Microsoft Edge |
| Detection Method | GoPhish telemetry + Sysmon + Wireshark |
| Status | Contained (lab environment) |

---

## 3. Attack Timeline

| Time (UTC) | Event | Evidence Source |
|---|---|---|
| 09:18:02 | Campaign created in GoPhish | GoPhish DB |
| 09:18:06 | Phishing email sent to victim | GoPhish DB |
| 09:20:08 | Victim opened the email | GoPhish DB |
| 09:25:53 | Victim clicked phishing link (first click) | GoPhish DB |
| 09:36:16 | Victim clicked link again | GoPhish DB |
| 09:37:18 | Victim clicked link again | GoPhish DB |
| 09:38:18 | Victim clicked link again | GoPhish DB |
| 09:41:46 | Victim clicked link again | GoPhish DB |
| 10:36:42 | Victim clicked link (6th time) | GoPhish DB |
| 10:40:12 | Victim submitted credentials (1st) | GoPhish DB |
| 10:42:03 | Victim submitted credentials (2nd) | GoPhish DB |
| 10:42:05 | Victim submitted credentials (3rd) | GoPhish DB |

**Total time from email delivery to credential submission: ~84 minutes**
**Total link clicks: 6**
**Total credential submissions: 3**

---

## 4. Attack Description

### 4.1 Initial Access — Email Delivery (T1566.002)
A phishing email was crafted impersonating an IT Security team, using
urgency language ("Action Required — Reset Your Password Immediately")
to pressure the victim into immediate action. The email was sent via
GoPhish using Gmail SMTP, causing it to pass all standard email
authentication checks (SPF, DKIM, DMARC).

### 4.2 User Execution — Link Click (T1204.001)
The victim clicked the embedded phishing link, which redirected to a
fake Microsoft login page hosted on the GoPhish server (SIEM_SERVER:80).
The link was clicked 6 times across the session, indicating repeated
attempts to access the page.

Sysmon EventCode=22 (DNS Query) captured 146 events during the attack
window, including browser activity from Microsoft Edge (msedge.exe),
confirming the victim's browser interaction with the phishing
infrastructure.

### 4.3 Credential Harvesting (T1056)
The victim entered credentials into the fake Microsoft login form.
GoPhish captured the submitted data 3 times. Wireshark packet capture
confirmed the credentials were transmitted in plaintext over HTTP (port 80)
in an HTTP POST request — no encryption was present.

---

## 5. Evidence

| Evidence Item | Source | Detail |
|---|---|---|
| GoPhish campaign dashboard | GoPhish UI | Full kill chain — Sent → Opened → Clicked → Submitted |
| GoPhish database events | SQLite3 query | 12 events with precise UTC timestamps |
| Phishing email in Thunderbird | Thunderbird inbox | Email with fake IT Security branding |
| Fake login page | Microsoft Edge screenshot | Credential harvesting form rendered |
| Captured credentials | GoPhish results table | Submitted data confirmed from 192.168.29.219 |
| Wireshark HTTP POST | PCAP file | Plaintext credentials in HTTP POST body |
| Wireshark HTTP stream | Stream follow | Full request/response including form data |
| Sysmon EventCode=22 | Splunk search | 146 DNS events during attack window |

---

## 6. IOC Summary

| IOC Type | Value |
|---|---|
| Victim IP | 192.168.29.219 (WINDOWS_TARGET) |
| Attacker IP | 192.168.29.191 (SIEM_SERVER) |
| Protocol | HTTP — Port 80 |
| HTTP Method | POST |
| Victim Browser | Microsoft Edge (msedge.exe) |
| Sending Email | victoria1119995@gmail.com |
| Email Subject | [Action Required] Reset Your Password Immediately |
| SMTP Relay | smtp.gmail.com:587 |
| First Click | 2026-06-15 09:25:53 UTC |
| Data Submitted | 2026-06-15 10:42:05 UTC |

---

## 7. Analyst Interpretation

### Why the Attack Succeeded
The phishing email passed all standard email authentication controls
(SPF/DKIM/DMARC) because it was sent through a legitimate Gmail
account. This is a common real-world attacker technique — abusing
trusted email infrastructure to bypass gateway filters.

The urgency-based social engineering ("Action Required", "Immediately")
exploited the victim's instinct to respond quickly without verifying
the sender's legitimacy. The multiple clicks (6 total) suggest the
victim encountered the Outlook error page initially and kept retrying,
which is realistic victim behaviour.

### Why Credentials Were Submitted 3 Times
The victim submitted credentials multiple times, likely because:
- The first submission redirected to Microsoft.com without clear confirmation
- The victim returned and submitted again assuming the first attempt failed
- This behaviour is realistic and commonly observed in real phishing incidents

### Key Defensive Gaps Identified
1. No MFA — once credentials are captured, the attacker has full access
2. HTTP used for credential transmission — no encryption
3. Email gateway allowed the phishing email through due to SPF/DKIM pass
4. No URL inspection at email gateway to flag internal IP addresses in links
5. No user awareness training — victim clicked link 6 times

---

## 8. MITRE ATT&CK Mapping

| Phase | Technique | ID | Evidence |
|---|---|---|---|
| Initial Access | Spearphishing Link | T1566.002 | Email delivered — GoPhish DB |
| Execution | Malicious Link | T1204.001 | Link clicked x6 — GoPhish DB |
| Credential Access | Web Credentials | T1056 | POST captured — Wireshark PCAP |
| Exfiltration | Exfil over HTTP | T1041 | Plaintext POST — Wireshark stream |

---

## 9. Recommendations

| Priority | Recommendation | Control Type |
|---|---|---|
| Critical | Enforce MFA on all accounts | Preventive |
| Critical | Deploy Secure Email Gateway with URL sandboxing | Preventive |
| High | Block outbound HTTP (port 80) for credential forms | Preventive |
| High | Implement URL rewriting in email gateway | Detective |
| High | Configure DMARC policy to reject (p=reject) | Preventive |
| Medium | Deploy phishing awareness training programme | Preventive |
| Medium | Alert on outbound HTTP POST from workstations | Detective |
| Low | Implement login anomaly detection | Detective |

---

## 10. Conclusion

The simulated phishing attack successfully demonstrated the complete
credential harvesting kill chain from email delivery to data exfiltration.
All phases were detected and documented using industry-standard SOC tools.

The most significant finding is that standard email authentication controls
(SPF/DKIM/DMARC) are insufficient to detect phishing sent through legitimate
email platforms. A layered defence combining email gateway URL analysis,
MFA enforcement, and user training is required to effectively mitigate
this threat vector.

This incident simulation demonstrates proficiency in phishing triage,
IOC extraction, SIEM-based investigation, packet analysis, and
incident report writing — core competencies for SOC L1 analyst roles.

---

*Lalith Vardhan Boddala | SOC Home Lab Portfolio*
*GitHub: https://github.com/lalithvardhan434*
