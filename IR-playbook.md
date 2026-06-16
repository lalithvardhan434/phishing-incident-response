# Phishing Incident Response Playbook
## Project: Phishing Incident Response | MITRE T1566
## Author: Lalith Vardhan Boddala

---

## Purpose
This playbook defines the step-by-step response procedure for a phishing
incident involving credential harvesting. It is designed for SOC L1 analysts
as a first-response guide from initial alert to resolution.

---

## Trigger Conditions
This playbook activates when any of the following are observed:
- User reports suspicious email
- Email gateway flags a message as phishing
- Splunk alert fires on T1566 detection rule
- User reports clicking a suspicious link
- Unusual outbound HTTP POST detected from workstation

---

## Phase 1 — Initial Triage (0–15 minutes)

| Step | Action | Tool |
|---|---|---|
| 1.1 | Assign incident ID — format: PHI-YYYY-NNN | Ticketing system |
| 1.2 | Record initial report time and reporter details | IR log |
| 1.3 | Identify affected user account and machine | AD / SIEM |
| 1.4 | Determine if credentials were submitted | Email gateway / SIEM |
| 1.5 | Escalate to L2 if credentials confirmed submitted | Escalation matrix |

**Severity Classification:**
| Condition | Severity |
|---|---|
| Email received, not opened | Low |
| Email opened, link not clicked | Medium |
| Link clicked, credentials not submitted | High |
| Credentials submitted | Critical |

---

## Phase 2 — Containment (15–30 minutes)

| Step | Action | Tool |
|---|---|---|
| 2.1 | Isolate affected workstation from network | EDR / Network switch |
| 2.2 | Reset victim's password immediately | Active Directory |
| 2.3 | Revoke all active sessions for the account | Identity provider |
| 2.4 | Block sender email address at gateway | Email gateway |
| 2.5 | Block phishing domain/IP at firewall | Firewall |
| 2.6 | Search for same email in other mailboxes | Email gateway |
| 2.7 | Notify affected user — do not delete email yet | Direct contact |

---

## Phase 3 — Investigation (30–90 minutes)

### 3.1 Email Header Analysis
Examine the following fields in raw email headers:
```
From:           verify display name vs actual sending address
Reply-To:       check if different from From — common phishing indicator
Received:       trace hop-by-hop path — identify origin server
X-Originating-IP: actual sending IP address
SPF:            check PASS/FAIL — FAIL indicates spoofed sender
DKIM:           check signature validity
DMARC:          check policy enforcement result
Message-ID:     unique identifier for cross-referencing
Date:           check timezone and timestamp consistency
```

### 3.2 Splunk Investigation Queries
```spl
-- Find DNS queries during attack window:
index=main EventCode=22 earliest=[INCIDENT_START] latest=[INCIDENT_END]
| table _time, QueryName, Image, User | sort _time

-- Find outbound HTTP connections:
index=main EventCode=3 DestinationPort=80 OR DestinationPort=443
earliest=[INCIDENT_START] latest=[INCIDENT_END]
| table _time, SourceIp, DestinationIp, DestinationPort, Image | sort _time

-- Find browser process launches:
index=main EventCode=1 Image="*msedge*" OR Image="*chrome*"
earliest=[INCIDENT_START] latest=[INCIDENT_END]
| table _time, Image, CommandLine, ParentImage, User | sort _time

-- Check for lateral movement after credential theft:
index=main EventCode=4624 LogonType=3
earliest=[INCIDENT_START] latest=[INCIDENT_END]
| table _time, Account_Name, WorkstationName, IpAddress | sort _time
```

### 3.3 Wireshark/PCAP Analysis
```
Filter 1 — All HTTP traffic:     http
Filter 2 — Traffic to C2:        ip.dst == [PHISHING_SERVER_IP]
Filter 3 — Credential POST:      http.request.method == "POST"
Filter 4 — Follow HTTP Stream:   Right-click POST → Follow → HTTP Stream
```

### 3.4 IOC Extraction Checklist
- [ ] Sender email address
- [ ] Sending IP address (from headers)
- [ ] Phishing domain / URL
- [ ] Landing page IP address
- [ ] HTTP POST destination
- [ ] User-Agent string
- [ ] Captured credential fields
- [ ] All timestamps (sent, opened, clicked, submitted)
- [ ] Victim machine IP
- [ ] Browser used

---

## Phase 4 — Eradication (90–120 minutes)

| Step | Action |
|---|---|
| 4.1 | Delete phishing email from all affected mailboxes |
| 4.2 | Remove any downloaded attachments from workstation |
| 4.3 | Scan workstation with AV/EDR for persistence mechanisms |
| 4.4 | Check for new accounts created or privilege changes after compromise |
| 4.5 | Verify no unauthorised forwarding rules added to mailbox |
| 4.6 | Confirm attacker infrastructure is blocked at all perimeter controls |

---

## Phase 5 — Recovery

| Step | Action |
|---|---|
| 5.1 | Reconnect workstation after clean bill of health from EDR |
| 5.2 | Confirm new password is set and MFA enrolled |
| 5.3 | Monitor account for 72 hours for anomalous activity |
| 5.4 | Confirm user received phishing awareness training |

---

## Phase 6 — Lessons Learned

Document the following after every phishing incident:
- How did the email bypass filtering?
- How long between delivery and click?
- Were credentials actually valid / used elsewhere?
- What detection fired first — automated or user report?
- What control would have prevented this?

---

## MITRE ATT&CK Coverage

| Technique | ID | Phase |
|---|---|---|
| Phishing: Spearphishing Link | T1566.002 | Initial Access |
| User Execution: Malicious Link | T1204.001 | Execution |
| Credentials from Web Browsers | T1555.003 | Credential Access |
| Exfiltration Over HTTP | T1041 | Exfiltration |

---
