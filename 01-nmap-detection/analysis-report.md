# Project 01 — Nmap Reconnaissance Detection & Triage

**Date:** 2026-05-17
**Analyst:** Halil Ibrahim Yilmaz
**Severity:** Medium
**Status:** Closed

---

## Objective

The goal of this project was to simulate a network reconnaissance attack in the home SOC lab and observe how Security Onion detects and alerts on the activity. Kali Linux was used as the attacking machine and Metasploitable2 as the target. Security Onion monitored all traffic passing through the soclab network segment.

---

## Environment

| Component | Details |
|---|---|
| Attacker | Kali Linux — 192.168.100.10 |
| Target | Metasploitable2 — 192.168.100.30 |
| Monitor | Security Onion 2.4.211 — bond0 (soclab) |

---

## Attack Summary

Three Nmap scans were performed in sequence against the target machine, each designed to gather different types of information.

### Scan 1 — SYN Scan

```
sudo nmap -sS 192.168.100.30
```

A stealth scan that sends SYN packets without completing the TCP handshake. Fast and quiet compared to a full connect scan. This revealed 23 open ports on the target including FTP (21), SSH (22), Telnet (23), HTTP (80), MySQL (3306), PostgreSQL (5432), VNC (5900), and several others. The number of open ports immediately indicated this was a heavily misconfigured system.

![SYN Scan Results](screenshots/01-syn-scan-results.png)

### Scan 2 — Version Detection

```
sudo nmap -sV 192.168.100.30
```

Sent additional probes to identify the software running on each open port. This returned specific version information including vsftpd 2.3.4 on FTP, OpenSSH 4.7p1 on SSH, Apache 2.2.8 on HTTP, MySQL 5.0.51a, and PostgreSQL 8.3.0. Each of these versions has known vulnerabilities that an attacker could use as a starting point for exploitation.

![Version Scan Results](screenshots/02-version-scan-results.png)

### Scan 3 — UDP Scan

```
sudo nmap -sU --top-ports 20 192.168.100.30
```

Probed the top 20 most common UDP ports. Found open or filtered ports on DNS (53), DHCP (67/68), TFTP (69), NetBIOS (137), and SNMP (161) among others.

![UDP Scan Results](screenshots/03-udp-scan-results.png)

---

## Alerts Generated

Security Onion produced 52 total alert events grouped into 17 distinct rules across the three scans.

### After SYN Scan — 5 alerts

![Alerts After SYN Scan](screenshots/04-alerts-after-syn-scan.png)

### After Version Detection — 12 alerts

![Alerts After Version Scan](screenshots/05-alerts-after-version-scan.png)

### After All Three Scans — 17 alert groups, 52 total events

![All Alerts](screenshots/06-alerts-all-scans.png)

| Alert | Severity | Count |
|---|---|---|
| ET SCAN Nmap Scripting Engine User-Agent Detected | High | 8 |
| ET SCAN Possible Nmap User-Agent Observed | High | 8 |
| GPL RPC portmap listing TCP 111 | Medium | 6 |
| ET SCAN Suspicious inbound to PostgreSQL port 5432 | Medium | 5 |
| ET TFTP Outbound TFTP Read Request | High | 4 |
| GPL SNMP public access udp | Medium | 4 |
| ET SCAN Suspicious inbound to mySQL port 3306 | Medium | 3 |
| ET SCAN Potential VNC Scan 5800-5820 | Medium | 2 |
| ET SCAN Suspicious inbound to MSSQL port 1433 | Medium | 2 |
| ET SCAN Suspicious inbound to Oracle SQL port 1521 | Medium | 2 |
| GPL DNS named version attempt | Medium | 2 |
| ET DOS Possible SSDP Amplification Scan in Progress | Medium | 1 |
| ET INFO RMI Request Outbound | High | 1 |
| ET P2P Vuze BT UDP Connection | High | 1 |
| GPL RPC rlogin login failure | High | 1 |
| ET CHAT IRC authorization message | Low | 1 |

---

## Key Findings

### Nmap was fingerprinted by its own user-agent

The most interesting detection came from the version scan. When Nmap's scripting engine probed the web services on ports 80 and 8180, it sent HTTP requests with a distinctive user-agent string:

```
User-Agent: Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)
```

Suricata caught this immediately. The attacker's tool was identified before any exploitation was even attempted.

![Alert Detail — Nmap User-Agent](screenshots/07-alert-detail-nmap-useragent-1.png)

The raw packet payload was also captured, showing the full HTTP request:

![Alert Detail — Decoded Packet](screenshots/07-alert-detail-nmap-useragent-2.png)

![Alert Detail — Rule Details](screenshots/07-alert-detail-nmap-useragent-3.png)

### HTTP requests returned successful responses

Several of Nmap's HTTP probes received 200 OK responses from the target. This means the scan wasn't just sending blind packets — it was actually getting useful information back about the web services running on the target.

### Database ports generated the most alerts

Suricata had specific rules for each database port being scanned — MySQL, PostgreSQL, MSSQL, Oracle. Each triggered separately, which shows how signature-based detection works: one scan generates multiple alerts, each one mapping to a different service being probed.

### UDP scan triggered high-severity alerts

The TFTP alert fired during the UDP scan. TFTP has no authentication by default, making it a common target for attackers looking for easy file access. SNMP with public community string is also a classic misconfiguration that exposes device information.

---

## MITRE ATT&CK Mapping

| Technique | ID | Observed Activity |
|---|---|---|
| Active Scanning | T1595 | All three Nmap scan types |
| Scanning IP Blocks | T1595.001 | SYN scan across port range |
| Vulnerability Scanning | T1595.002 | Version detection (-sV) |
| Gather Victim Host Information | T1592 | Service version banners collected |

---

## Triage Outcome

All 52 alerts were reviewed and classified as true positives. The scanning activity did occur exactly as the rules described. A case was opened in Security Onion's case management module and closed after documenting the findings.

![Cases Overview](screenshots/08-cases-overview.png)

In a real environment, this volume of scanning activity from a single internal IP in a short time window would warrant immediate investigation. The combination of rapid sequential port scanning, Nmap fingerprinting, and successful HTTP responses is a strong indicator of active reconnaissance.

---

*This report was produced as part of a home SOC lab exercise. All activity occurred in an isolated virtual network. No real systems were targeted.*

