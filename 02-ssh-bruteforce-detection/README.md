# Project 02 — SSH Brute Force Detection with Splunk SIEM

A home SOC lab exercise simulating an SSH brute force attack and detecting it in real time through a Splunk SIEM pipeline.

## What I Did

Built a three-VM lab on an isolated NAT network and engineered a stable log forwarding pipeline from a vulnerable Linux victim to a centralized Splunk indexer. Then ran a real brute force attack from Kali Linux and verified detection inside Splunk.

- **Attacker** (`10.0.2.10`): Kali Linux running Medusa against SSH
- **Victim** (`10.0.2.14`): Metasploitable2 — target of the brute force
- **SIEM** (`10.0.2.11`): Splunk Enterprise 10.2.3, listening on UDP/514

## What I Built

Replaced an unstable `tail | nc` PoC log shipper with a proper `rsyslog` forwarder, configured Splunk to ingest and parse syslog correctly, and validated end-to-end packet flow with `tcpdump` and `ss` at each hop.

- `auth.*` and `authpriv.*` facilities forwarded from victim to SIEM
- Timezone alignment between victim and indexer
- Custom Splunk SPL query with inline regex to extract `attacked_user` and `src_ip` from raw events

## What Splunk Detected

Medusa ran 6 SSH login attempts against the victim in under 3 seconds. All 6 events landed in Splunk — 5 `Failed password` and 1 `Accepted password` for `msfadmin` from `10.0.2.10`. Zero packet loss under flood, which was the core failure mode of the original `nc`-based pipeline.

## Engineering Notes

The pipeline went through four distinct failure modes before stabilizing: log buffering, timestamp skew, SSH algorithm incompatibility, and a Splunk disk-space soft limit that silently dropped indexed events. Each was diagnosed with a different tool — `tcpdump`, `ss`, `splunkd.log`, and Splunk's Health Status panel — and the full debug walkthrough is in the analysis report.

## Tools Used

- Splunk Enterprise 10.2.3
- rsyslog 1.19.12
- Medusa 2.3 (SSH brute force)
- tcpdump, ss (network verification)
- Oracle VirtualBox (NAT Network)

## Full Report

Detailed pipeline architecture, problem-resolution log, and Splunk query breakdown: [analysis-report.md](./analysis-report.md)
