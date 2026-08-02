# Home Lab SIEM

A self-built detection lab: two VMs (an Ubuntu Server victim and a Kali Linux attacker) on an isolated network, an Elastic Stack SIEM ingesting host logs, and four custom detection rules — each mapped to a MITRE ATT&CK technique and validated against a real simulated attack.

## Architecture

```
┌─────────────────────┐         ┌──────────────────────┐
│   Kali Linux         │         │   Ubuntu Server        │
│   (Attacker)          │ ──────▶ │   (Victim)              │
│   192.168.56.106      │  attacks │   192.168.56.104        │
└─────────────────────┘  over    │                          │
                          host-only│   - OpenSSH server      │
                          network  │   - ufw firewall        │
                                   │   - Elastic Agent        │
                                   │     (standalone)         │
                                   └───────────┬──────────────┘
                                               │ ships logs
                                               │ (auth.log, ufw.log)
                                               ▼
                                   ┌──────────────────────────┐
                                   │   Host Machine             │
                                   │   Elastic Stack (Docker)    │
                                   │   - Elasticsearch            │
                                   │   - Kibana                    │
                                   │   - 4 detection rules          │
                                   └──────────────────────────────┘
```

Both VMs run in VirtualBox on a host-only network (`192.168.56.0/24`), which also gives them a route to the host machine itself — that's how the Elastic Agent on the Ubuntu VM reaches Elasticsearch running in Docker on the host.

## Attack Chain Simulated

This lab walks through a realistic attack progression, not just isolated demos:

1. **Reconnaissance** — port scan against the victim (MITRE T1046)
2. **Initial Access** — SSH brute force against a discovered open port (MITRE T1110)
3. **Privilege Escalation** — abuse of a misconfigured sudo-enabled low-privilege account (MITRE T1548.003)
4. **Persistence** — planting an SSH key for passwordless re-entry (MITRE T1098.004)

Each stage has its own detection rule, written in Elastic's ES|QL query language, running on a schedule against live log data — not a one-off search.

## Detection Rules

| # | Detection | MITRE Technique | Data Source | Writeup |
|---|-----------|-----------------|--------------|---------|
| 1 | SSH Brute Force | [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/) | `auth.log` | [detections/01-ssh-brute-force.md](detections/01-ssh-brute-force.md) |
| 2 | Port Scan | [T1046 - Network Service Discovery](https://attack.mitre.org/techniques/T1046/) | `ufw.log` | [detections/02-port-scan.md](detections/02-port-scan.md) |
| 3 | Privilege Escalation | [T1548.003 - Sudo and Sudo Caching](https://attack.mitre.org/techniques/T1548/003/) | `auth.log` | [detections/03-privilege-escalation.md](detections/03-privilege-escalation.md) |
| 4 | SSH Key Persistence | [T1098.004 - SSH Authorized Keys](https://attack.mitre.org/techniques/T1098/004/) | `auth.log` | [detections/04-persistence-ssh-key.md](detections/04-persistence-ssh-key.md) |

## Dashboard

A Kibana dashboard tracking log activity across both data sources over time:

![SIEM Dashboard](dashboard/siem-dashboard.png)

## Stack

- **Elasticsearch + Kibana** (via [Elastic's `start-local` script](https://github.com/elastic/start-local), running in Docker)
- **Elastic Agent** — standalone mode (no Fleet Server), configured directly via `elastic-agent.yml`
- **VirtualBox** — Ubuntu Server 26.04 LTS (victim) + Kali Linux (attacker), host-only networking
- **ufw** — Ubuntu's firewall, configured with logging enabled to capture blocked connection attempts
- **Detection rules** — Kibana's Elasticsearch Query Rule type, using ES|QL for parsing (`GROK`) and aggregation (`STATS`)

## Notes on Design Decisions

- **Standalone Elastic Agent instead of Fleet-managed** — kept the lab simpler by configuring the agent directly via YAML rather than standing up a separate Fleet Server. In a production environment, Fleet-managed agents would be preferred for centralized policy management at scale.
- **ES|QL for detection logic** — rather than using Kibana's built-in threshold rule type, each rule uses a full ES|QL query so that source IPs and other fields could be parsed out of raw log lines with `GROK` before aggregating — necessary since the underlying logs (`auth.log`, `ufw.log`) aren't pre-parsed into structured fields.
- **Rate-limited firewall logging** — `ufw`'s default logging doesn't log every single blocked packet, only a rate-limited sample. The port scan detection threshold was tuned to reflect that real-world behavior rather than an idealized "log everything" assumption.
- **5-minute detection windows** — initial rules used a 1-minute window matching the underlying attack pattern (e.g. "more than 5 failed logins in 60 seconds"), but this proved too tight for manual testing/validation given normal latency in log shipping and indexing. Widened to 5 minutes for reliability; a production deployment against continuous traffic could safely use a tighter window.
