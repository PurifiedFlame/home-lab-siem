# Detection: Port Scan

**MITRE ATT&CK:** [T1046 - Network Service Discovery](https://attack.mitre.org/techniques/T1046/) (Tactic: Discovery)

## What it catches

A source IP getting blocked on more than 5 distinct ports within a rolling window. Normal traffic tends to hit the same port over and over; an attacker probing for open services touches a lot of different ones fast.

## Setup

Port scans don't show up in `auth.log` — that file's only for authentication events. To catch this I had to turn on logging in `ufw` (Ubuntu's firewall):

```
sudo ufw allow 22/tcp        # allow SSH first, before default-deny, so I don't lock myself out
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw logging on
sudo ufw enable
```

Then I added a second Elastic Agent input to ship `/var/log/ufw.log` into a new `logs-ufw.log-default` data stream, running alongside the existing `auth.log` input.

## The attack

From Kali, I scanned the victim's top 1000 common ports with Nmap:

```
sudo nmap 192.168.56.104
```

Only port 22 was actually open — everything else got dropped and logged by ufw.

## Log evidence

```
[UFW BLOCK] IN=enp0s8 OUT= MAC=... SRC=192.168.56.106 DST=192.168.56.104 LEN=44 ... PROTO=TCP SPT=60055 DPT=443 WINDOW=1024 RES=0x00 SYN URGP=0
```

## Detection query (ES|QL)

```
FROM logs-ufw.log-default
| WHERE @timestamp > NOW() - 5 minutes
| WHERE message LIKE "*UFW BLOCK*"
| GROK message """%{GREEDYDATA} SRC=%{IP:source_ip} DST=%{IP:dest_ip} %{GREEDYDATA}DPT=%{POSINT:dest_port}%{GREEDYDATA}"""
| STATS distinct_ports = COUNT_DISTINCT(dest_port) BY source_ip
| WHERE distinct_ports > 5
| KEEP source_ip, distinct_ports
```

## Result

Confirmed 14 distinct ports probed by `192.168.56.106` (the Kali VM) in a single scan — well past the threshold. The rule fired and generated 3 alerts across my testing (1 Active, 2 Recovered), visible in Kibana's alert history.

## Things I noticed / would do differently

- **Rate-limited logging is a real constraint, and I didn't expect it going in.** ufw's default logging doesn't record every blocked packet — just a rate-limited burst of roughly 10, then it throttles. A full 1000-port Nmap scan only produced 10-14 log entries, not 1000. My original threshold assumed something closer to full logging and never fired; I only got it working after checking the actual log volume and tuning the threshold to match reality instead of my assumption. Worth designing around up front rather than discovering it the hard way, like I did.
