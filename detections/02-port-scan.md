# Detection: Port Scan

**MITRE ATT&CK:** [T1046 - Network Service Discovery](https://attack.mitre.org/techniques/T1046/) (Tactic: Discovery)

## Summary

Flags any source IP that gets blocked while attempting to reach more than 5 distinct ports within a rolling window — the signature of an attacker probing a host to discover open services, as opposed to normal traffic which typically hits the same port repeatedly.

## Setup

Port scans don't show up in `auth.log` (that only records authentication events). To detect them, `ufw` (Ubuntu's firewall) was configured with logging enabled:

```
sudo ufw allow 22/tcp        # allow SSH before enabling default-deny, to avoid lockout
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw logging on
sudo ufw enable
```

A second Elastic Agent input was added to ship `/var/log/ufw.log` into a new `logs-ufw.log-default` data stream, alongside the existing `auth.log` input.

## Simulated Attack

From Kali, ran an Nmap scan against the victim's top 1000 common ports:

```
sudo nmap 192.168.56.104
```

Only port 22 (SSH) is open; every other probed port gets dropped and logged by `ufw`.

## Log Evidence

```
[UFW BLOCK] IN=enp0s8 OUT= MAC=... SRC=192.168.56.106 DST=192.168.56.104 LEN=44 ... PROTO=TCP SPT=60055 DPT=443 WINDOW=1024 RES=0x00 SYN URGP=0
```

## Detection Query (ES|QL)

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

Confirmed 14 distinct ports probed by `192.168.56.106` (the Kali VM) in a single scan, well above the detection threshold. Rule fired, generating 3 alerts across testing (1 Active, 2 Recovered) visible in Kibana's alert history.

## Notes

- **Rate-limited logging is a real constraint.** `ufw`'s default logging doesn't record every blocked packet — only a rate-limited sample (roughly a burst of ~10, then throttled). A full 1000-port Nmap scan only produced ~10-14 logged entries, not 1000. The detection threshold (`> 5`) was tuned to reflect this actual observed log volume rather than an idealized assumption that every packet gets logged. This is a real operational consideration when relying on firewall logs for detection — worth explicitly designing around, not something to discover by surprise in production.
