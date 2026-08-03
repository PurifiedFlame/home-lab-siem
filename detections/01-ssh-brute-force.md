# Detection: SSH Brute Force

**MITRE ATT&CK:** [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/) (Tactic: Credential Access)

## What it catches

Any source IP that racks up more than 5 failed SSH login attempts in a short window. That pattern doesn't really happen from normal human error — it's what an automated password-guessing tool looks like.

## The attack

From the Kali VM, I ran Hydra against the Ubuntu victim's SSH service with a wordlist:

```
hydra -l ubuntu -P /usr/share/wordlists/rockyou.txt -t 4 ssh://192.168.56.104
```

## Log evidence

Every failed attempt shows up in `/var/log/auth.log`, which Elastic Agent ships into the `logs-auth.log-default` data stream:

```
Failed password for invalid user admin from 203.0.113.5 port 51000 ssh2
```

## Detection query (ES|QL)

```
FROM logs-auth.log-default
| WHERE @timestamp > NOW() - 5 minutes
| WHERE message LIKE "*Failed password*"
| GROK message """%{SYSLOGTIMESTAMP:log_timestamp} %{SYSLOGHOST:hostname} sshd\[%{POSINT:pid}\]: Failed password for (invalid user )?%{USERNAME:username} from %{IP:source_ip} port %{POSINT:source_port} %{WORD:protocol}"""
| STATS attempt_count = COUNT(*) BY source_ip
| WHERE attempt_count > 5
| KEEP source_ip, attempt_count
```

## Result

The rule fired against the live Hydra attack and generated a real Kibana alert tagged `credential-access`, `mitre-t1110`. I checked Rules > Alert History and confirmed it ran on schedule and correctly flipped from Active to Recovered once the attack burst ended.

## Things I noticed / would do differently

- The rule alerts once per check cycle rather than once per attacking IP — the per-IP grouping happens inside the ES|QL query itself (`STATS ... BY source_ip`) instead of through Kibana's native alert-grouping. For a real deployment I'd use Kibana's built-in grouping so each source IP gets its own alert instance.
- The threshold (5 in 5 minutes) is deliberately loose for a lab. In production I'd tune it against actual baseline traffic — a user fat-fingering their password twice shouldn't trip the same alert as a brute-force tool.
