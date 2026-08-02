# Detection: SSH Brute Force

**MITRE ATT&CK:** [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/) (Tactic: Credential Access)

## Summary

Flags any source IP with more than 5 failed SSH login attempts within a rolling window — the signature of an automated password-guessing attack against SSH.

## Simulated Attack

From the Kali VM, ran Hydra against the Ubuntu victim's SSH service using a wordlist:

```
hydra -l ubuntu -P /usr/share/wordlists/rockyou.txt -t 4 ssh://192.168.56.104
```

## Log Evidence

Each failed attempt generates a line in `/var/log/auth.log`, shipped by Elastic Agent into the `logs-auth.log-default` data stream:

```
Failed password for invalid user admin from 203.0.113.5 port 51000 ssh2
```

## Detection Query (ES|QL)

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

Rule fired against the live Hydra attack, generating a real Kibana alert tagged `credential-access`, `mitre-t1110`. Confirmed via Kibana's Rules > Alert History: rule executed on schedule, correctly transitioned from Active to Recovered once the attack burst ended.

## Notes

- The rule alerts as a single event per check cycle rather than one alert per attacking IP, since per-IP grouping happens inside the ES|QL query (`STATS ... BY source_ip`) rather than through Kibana's native alert-grouping feature. A production version would use Kibana's built-in grouping to generate a distinct alert instance per source IP.
- Threshold (`> 5` in 5 minutes) is intentionally lenient for a lab environment; a real deployment would tune this against baseline traffic to avoid false positives from legitimate retry behavior (e.g. a user mistyping a password twice).
