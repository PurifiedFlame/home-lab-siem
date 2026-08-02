# Detection: Privilege Escalation via Sudo

**MITRE ATT&CK:** [T1548.003 - Abuse Elevation Control Mechanism: Sudo and Sudo Caching](https://attack.mitre.org/techniques/T1548/003/) (Tactic: Privilege Escalation)

## Summary

Flags any use of `sudo` by an account outside the known set of legitimate administrators — the signature of an attacker who has compromised a low-privilege account that (correctly or via misconfiguration) has sudo rights, and is using it to escalate to root.

## Simulated Attack

Simulated a misconfigured low-privilege service account being abused after compromise:

```
# As the legitimate admin (ubuntu):
sudo useradd -m -s /bin/bash webapp
sudo passwd webapp
sudo usermod -aG sudo webapp    # the misconfiguration: this account shouldn't have sudo

# As the "attacker," now in possession of webapp's credentials:
ssh webapp@192.168.56.104
sudo whoami
sudo cat /etc/shadow            # classic post-escalation move: dumping password hashes
```

## Log Evidence

`sudo` logs every invocation to `auth.log`, including the acting user, target user, and full command:

```
sudo: webapp : TTY=/dev/pts/1 ; PWD=/home/webapp ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow
```

## Detection Query (ES|QL)

```
FROM logs-auth.log-default
| WHERE @timestamp > NOW() - 5 minutes
| WHERE message LIKE "*sudo:*COMMAND=*"
| GROK message """%{TIMESTAMP_ISO8601:log_timestamp} %{SYSLOGHOST:hostname} sudo: %{USERNAME:sudo_user} : TTY=%{DATA:tty} ; PWD=%{DATA:pwd} ; USER=%{USERNAME:target_user} ; COMMAND=%{GREEDYDATA:command}"""
| WHERE sudo_user != "ubuntu"
| KEEP sudo_user, target_user, tty, command
```

`ubuntu` is treated as the one known, expected administrator account for this environment; any other account invoking `sudo` is flagged.

## Result

Rule correctly matched both `sudo` commands run by `webapp` (`whoami` and `cat /etc/shadow`), confirmed via Kibana's query test panel before enabling the rule live.

## Notes

- This is an allowlist-based detection (flag anyone *except* known admins) rather than a signature-based one (flag specific suspicious commands). That tradeoff is deliberate: it catches privilege escalation regardless of which command the attacker runs, at the cost of needing the allowlist kept up to date as legitimate admin accounts change. A more mature version would pull the expected-admin list from a maintained asset inventory rather than hardcoding a single username.
