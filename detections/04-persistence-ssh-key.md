# Detection: SSH Key Persistence

**MITRE ATT&CK:** [T1098.004 - Account Manipulation: SSH Authorized Keys](https://attack.mitre.org/techniques/T1098/004/) (Tactic: Persistence)

## Summary

Flags any public-key SSH login by an account outside the known set of legitimate administrators — the signature of an attacker who planted their own SSH key on a compromised account to maintain passwordless access, without needing to repeat the initial compromise.

## Simulated Attack

Continuing from the privilege escalation scenario, the compromised `webapp` account plants a backdoor key for itself:

```
# As webapp (already compromised in the prior stage):
ssh-keygen -t rsa -f ~/.ssh/backdoor -N ""
cat ~/.ssh/backdoor.pub >> ~/.ssh/authorized_keys
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
```

The private key is exfiltrated to the attacker machine (Kali) and used to log back in without a password — proving the persistence mechanism works:

```
ssh -i backdoor_key webapp@192.168.56.104
```

## Log Evidence

```
sshd-session[2261]: Accepted publickey for webapp from 192.168.56.106 port 60390 ssh2: RSA SHA256:f9lLIyy4KPBdRC8Uw7nOJdP5cin0tpP4desAoQX10Cs
```

Note the process name is `sshd-session`, not `sshd` — newer OpenSSH versions split per-connection handling into a separate process from the main listener.

## Detection Query (ES|QL)

```
FROM logs-auth.log-default
| WHERE @timestamp > NOW() - 5 minutes
| WHERE message LIKE "*Accepted publickey*"
| GROK message """%{TIMESTAMP_ISO8601:log_timestamp} %{SYSLOGHOST:hostname} sshd-session\[%{POSINT:pid}\]: Accepted %{WORD:auth_method} for %{USERNAME:username} from %{IP:source_ip} port %{POSINT:source_port} %{WORD:protocol}%{GREEDYDATA}"""
| WHERE username != "ubuntu"
| KEEP username, auth_method, source_ip, source_port
```

## Result

Rule correctly matched the backdoor login (`username: webapp`), confirmed via the query test panel.

## Notes

- This detects *use* of a planted key (the login event), not the *planting* of the key itself (the file write to `authorized_keys`). A more thorough detection would also monitor file integrity on `~/.ssh/authorized_keys` paths directly (e.g. via `auditd` watch rules), catching the persistence mechanism at creation time rather than only when it's exercised. That was out of scope for this lab to keep the log pipeline consistent with the other three detections, but is a natural next step.
- Chains directly off the privilege escalation detection — together they tell a complete story: an attacker compromises a low-privilege account, escalates via a sudo misconfiguration, and plants persistence to avoid needing to repeat the compromise.
