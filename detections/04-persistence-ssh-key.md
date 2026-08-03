# Detection: SSH Key Persistence

**MITRE ATT&CK:** [T1098.004 - Account Manipulation: SSH Authorized Keys](https://attack.mitre.org/techniques/T1098/004/) (Tactic: Persistence)

## What it catches

Any public-key SSH login from an account outside my known set of admins. That's what it looks like when an attacker plants their own SSH key on a compromised account so they can keep passwordless access without repeating the original compromise.

## The attack

Continuing from the privilege escalation stage, I had the compromised `webapp` account plant a backdoor key for itself:

```
# As webapp (already compromised in the prior stage):
ssh-keygen -t rsa -f ~/.ssh/backdoor -N ""
cat ~/.ssh/backdoor.pub >> ~/.ssh/authorized_keys
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
```

Then I pulled the private key over to the attacker machine (Kali) and used it to log back in without a password — proving the persistence mechanism actually worked, not just that the key existed:

```
ssh -i backdoor_key webapp@192.168.56.104
```

## Log evidence

```
sshd-session[2261]: Accepted publickey for webapp from 192.168.56.106 port 60390 ssh2: RSA SHA256:f9lLIyy4KPBdRC8Uw7nOJdP5cin0tpP4desAoQX10Cs
```

Worth noting: the process name here is `sshd-session`, not `sshd` — newer OpenSSH versions split per-connection handling into its own process from the main listener. I had to account for that in the GROK pattern.

## Detection query (ES|QL)

```
FROM logs-auth.log-default
| WHERE @timestamp > NOW() - 5 minutes
| WHERE message LIKE "*Accepted publickey*"
| GROK message """%{TIMESTAMP_ISO8601:log_timestamp} %{SYSLOGHOST:hostname} sshd-session\[%{POSINT:pid}\]: Accepted %{WORD:auth_method} for %{USERNAME:username} from %{IP:source_ip} port %{POSINT:source_port} %{WORD:protocol}%{GREEDYDATA}"""
| WHERE username != "ubuntu"
| KEEP username, auth_method, source_ip, source_port
```

## Result

The rule correctly matched the backdoor login (`username: webapp`), confirmed in the query test panel.

## Things I noticed / would do differently

- This only catches the *use* of a planted key (the login event), not the planting itself (the file write to `authorized_keys`). A more thorough setup would also watch `~/.ssh/authorized_keys` directly for changes — e.g. with `auditd` file integrity rules — to catch the persistence mechanism the moment it's created, not just when it gets used later. I kept this one scoped to the log pipeline I already had running rather than adding a new detection surface, but it's the natural next step.
- This one chains right off the privilege escalation detection — together they tell one continuous story: an attacker compromises a low-privilege account, escalates through a sudo misconfiguration, then plants persistence so they don't have to repeat the compromise.
