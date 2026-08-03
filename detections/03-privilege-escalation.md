# Detection: Privilege Escalation via Sudo

**MITRE ATT&CK:** [T1548.003 - Abuse Elevation Control Mechanism: Sudo and Sudo Caching](https://attack.mitre.org/techniques/T1548/003/) (Tactic: Privilege Escalation)

## What it catches

Any use of `sudo` by an account outside my known list of admins. That's the pattern you'd see if an attacker got hold of a low-privilege account that (correctly or through a misconfiguration) has sudo rights, and is using it to get to root.

## The attack

I simulated a misconfigured service account getting abused after compromise:

```
# As the legitimate admin (ubuntu):
sudo useradd -m -s /bin/bash webapp
sudo passwd webapp
sudo usermod -aG sudo webapp    # the misconfig: this account shouldn't have sudo at all

# As the "attacker," now holding webapp's credentials:
ssh webapp@192.168.56.104
sudo whoami
sudo cat /etc/shadow            # classic post-escalation move: dump the password hashes
```

## Log evidence

`sudo` logs every invocation to `auth.log`, including who ran it, what they targeted, and the full command:

```
sudo: webapp : TTY=/dev/pts/1 ; PWD=/home/webapp ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow
```

## Detection query (ES|QL)

```
FROM logs-auth.log-default
| WHERE @timestamp > NOW() - 5 minutes
| WHERE message LIKE "*sudo:*COMMAND=*"
| GROK message """%{TIMESTAMP_ISO8601:log_timestamp} %{SYSLOGHOST:hostname} sudo: %{USERNAME:sudo_user} : TTY=%{DATA:tty} ; PWD=%{DATA:pwd} ; USER=%{USERNAME:target_user} ; COMMAND=%{GREEDYDATA:command}"""
| WHERE sudo_user != "ubuntu"
| KEEP sudo_user, target_user, tty, command
```

I treated `ubuntu` as the one known admin account in this environment — anyone else invoking sudo gets flagged.

## Result

The rule caught both sudo commands run by `webapp` (`whoami` and `cat /etc/shadow`). I confirmed this in Kibana's query test panel before turning the rule on live.

## Things I noticed / would do differently

- This is allowlist-based (flag anyone except known admins) rather than signature-based (flag specific suspicious commands). I went this way on purpose — it catches escalation no matter what command the attacker runs, but it means the allowlist has to stay current as real admin accounts change. In a real environment I'd pull that list from an asset inventory instead of hardcoding a single username the way I did here.
