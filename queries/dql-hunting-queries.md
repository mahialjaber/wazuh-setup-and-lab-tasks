# 🕵️ SOC Threat Hunting Queries Handbook

This handbook provides the core OpenSearch Dashboard Query Language (DQL) queries developed during the 10-Task Gauntlet to slice through background telemetry, isolate adversary actions, and eliminate alert fatigue.

> **How to use:** run these in the Wazuh Dashboard DQL bar and you can also set the time range with the time picker. Section 1 comes from Task 06 and was run in the lab (42 hits); the rest are starting points - validate field names against your own index mappings before relying on them.

---

## 1. Gauntlet Task 06: High-Severity Triage Filter

Used during **Task 06** to isolate real endpoint threats while eliminating manager internal heartbeat spam and routine network disconnection noise:

```sql
rule.level >= 8 and not agent.id: "000" and not rule.description: *disconnect* and @timestamp >= now-24h
```

---

## 2. Threat Intel & Payload Hunting (VirusTotal)

Find all files flagged as malicious by VirusTotal threat intelligence enrichment across all fleet agents:

```sql
data.integration: "virustotal" and data.virustotal.malicious: 1
```

Find high-detection payloads where more than 10 antivirus engines flagged the sample:

```sql
data.virustotal.positives >= 10
```

---

## 3. Windows Process Lineage & LOLBins Forensics (Event ID 4688 / Sysmon EID 1)

Find interactive commands spawned by Windows script interpreters or administrative shells:

```sql
agent.id: "001" and (data.win.eventdata.parentProcessName: *cmd.exe or data.win.eventdata.parentProcessName: *powershell.exe)
```

Find process executions containing encoded PowerShell cradles or privilege discovery flags:

```sql
data.win.eventdata.commandLine: (*whoami* or *-enc* or *DownloadString* or *Invoke-Expression* or *IEX*)
```

Hunt for remote service creations (Sysinternals `PSEXESVC` vs Impacket randomized service installations):

```sql
# Sysinternals PsExec service execution
data.win.system.eventID: "7045" and data.win.eventdata.serviceName: *PSEXESVC*

# Impacket PsExec randomized service execution: DQL has no regex support, so use the
# Dev Tools console instead (untested draft - confirm the imagePath field is a keyword type):
#   GET wazuh-alerts-*/_search
#   { "query": { "bool": { "must": [
#       { "match":  { "data.win.system.eventID": "7045" } },
#       { "regexp": { "data.win.eventdata.imagePath": ".*\\\\[A-Za-z0-9]{4,8}\\.exe" } } ] } } }
```

---

## 4. Linux Authentication & Brute-Force Hunting

Find all failed SSH authentication attempts across Linux nodes within the past 12 hours:

```sql
rule.groups: "authentication_failed" and rule.groups: "sshd" and @timestamp >= now-12h
```

Hunt for successful logons from non-standard internal subnets:

```sql
rule.id: 5715 and not data.srcip: 192.168.198.*
```

---

## 5. Network Intrusion Detection (Suricata NIDS)

Isolate all Network IDS alerts originating from the attacker machine (`192.168.198.128` or Kali's IPv6):

```sql
location: "/var/log/suricata/eve.json" and data.alert.severity <= 2
```

Find port scan and reconnaissance signatures:

```sql
data.alert.category: "Attempted Information Leak" or data.alert.signature: *Scan* or data.alert.signature: *Nmap*
```

---

## 6. Real-Time File Integrity Monitoring (FIM)

Isolate all binary file tampering events across `/usr/bin`, `/usr/sbin`, or `C:\Users\Public`:

```sql
rule.groups: "syscheck_entry_modified" and (syscheck.path: /usr/bin/* or syscheck.path: C\:\\Users\\Public\\*)
```
