# 🛡️ Task 05: Active Defense Verification (Automated IP Blocking)

## 📌 Challenge Overview

| Attribute | Specification |
| :--- | :--- |
| **Domain** | Active Response, Dynamic Host Firewalling & Incident Containment |
| **Target Host** | Rocky Linux 9.8 (`192.168.198.132` \| Agent ID: `002`) |
| **Adversary Machine** | Kali Linux (`192.168.198.128`) |
| **Attack Vector** | High-Rate SSH Credential Brute-Force via NetExec (`nxc`) |
| **Containment Action** | Dynamic Firewall Drop (`firewall-drop` script) |
| **Triggered Rules** | **Rule `5712` / `5720` / `100011`** |
| **MITRE ATT&CK Mapping** | **T1110** (Brute Force), **T1078** (Valid Accounts) |
| **Verification Status** | **Verified in Live Lab** |

---

## 🎯 The Mission Scenario

An external attacker from Kali Linux initiates an automated SSH brute-force attack against an enterprise Linux server.

The SOC Lead requires:
1. Simulating an authentication brute-force attack from Kali using NetExec (`nxc`) with a wordlist of incorrect credentials.
2. Configuring Wazuh Active Response on the Manager to automatically trigger `firewall-drop` upon detecting repeated authentication failures.
3. Verifying that the attacker's network connection is severed in real-time, locking out the attacking IP address.

---

## ⚙️ Technical Implementation & The 5-Hour Troubleshooting Battle

This challenge proved to be one of the most intense, authentic engineering learning experiences in the entire gauntlet. I spent 5 continuous hours diagnosing every moving part of the Linux host defense pipeline.

### 1. The Linux Endpoint Hardening
Rocky Linux 9 defaults to modern `nftables` and `systemd-journald` without traditional syslog files. The following steps were executed:
```bash
# Installed rsyslog and iptables-nft translation layer
sudo dnf install -y rsyslog iptables-nft
sudo systemctl enable --now rsyslog

# Started firewalld host firewall service
sudo systemctl enable --now firewalld
```

Monitored `/var/log/secure` as a syslog source in Rocky Linux's `/var/ossec/etc/ossec.conf`:
```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/secure</location>
</localfile>
```

### 2. Wazuh Manager Active Response Configuration
In `/var/ossec/etc/ossec.conf` on the Ubuntu Manager:
```xml
<!-- Dynamic Active Response: Drop Kali upon SSH Brute Force -->
<active-response>
  <command>firewall-drop</command>
  <location>defined-agent</location>
  <agent_id>002</agent_id>
  <rules_id>5712, 5720, 100011</rules_id>
  <timeout>1200</timeout>
</active-response>
```

### 3. Adversary Attack Execution from Kali Linux
From Kali Linux (`192.168.198.128`), launched NetExec against Rocky Linux:
```bash
nxc ssh 192.168.198.132 -u 'perker' -p /usr/share/wordlists/fasttrack.txt
```

---

## 🔍 Verified Investigation Deliverables

### The Moment of Containment:
As the brute-force attack crossed the alert threshold, NetExec experienced catastrophic connection drops:
```text
[08:54:46] ERROR Internal Paramiko error for perker:winter2021, Error reading SSH protocol banner
[08:54:48] ERROR Internal Paramiko error for perker:spring2020, Error reading SSH protocol banner
[08:54:50] ERROR Internal Paramiko error for perker:Summer2020, Error reading SSH protocol banner
```
The SSH daemon stopped responding to Kali because incoming packets were dropped at the kernel firewall layer!

---

## 📸 Verified Technical Evidence

### 1. Active Response Configuration in Manager `ossec.conf`
Shows initial `firewall-drop` testing block (`<location>local</location>`, `600s` timeout) prior to pinning `defined-agent` (`002`), adding `5720`, and raising timeout to `1200s`:

![Manager Active Response Config](../../assets/screenshots/task05-manager-active-response-config.png)

### 2. Rocky Linux `iptables-nft` & `rsyslog` Deployment
Shows package installation and daemon enablement on the victim host:

![Rocky Linux iptables and rsyslog Setup](../../assets/screenshots/task05-rocky-iptables-rsyslog-setup.png)

### 3. Kali Linux NetExec Connection Drop
NetExec Paramiko banner-read errors during active password spraying:

![Kali Linux SSH Brute Force Drop](../../assets/screenshots/task05-kali-ssh-bruteforce-drop.png)

### 4. Suricata SSH Protocol Decoding
Wazuh dashboard showing `SURICATA SSH invalid banner` events in the Threat Hunting table alongside Suricata stream telemetry:

![Suricata SSH Banner Alert](../../assets/screenshots/task05-suricata-ssh-banner-alert.png)

---

## 🧠 Analyst Engineering Notes & Crucial Nuances

> **1. `<location>` Target Logic (`local` vs `server` vs `defined-agent`):**  
> * `<location>local</location>` executes the Active Response script on whichever node/agent **originated the log event**. For logs collected locally by Agent `002` (`/var/log/secure`), `local` targets Agent `002`; however, if logs arrive via remote `rsyslog` forwarding or manager-side ingestion, the originating node is the **Manager (`000`)**, so `local` runs on the Manager instead of the Rocky Linux victim.
> * `<location>server</location>` always runs on the Wazuh Manager itself.
> * `<location>defined-agent</location>` with `<agent_id>002</agent_id>` explicitly dispatches the AR execution command over `TCP 1514` to **Agent 002 (Rocky Linux)** regardless of log ingestion path, ensuring Rocky's local firewall drops the attacker.
>
> **2. SSH Rule Trigger Coverage (`5712` vs `5720`):**  
> * Rule `5712` only matches **invalid-user** SSH failures (`if_matched_sid: 5710`), whereas spraying an existing local account such as `perker` fires **Rule `5720`** (failed password for a valid user, `if_matched_sid: 5716`). Including both `5712` and `5720` (alongside escalation rule `100011`) in `<rules_id>` prevents valid-user sprays from bypassing containment prior to a successful login.
>
> **3. Rocky Linux 9 Firewall Backend:**  
> * Rocky Linux 9 runs `firewalld` on top of `nftables`. Ensure either `iptables-nft` is available for `firewall-drop` or use Wazuh's native `firewalld-drop` executable with `firewalld` running, and verify execution in `/var/ossec/logs/active-responses.log`.
