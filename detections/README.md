# 🛡️ Detection Engineering Suite (`detections/`)

This directory houses the custom detection rules, suppression logic, and MITRE ATT&CK mappings authored during the 10-Task Gauntlet.

---

## 📋 Rule Catalog Summary

| Rule ID | Level | Classification | Trigger / Logic Summary | MITRE ATT&CK |
| :---: | :---: | :--- | :--- | :--- |
| **`100025`** | **10** | High Reconnaissance | PCRE2 regex matching `whoami /priv` or `cat /etc/shadow` across Windows and Linux. | **T1033**, **T1003.008** |
| **`100060`** | **0** | False Positive Tuning | Silences Suricata ping signature `9000001` exclusively when originating from authorized Kali IPv6. | **T1046** |
| **`100011`** | **14** | Critical Breach | Correlates SSH authentication success following brute-force failures from same IP (`if_sid: 5715` + `if_matched_sid: 5720`). | **T1110**, **T1078** |
| **`5720`** | **10** | Overwrite Tuning | Lowers SSH brute-force threshold to exactly 10 failed attempts within 120s from the same IP. | **T1110** |
| **`5712`** | **10** | Overwrite Tuning | Lowers invalid user SSH brute-force threshold to exactly 10 attempts within 120s from the same IP. | **T1110** |

> **Status of each rule.** `100025`, `100060` and the `5712`/`5720` overrides were exercised in the lab (see `tasks/`). `100011` is referenced by Active Response but its success-after-failure chain has no separate evidence yet. `100025` is a *lab prototype* (unscoped regex, see the note in `local_rules.xml`).

## 🧪 Draft Rules (not deployed)

`100001` (reverse shell), `100010` (Windows brute-force then success), `100012` (PsExec) and `100013` (Impacket PsExec) were written but never replayed through `wazuh-logtest`, so they live in [`drafts/draft_rules_untested.xml`](drafts/draft_rules_untested.xml) with a list of known problems. They move back into `local_rules.xml` only after a positive sample, a negative sample and saved logtest output exist for each.

---

## ⚙️ Testing Custom Rules with `wazuh-logtest`

To validate custom detection rules without restarting the production manager daemon, execute `/var/ossec/bin/wazuh-logtest`:

```bash
sudo /var/ossec/bin/wazuh-logtest
```

### Test Case 1: Testing Windows Privilege Reconnaissance
* **Input String:** `powershell.exe: whoami /priv`
* **Expected Output:**
  ```text
  **Phase 1: Completed pre-decoding.
  **Phase 2: Completed decoding.
  **Phase 3: Completed filtering (rules).
      id: '100025'
      level: '10'
      description: 'Suspicious command execution: whoami /priv (Windows) or cat /etc/shadow (Linux)'
  **Alert to be generated.
  ```

### Test Case 2: Testing Linux Credential Access
* **Input String:** `bash: cat /etc/shadow`
* **Expected Output:** Triggers Rule `100025` with MITRE `T1003.008`.

---

## 🚀 Deployment Instructions

1. Append or replace the rules into `/var/ossec/etc/rules/local_rules.xml` on the Wazuh Manager.
2. Validate syntax:
   ```bash
   sudo /var/ossec/bin/wazuh-analysisd -t
   ```
3. Restart the Wazuh Manager service:
   ```bash
   sudo systemctl restart wazuh-manager
   ```
