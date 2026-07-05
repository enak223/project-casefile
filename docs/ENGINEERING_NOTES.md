# 🛠️ Engineering Notes

Hard-won findings from building Project Casefile. Each entry is a problem that cost real debugging time, its root cause, and the fix — recorded so they don't have to be rediscovered.

---

## v0.2 — Wazuh → n8n → IRIS Ingestion

### 1. `sed` on `ossec.conf` replaces *every* `</ossec_config>`

**Symptom:** Inserting an `<integration>` block by replacing `</ossec_config>` with sed produced **three** copies of the integration — one per config block in the file.

**Root cause:** `ossec.conf` is not a single config block. It contains multiple `<ossec_config>...</ossec_config>` sections, so a naive `sed "s|</ossec_config>|...new...</ossec_config>|"` matches and rewrites all of them.

**Fix:** Don't inject into an existing closing tag. Remove any prior copy with a targeted regex, then **append a new dedicated `<ossec_config>` block** at the end of the file:

```python
import re
c = open('/var/ossec/etc/ossec.conf').read()
c = re.sub(r'<ossec_config>\s*<integration>\s*<name>custom-n8n</name>.*?</integration>\s*</ossec_config>\n?', '', c, flags=re.S)
c = c.rstrip() + '\n\n<ossec_config>\n  <integration>...</integration>\n</ossec_config>\n'
open('/var/ossec/etc/ossec.conf','w').write(c)
```

**Verify:** `grep -c "custom-n8n" ossec.conf` must return exactly `1`.

---

### 2. `wazuh-integratord` runs integration scripts with **system** Python, not Wazuh's framework Python

**Symptom:** Rule 5763 fired and was written to `alerts.json`, but no alert ever reached n8n. `integrations.log` was empty. The integrator debug log showed only `jqueue_next()` looping — no `Sending new alert` line initially, and once alerts *were* being read, the script silently failed.

**The misleading test:** Checking `import requests` with
`/var/ossec/framework/python/bin/python3 -c "import requests"` returned **OK** — but that is *not* the interpreter the integrator uses.

**Root cause:** The integration script had `#!/usr/bin/env python3`, so `wazuh-integratord` executed it with the **system** `/usr/bin/python3`, which does **not** have the `requests` module. The script crashed on `import requests` with `ModuleNotFoundError`, exit status 1 — and the failure only surfaced in the integrator debug log:

```
integrator.c:451 DEBUG: ModuleNotFoundError: No module named 'requests'
integrator.c:460 ERROR: Unable to run integration for custom-n8n
```

**Fix:** Remove the external dependency entirely. Rewrite the script using only Python's standard library (`urllib.request` instead of `requests`), so it works regardless of which interpreter runs it:

```python
#!/usr/bin/env python3
import sys, json, urllib.request, ssl
alert = json.load(open(sys.argv[1]))
data = json.dumps(alert).encode("utf-8")
req = urllib.request.Request(sys.argv[3], data=data, headers={"Content-Type": "application/json"})
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
urllib.request.urlopen(req, timeout=10, context=ctx)
```

**Diagnostic that cracked it:** Enable `integrator.debug=2` in `local_internal_options.conf`, restart, then append a known-good alert directly to `alerts.json` and watch the integrator log with `grep -a` (the log contains binary bytes; without `-a`, grep hides matching lines as "binary file matches"). A working integrator always logs `Sending new alert` when *any* line is appended — if that line never appears, the daemon isn't reading the file; if it appears followed by a script error, the script is the problem.

---

### 3. IRIS alert severity IDs are **non-linear**

**Symptom:** Level-10 (brute force) alerts kept arriving in IRIS as **Low** even though the n8n code mapped them to severity `4`.

**Root cause:** Assumed a linear scale (`2=Low, 3=Med, 4=High, 5=Crit`). IRIS's actual alert severity IDs are not linear:

| severity_id | Meaning |
|---|---|
| 2 | Unspecified |
| 3 | Informational |
| 4 | Low |
| 5 | High |
| 6 | Critical |
| 1 | Medium *(yes — Medium is 1, out of order)* |

The initial curl test was the tell: sending `alert_severity_id: 4` returned `severity_name: "Low"`.

**Fix — Wazuh level → IRIS severity_id mapping** (matches Wazuh's official integration):

```javascript
let sev = 2;                    // <5  → Unspecified
if (lvl >= 13) sev = 6;         // ≥13 → Critical
else if (lvl >= 10) sev = 5;    // 10–12 → High
else if (lvl >= 7)  sev = 4;    // 7–9  → Low
else if (lvl >= 5)  sev = 3;    // 5–6  → Informational
```

---

### 4. Alert noise: filter by `rule_id`, not `group` or `level`

**Symptom:** One `hydra` run created ~20 IRIS alerts — one per individual `sshd: authentication failed` (rule 5760, level 5).

**Root cause:** The integration forwarded every auth-failure event. Wazuh already aggregates repeated failures into a single brute-force summary (rule **5763**, level 10), which is the alert actually worth a case.

**Fix:** Filter the integration to the summary rule(s) only:

```xml
<rule_id>5763,5712</rule_id>
```

This collapsed ~20 alerts per attack down to one meaningful High-severity alert. Effectively deduplication at the source, before n8n.

---

### Minor / environment notes

- **Postgres password `%` breaks IRIS.** A `%` in `POSTGRES_PASSWORD` crashes the app on boot (`ValueError: invalid interpolation syntax` — Python configparser treats `%` as special). Avoid `%`, and also `$ : / @` to be safe. Recreate DB volumes (`docker compose down -v`) after changing.
- **IRIS container runs on UTC.** Alert timestamps show ~4–5h ahead of local (Florida). Cosmetic; note it when reading timelines.
- **OneDrive + git.** The repo lives under OneDrive. Two gotchas: Files-On-Demand can virtualize files (pin with "Always keep on this device"), and Notepad silently appends `.txt` (a file shown as `x.json` may really be `x.json.txt`). Check "Type of file" in Properties.
- **Two Python interpreters, two `requests`.** See finding #2 — never assume the framework Python's packages are available to integration scripts.
