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

---

## v0.3 — Claude L1 Triage Layer

The goal of v0.3: insert Claude between n8n and IRIS so every alert arrives pre-triaged with a verdict, MITRE mapping, extracted IOCs, and written analyst notes. The AI logic was the easy part. Getting n8n's HTTP Request node to send correctly-typed JSON to two different strict APIs (Anthropic, then IRIS) was the entire fight.

### 5. n8n HTTP Request node mangles expression-built JSON bodies (the core v0.3 bug)

**Symptom:** A long cascade of errors when POSTing an expression-built body, each one shifting as we changed modes:
- `Unexpected token '=', "={"model"...` — expression sent as literal text
- `=[object Object]` — object reference not evaluated
- `The request body must be a JSON object, got str.` (Anthropic) — pre-stringified body sent as a quoted string
- `Input is a zero-length, empty document` — body dropped entirely
- `'str' object has no attribute 'pop'` (IRIS) — same string-not-object problem downstream

**Root cause:** n8n's HTTP Request node (v4.4, n8n 2.23.2) is genuinely inconsistent about how it serializes a body built from an expression. Passing `JSON.stringify(obj)` makes it send a **string**; passing `$json.obj` in the wrong field mode sends `[object Object]` or literal text; Raw mode sends the string verbatim (which strict APIs reject because they want an object).

**The winning pattern (confirmed against n8n docs):**
- Build the body as a **real object** in a Code node (where JS quoting just works). Return it as an object, not a stringified string.
- In the HTTP node: **Body Content Type = JSON**, **Specify Body = Using JSON**, field in **Expression mode**, referencing the object directly: `={{ $json.irisBody }}`.
- JSON mode + object reference is the only combination that preserves types and structure end-to-end.

### 6. "Using Fields Below" always sends values as strings — breaks integer fields

**Symptom:** With body set to "Using Fields Below," IRIS rejected `alert_severity_id` with `Not a valid integer.` even though the value was `5`.

**Root cause:** Per n8n's own docs: *"Using Fields Below always imports any parameter values as strings."* It sent `"5"` (string); IRIS's schema requires an integer. There is no per-field type toggle in this mode.

**Fix:** Abandon "Using Fields Below" for any body containing numbers or booleans. Use **Using JSON** with an object expression (finding #5) — JSON mode preserves the number type because the source object's `iris_severity_id` is a genuine JS number.

### 7. Anthropic model quirks in the n8n node

- The **"Anthropic Chat Model"** node is a sub-node for AI Agents — it has no message field and can't be wired inline. The correct node is **Anthropic → Message a Model** (a Text action).
- **`temperature` is deprecated** for current Sonnet models — passing it returns a 400. Remove the temperature option entirely.
- The node's response text lands at `content[0].text` as a JSON string; parse it defensively (a parse-failure fallback routes to `needs_review` so a malformed AI response never silently drops an alert).

### Severity mapping (correction from v0.2)

IRIS alert severity IDs, confirmed empirically: **2=Unspecified, 3=Informational, 4=Low, 5=High, 6=Critical** (Medium=1, out of order). Wazuh level → IRIS severity used in the Code node:
```
lvl >= 13 -> 6 (Critical) ; >= 10 -> 5 (High) ; >= 7 -> 4 (Low) ; >= 5 -> 3 (Info) ; else 2
```

### 8. Snapshot delta filled the host disk and corrupted the VM (infra incident)

**Symptom:** Mid-session, n8n went unreachable (`ERR_CONNECTION_TIMED_OUT`), then VMware threw *"The operation on file ubuntuai-cl1-000001.vmdk failed."*

**Root cause:** The `ubuntuai` VM was running on a snapshot delta (`-000001.vmdk`) on a nearly-full drive (E: had ~220 KB free). The delta grew until the disk filled; a write failed mid-flight and left the vmdk in a corrupt state.

**Recovery (order matters):**
1. **Cancel** the VMware dialog to power off cleanly — never **Continue** (forwarding a disk error to the running guest risks filesystem corruption).
2. Free space safely: delete leftover `.vmem` (saved-RAM) files of unused clones. **Never** hand-delete `.vmdk` files — that destroys the VM.
3. Repair the delta: `vmware-vdiskmanager.exe -R "path\to\-000001.vmdk"`.
4. Consolidate: Snapshot Manager → delete the snapshot (this *merges* the delta into the base, preserving current state and reclaiming space).

**Lesson:** Don't run homelab VMs on a near-full drive, and don't let snapshots live for weeks — the delta grows unbounded. All work was recovered; n8n persists workflows to its own DB, so nothing was lost.
