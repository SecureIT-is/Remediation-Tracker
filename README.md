# Remediation Tracker Template

Standalone HTML remediation checklist generated from Nessus vulnerability scan data. Dual view (by issue / by machine), synced checkboxes, localStorage persistence, search and filter. No server required.

## Files

| File | Audience | Purpose |
|------|----------|---------|
| `remediation_tracker_template.html` | End product | The tracker itself. Contains a labeled `DATA` section near the top of the script block with example data. Replace `SCAN_NAME` and the `DATA` JSON object with real scan data to produce a new tracker |
| `Instructions.md` | Humans | Full JSON schema reference. Documents every field, its type, where it comes from in a .nessus file, and which fields require analyst judgment |
| `LLM-INSTRUCTIONS.md` | LLM co-pilot | Step by step Python workflow for parsing a .nessus file with `lxml.iterparse`, filtering by VPR/CVSS threshold, selecting achievable issues, building the JSON payload, and injecting it into the template |

## Usage

1. Run a Nessus scan and export the `.nessus` file.
2. Follow `LLM-INSTRUCTIONS.md` (or hand it to your LLM) to parse, filter, and curate findings.
3. Copy the template, replace `SCAN_NAME` and `DATA`, open in a browser.

Checkbox state persists in `localStorage`, keyed by scan name, so multiple trackers can coexist in the same browser without conflict.
