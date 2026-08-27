# Remediation Tracker Template

Standalone HTML remediation checklist generated from Nessus vulnerability scan data. Dual view (by issue / by machine), synced checkboxes, localStorage persistence, search and filter. No server required.

## Files

| File | Audience | Purpose |
|------|----------|---------|
| `remediation_tracker_template.html` | End product | The tracker itself. Contains a labeled `INITIAL_DATA` section near the top of the script block with example data. Replace the `INITIAL_DATA` JSON object with real scan data to produce a new tracker |
| `Instructions.md` | Humans | Full JSON schema reference. Documents every field, its type, where it comes from in a .nessus file, and which fields require analyst judgment |
| `LLM-INSTRUCTIONS.md` | LLM co-pilot | Step by step Python workflow for parsing a .nessus file with `lxml.iterparse`, filtering by VPR/CVSS threshold, selecting achievable issues, building the JSON payload, and injecting it into the template |

## Projects folder

The `Projects/` directory is where generated client trackers live. It is git ignored so client data never syncs to the remote repository. Only the folder itself (via `.gitkeep`) is tracked.

To create a new project, make a subfolder under `Projects/` named for the engagement (e.g. `Projects/ACME/`) and place the generated HTML file there.

## Usage

1. Run a Nessus scan and export the `.nessus` file.
2. Follow `LLM-INSTRUCTIONS.md` (or hand it to your LLM) to parse, filter, and curate findings.
3. Copy the template, replace `INITIAL_DATA`, and save into `Projects/<client>/`.
4. Open in a browser. Checkbox state persists in `localStorage`, keyed by scan name, so multiple trackers can coexist in the same browser without conflict.
