# Tools

Python helpers for turning a `.nessus` export into a tracker, and for reading trackers back.

## Setup (once per machine)

Homebrew Python blocks system-wide `pip install` (PEP 668), so use a project virtualenv. `.venv/` is git ignored.

```bash
python3 -m venv .venv && .venv/bin/pip install -r tools/requirements.txt
```

## Files

| File | Purpose |
|------|---------|
| `nessus_parse.py` | Stream-parse a `.nessus` file (lxml `iterparse`, constant memory) into compact JSON: hosts, plugins with per-host port/service/output |
| `nessus_summary.py` | Triage views over that JSON: `table` (severity/score with prior-quarter host counts), `gone` (prior findings now absent), `hosts` (hosts missing vs prior), `dump` (per-host output for chosen plugins) |
| `docx2txt.py` | Flatten a customer report `.docx` to text (headings and tables kept) |
| `trackerlib.py` | Shared library: `Scan` wrapper, detail builders, `assemble()` to schema v200, `validate()`, tracker read/inject with brace-matching extraction |
| `example_build.py` | Minimal per-client build script to copy into `Projects/<client>/<quarter>/` |
| `tracker_inject.py` | CLI: payload JSON (+ notes / checked / FP) into the template |
| `tracker_read.py` | CLI: summarise a tracker (progress per issue) or `--export` its data, checked, FP and notes as JSON |

## New quarter workflow

```bash
# 1. Parse this quarter and the prior scan (writes outside the repo)
.venv/bin/python tools/nessus_parse.py "<cur>.nessus" /tmp/cur.json
.venv/bin/python tools/nessus_parse.py "<prior>.nessus" /tmp/prior.json

# 2. Triage against the customer report
.venv/bin/python tools/docx2txt.py "<report>.docx" /tmp/report.txt
.venv/bin/python tools/nessus_summary.py table /tmp/cur.json --prior /tmp/prior.json
.venv/bin/python tools/nessus_summary.py gone  /tmp/cur.json /tmp/prior.json
.venv/bin/python tools/nessus_summary.py dump  /tmp/cur.json 42873,94437

# 3. Carry forward last quarter's notes and progress
.venv/bin/python tools/tracker_read.py Projects/<client>/<last>.html --export /tmp/last

# 4. Write the build script (start from example_build.py or last quarter's) and run it
#    (example_build.py takes: CUR.json OUT.html --prior PRIOR.json)
.venv/bin/python Projects/<client>/<quarter>/build_tracker.py /tmp/cur.json \
    Projects/<client>/<quarter>/<client>_<quarter>_remediation.html --prior /tmp/prior.json
```

The build script holds client data (IPs, hostnames, customer notes), so it lives under `Projects/`, which is git ignored. Only the generic tools are committed.

Progress, False Positive marks and notes are in a tracker file only after a user pressed **Save**. Unsaved state stays in that user's browser and `tracker_read.py` cannot see it.

## Migrating a tracker onto a newer template

```bash
.venv/bin/python tools/tracker_read.py old.html --export /tmp/m
.venv/bin/python tools/tracker_inject.py /tmp/m/data.json new.html \
    --notes /tmp/m/notes.json --checked /tmp/m/checked.json --fp /tmp/m/fp.json
```

This carries `INITIAL_DATA`, `PRE_CHECKED`, `PRE_FP` and `PRE_NOTES`. `SAVED_DATE` is cleared and theme/stamp constants take the template defaults; copy them across by hand if they matter.
