#!/usr/bin/env python3
"""Minimal per-client build script. Copy to Projects/<client>/<quarter>/build_tracker.py and edit.

Usage:
    .venv/bin/python Projects/<client>/<quarter>/build_tracker.py CUR.json OUT.html [--prior PRIOR.json]

CUR.json / PRIOR.json come from tools/nessus_parse.py. --prior is optional;
without it no "Also present in the prior scan" lines are added.

Each Issue is one card in the tracker. Fields, in order:
    key          short id used by CARRIED_NOTES / tid_for()
    pids         plugin IDs; several = merged into one issue (one fix closes all)
    name         card title
    workstream   group heading (who does the work)
    effort       Low / Medium / High
    estimate     free text, e.g. "1 to 2 hours"
    cvss         score shown on the badge (use the report's number)
    history      first remediation line, e.g. "Open since Q1 2026." ('' to omit)
    builder      callable -> [(ip, detail), ...]; detail segments split on ' | '
    remediation  steps, ' | '-separated; a segment ending in ':' renders as a header
    caveat       warning box text ('' for none)
    prior_re     regex on prior-scan plugin names to flag "Also present in the <prior> scan"
"""
import argparse
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(ROOT, "remediation_tracker_template.html")):  # walk up to the repo root
    parent = os.path.dirname(ROOT)
    assert parent != ROOT, "run from inside the remediation-tracker repo"
    ROOT = parent
sys.path.insert(0, os.path.join(ROOT, "tools"))
from trackerlib import Issue, Scan, Slugger, assemble, flat, grab, inject, summary  # noqa: E402,F401

SEED = 20260101                     # keep fixed per tracker so rebuilds keep task ids
META = {"scan": "Client Q1 2026 Internal", "scan_date": "2026-01-15"}   # scan name keys localStorage
PRIOR_LABEL = "Q4 2025"

ap = argparse.ArgumentParser()
ap.add_argument("cur")
ap.add_argument("out")
ap.add_argument("--prior")
ap.add_argument("--template", default=os.path.join(ROOT, "remediation_tracker_template.html"))
args = ap.parse_args()

scan = Scan(args.cur)
prior = Scan(args.prior) if args.prior else None

ISSUES = [
    # Version check plugin: ver_task() pulls "<path> <installed> → <fixed>" from the output.
    Issue("curl", ["342616"], "Curl < 8.22.0", "Windows server patching", "Low", "1 to 2 hours", 9.8,
          "", scan.simple(["342616"]),
          "Install the latest Windows cumulative update. | If that is not possible, install a supported curl ahead of System32 in PATH.",
          "", r"^Curl "),
    # Fixed text per host.
    Issue("smb", ["57608"], "SMB Signing Not Required", "Protocol hardening", "Low", "1 hour", 5.3,
          "", scan.one("57608", lambda ip: "SMB signing enabled but not required on 445/tcp"),
          "Windows: | Set 'Digitally sign communications (always)' to Enabled through GPO.",
          "Test scan-to-folder on printers after enforcing signing.", r"SMB Signing"),
]

DATA, tid_for = assemble(scan, ISSUES, META, Slugger(SEED), prior=prior, prior_label=PRIOR_LABEL)

NOTES = {}
# NOTES[tid_for("smb", "10.0.0.5")] = "Customer: printer replaced in March."

summary(DATA, NOTES)
inject(args.template, args.out, DATA, NOTES)
