#!/usr/bin/env python3
"""Place a DATA payload (and optional notes / checked / FP state) into the template.

Usage:
    .venv/bin/python tools/tracker_inject.py PAYLOAD.json OUT.html \
        [--template remediation_tracker_template.html] [--notes NOTES.json] \
        [--checked CHECKED.json] [--fp FP.json]

PAYLOAD.json is the schema v200 DATA object. NOTES.json is {task_id: "note"};
CHECKED.json and FP.json are lists of task ids. The payload is validated first
(unique ids, sanitize-safe slugs, no '};' or '</').
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import trackerlib  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load(p):
    if not p:
        return None
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("payload")
    ap.add_argument("out")
    ap.add_argument("--template", default=os.path.join(ROOT, "remediation_tracker_template.html"))
    ap.add_argument("--notes")
    ap.add_argument("--checked")
    ap.add_argument("--fp")
    a = ap.parse_args()
    trackerlib.inject(a.template, a.out, load(a.payload), load(a.notes), load(a.checked), load(a.fp))


if __name__ == "__main__":
    main()
