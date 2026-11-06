#!/usr/bin/env python3
"""Summarise a tracker HTML file, or export its embedded data.

Usage:
    .venv/bin/python tools/tracker_read.py TRACKER.html            # summary with per-issue progress
    .venv/bin/python tools/tracker_read.py TRACKER.html --export DIR

--export writes data.json, checked.json, fp.json and notes.json into DIR, ready
for tracker_inject.py (for example to migrate a project onto a newer template:
tracker_inject.py DIR/data.json new.html --notes DIR/notes.json --checked
DIR/checked.json --fp DIR/fp.json).

Note: checkbox, FP and note state lives in the file only after the user pressed
Save. Unsaved state sits in that user's browser localStorage and cannot be read here.
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import trackerlib  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("tracker")
    ap.add_argument("--export", metavar="DIR")
    a = ap.parse_args()
    t = trackerlib.read_tracker(a.tracker)
    d = t["INITIAL_DATA"]
    checked, fp, notes = set(t["PRE_CHECKED"]), set(t["PRE_FP"]), t["PRE_NOTES"]

    print(f'version {t["TRACKER_VERSION"]} | meta {d["meta"]} | saved {t["SAVED_DATE"]!r} | stamp {t["FILE_STAMP"]!r}')
    n = sum(len(i["tasks"]) for i in d["issues"])
    print(f'{len(d["issues"])} issues, {len(d["machines"])} machines, {n} tasks | '
          f'{len(checked)} checked, {len(fp)} false positive, {len(notes)} notes')
    for i in d["issues"]:
        ids = [x["id"] for x in i["tasks"]]
        done = sum(1 for x in ids if x in checked)
        nfp = sum(1 for x in ids if x in fp)
        print(f' {i["pid"]:>14} {i["score"]:4} {i["src"]:6} {i["effort"]:6} {len(ids):3}t {done:3}done {nfp:2}fp  '
              f'[{i["workstream"]}] {i["name"][:70]}')

    if a.export:
        os.makedirs(a.export, exist_ok=True)
        for name, val in (("data", d), ("checked", sorted(checked)), ("fp", sorted(fp)), ("notes", notes)):
            with open(os.path.join(a.export, f"{name}.json"), "w", encoding="utf-8") as f:
                json.dump(val, f, ensure_ascii=False, indent=2)
        print(f"exported to {a.export}")


if __name__ == "__main__":
    main()
