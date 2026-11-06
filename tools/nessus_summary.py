#!/usr/bin/env python3
"""Quick triage views over JSON produced by nessus_parse.py.

Usage:
    # Severity table (default High and Critical), with host counts from a prior quarter
    .venv/bin/python tools/nessus_summary.py table CUR.json [--prior PRIOR.json] [--min-sev 3]

    # Same, but rank by score threshold instead of severity
    .venv/bin/python tools/nessus_summary.py table CUR.json --prior PRIOR.json --min-score 8.5

    # Findings in the prior scan that are gone now (likely fixed, or host not scanned)
    .venv/bin/python tools/nessus_summary.py gone CUR.json PRIOR.json [--min-sev 3]

    # Per-host plugin output for chosen plugins, trimmed to N chars
    .venv/bin/python tools/nessus_summary.py dump CUR.json 42873,94437 [--chars 300]

    # Hosts present in the prior scan but missing now
    .venv/bin/python tools/nessus_summary.py hosts CUR.json PRIOR.json
"""
import argparse
import json


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def ip_key(ip):
    try:
        return tuple(int(x) for x in ip.split("."))
    except ValueError:
        return (999, ip)


def credentialed(d):
    c = sum(1 for h in d["hosts"].values() if h.get("Credentialed_Scan") == "true")
    return f'{c}/{len(d["hosts"])} hosts credentialed'


def selected(d, min_sev, min_score):
    if min_score is not None:
        return [p for p in d["plugins"].values() if p["score"] >= min_score]
    return [p for p in d["plugins"].values() if p["sev"] >= min_sev]


def cmd_table(a):
    d = load(a.cur)
    prior = load(a.prior) if a.prior else None
    print(f'{d["report"]}: {credentialed(d)}, sev counts {d["sev_counts"]}')
    if prior:
        print(f'prior {prior["report"]}: {credentialed(prior)}, sev counts {prior["sev_counts"]}')
    rows = selected(d, a.min_sev, a.min_score)
    rows.sort(key=lambda p: (-p["sev"], -len(p["hosts"]), -p["score"]))
    print(f'\n{"pid":>7} sv {"vpr":>4} {"cvss":>4} {"hosts":>5} {"prior":>5} {"kev":10} {"epss":>4}  name')
    for p in rows:
        o = prior["plugins"].get(p["pid"]) if prior else None
        print(f'{p["pid"]:>7} {p["sev"]}  {p["vpr"] if p["vpr"] is not None else "-":>4} '
              f'{p["cvss3"] if p["cvss3"] is not None else "-":>4} {len(p["hosts"]):5d} '
              f'{len(o["hosts"]) if o else "-":>5} {p["kev_date"] or "-":10} {p["epss"]:4.2f}  {p["name"][:80]}')
    print(f"\n{len(rows)} plugins")


def cmd_gone(a):
    d, prior = load(a.cur), load(a.prior)
    rows = [p for p in selected(prior, a.min_sev, a.min_score) if p["pid"] not in d["plugins"]]
    rows.sort(key=lambda p: -len(p["hosts"]))
    print(f"{len(rows)} prior findings absent from {d['report']}:")
    for p in rows:
        missing = [ip for ip in p["hosts"] if ip not in d["hosts"]]
        note = f"  ({len(missing)} host(s) not in current scan)" if missing else ""
        print(f'  {p["pid"]:>7} sev{p["sev"]} {p["score"]:4.1f} {len(p["hosts"]):4d}h  {p["name"][:80]}{note}')


def cmd_dump(a):
    d = load(a.cur)
    H = d["hosts"]
    for pid in a.pids.split(","):
        p = d["plugins"].get(pid)
        if not p:
            print(f"\n##### {pid} NOT FOUND")
            continue
        print(f'\n##### {pid} | {p["name"]} | sev{p["sev"]} vpr={p["vpr"]} cvss={p["cvss3"]} '
              f'epss={p["epss"]} kev={p["kev_date"]} maturity={p["maturity"]} ports={p["ports"]} cves={len(p["cves"])}')
        for ip in sorted(p["hosts"], key=ip_key):
            h = H.get(ip, {})
            nm = h.get("host-fqdn") or h.get("netbios-name") or h.get("hostname") or ""
            o = " | ".join(" ".join(x["out"].split()) for x in p["hosts"][ip])
            print(f'  {ip:15} {nm[:28]:28} {h.get("operating-system", "")[:38]:38} :: {o[:a.chars]}')


def cmd_hosts(a):
    d, prior = load(a.cur), load(a.prior)
    gone = sorted(set(prior["hosts"]) - set(d["hosts"]), key=ip_key)
    new = sorted(set(d["hosts"]) - set(prior["hosts"]), key=ip_key)
    print(f"{len(prior['hosts'])} hosts prior, {len(d['hosts'])} now; {len(gone)} missing, {len(new)} new")
    for ip in gone:
        h = prior["hosts"][ip]
        print(f'  missing {ip:15} {(h.get("netbios-name") or h.get("host-fqdn") or "")[:28]:28} {h.get("operating-system", "")[:40]}')


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn in (("table", cmd_table), ("gone", cmd_gone)):
        s = sub.add_parser(name)
        s.add_argument("cur")
        if name == "table":
            s.add_argument("--prior")
        else:
            s.add_argument("prior")
        s.add_argument("--min-sev", type=int, default=3)
        s.add_argument("--min-score", type=float)
        s.set_defaults(fn=fn)
    s = sub.add_parser("dump")
    s.add_argument("cur")
    s.add_argument("pids", help="comma-separated plugin IDs")
    s.add_argument("--chars", type=int, default=300)
    s.set_defaults(fn=cmd_dump)
    s = sub.add_parser("hosts")
    s.add_argument("cur")
    s.add_argument("prior")
    s.set_defaults(fn=cmd_hosts)
    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
