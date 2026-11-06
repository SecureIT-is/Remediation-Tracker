#!/usr/bin/env python3
"""Stream-parse a .nessus export into a compact JSON file.

Uses lxml.iterparse and clears each element after use, so memory stays flat
even for multi-hundred-MB scans.

Usage:
    .venv/bin/python tools/nessus_parse.py SCAN.nessus OUT.json

Output shape:
    {
      "report": "<scan name>",
      "sev_counts": {"0": n, ... "4": n},
      "hosts":   {ip: {host-ip, host-fqdn, hostname, netbios-name, operating-system,
                       system-type, Credentialed_Scan, HOST_START, mac-address, host-rdns}},
      "plugins": {pid: {pid, name, family, sev, risk, vpr, cvss3, epss, exploit, maturity,
                        kev_date, cves, synopsis, solution, description, patch_date,
                        ports, score, src,
                        hosts: {ip: [{port, svc, out}, ...]}}}
    }

Only severity > 0 findings are kept in "plugins". "score" is VPR when present,
else CVSSv3, and "src" says which.
"""
import argparse
import json

from lxml import etree

HOST_PROPS = ("host-ip", "host-fqdn", "hostname", "netbios-name", "operating-system",
              "system-type", "Credentialed_Scan", "HOST_START", "mac-address", "host-rdns")


def _txt(el, tag):
    return (el.findtext(tag) or "").strip()


def parse(src, desc_limit=1500, out_limit=4000):
    plugins, hosts = {}, {}
    report_name, host_name = None, None
    sev_counts = {i: 0 for i in range(5)}

    for ev, el in etree.iterparse(src, events=("start", "end"), huge_tree=True, recover=True):
        tag = el.tag
        if ev == "start":
            if tag == "Report":
                report_name = el.get("name")
            elif tag == "ReportHost":
                host_name = el.get("name")
            continue

        if tag == "HostProperties":
            props = {t.get("name"): (t.text or "").strip() for t in el.findall("tag")}
            hosts[host_name] = {k: props.get(k, "") for k in HOST_PROPS}
        elif tag == "ReportItem":
            sev = int(el.get("severity", "0"))
            sev_counts[sev] += 1
            if sev > 0:
                pid = el.get("pluginID")
                p = plugins.get(pid)
                if p is None:
                    vpr, cvss3 = _txt(el, "vpr_score"), _txt(el, "cvss3_base_score")
                    p = plugins[pid] = {
                        "pid": pid, "name": el.get("pluginName"), "family": el.get("pluginFamily"),
                        "sev": sev, "risk": _txt(el, "risk_factor"),
                        "vpr": float(vpr) if vpr else None,
                        "cvss3": float(cvss3) if cvss3 else None,
                        "epss": float(_txt(el, "epss_score") or 0),
                        "exploit": _txt(el, "exploit_available") == "true",
                        "maturity": _txt(el, "exploit_code_maturity"),
                        "kev_date": _txt(el, "cisa-known-exploited"),
                        "cves": sorted({c.text for c in el.findall("cve") if c.text}),
                        "synopsis": _txt(el, "synopsis"),
                        "solution": _txt(el, "solution"),
                        "description": _txt(el, "description")[:desc_limit],
                        "patch_date": _txt(el, "patch_publication_date"),
                        "ports": set(), "hosts": {},
                    }
                port = f'{el.get("port", "0")}/{el.get("protocol", "tcp")}'
                p["ports"].add(port)
                p["hosts"].setdefault(host_name, []).append(
                    {"port": port, "svc": el.get("svc_name", ""), "out": _txt(el, "plugin_output")[:out_limit]})
            el.clear()
        elif tag == "ReportHost":
            el.clear()
            while el.getprevious() is not None:
                del el.getparent()[0]

    for p in plugins.values():
        p["ports"] = sorted(p["ports"])
        s = p["vpr"] if p["vpr"] is not None else p["cvss3"]
        p["score"], p["src"] = (s or 0.0), ("VPR" if p["vpr"] is not None else "CVSSv3")

    return {"report": report_name, "sev_counts": sev_counts, "hosts": hosts, "plugins": plugins}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("nessus")
    ap.add_argument("out")
    a = ap.parse_args()
    d = parse(a.nessus)
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(d, f)
    print(f"{d['report']}: {len(d['hosts'])} hosts, {len(d['plugins'])} plugins sev>0, sev counts {d['sev_counts']}")


if __name__ == "__main__":
    main()
