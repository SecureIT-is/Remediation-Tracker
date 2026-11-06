"""Shared helpers for building and editing remediation tracker files.

A per-client build script (kept in Projects/<client>/<quarter>/, which is git
ignored) imports this module, describes its issues, and calls assemble().
See tools/README.md for the full workflow and tools/example_build.py for a
minimal build script.

Sections:
    Scan            wraps nessus_parse.py JSON: per-host entries, host metadata
    builders        simple(), one(), ver_task() for common task-detail shapes
    assemble()      issue catalogue -> schema v200 DATA + task-id lookup
    validate()      invariants the template relies on
    tracker IO      extract_js_object(), read_tracker(), inject()
"""
import json
import random
import re
import string
from collections import namedtuple

# --------------------------------------------------------------------------- text helpers


def flat(s):
    """Collapse all whitespace (plugin output is multi-line) to single spaces."""
    return " ".join((s or "").split())


def grab(pattern, s, default=""):
    """First capture group of pattern in s, stripped, or default."""
    m = re.search(pattern, s)
    return m.group(1).strip() if m else default


def ip_key(ip):
    try:
        return tuple(int(x) for x in ip.split("."))
    except ValueError:
        return (999, ip)


def subnet24(ip):
    a = ip.split(".")
    return f"{a[0]}.{a[1]}.{a[2]}.0/24" if len(a) == 4 else ""


class Slugger:
    """Seeded slug generator so a rebuild produces the same IDs (and keeps saved state valid)."""

    def __init__(self, seed):
        self.rng = random.Random(seed)

    def __call__(self, prefix):
        return prefix + "_" + "".join(self.rng.choices(string.ascii_letters + string.digits, k=8))


# --------------------------------------------------------------------------- scan wrapper

# Substring of the OS string -> friendly name used when a host has no hostname.
DEVICE_HINTS = [
    ("siemens", "Siemens device"), ("polycom", "Polycom IP phone"), ("grandstream", "Grandstream SIP device"),
    ("avaya", "Avaya SIP device"), ("yealink", "Yealink SIP phone"), ("axis", "AXIS camera"),
    ("jetdirect", "HP JetDirect printer"), ("ricoh", "RICOH printer"), ("konica", "Konica Minolta printer"),
    ("fortinet", "FortiGate"), ("remote access controller", "Dell iDRAC"), ("hyperflex", "Cisco HyperFlex"),
    ("cisco", "Cisco device"),
]
# Substring of the OS string -> klass Embedded.
EMBEDDED_HINTS = ("siemens", "polycom", "grandstream", "avaya", "yealink", "axis", "jetdirect", "ricoh", "konica",
                  "fortinet", "remote access controller", "cisco ios", "cisco device", "linux kernel 2.6", "sip")


class Scan:
    """Read access to one parsed scan (output of nessus_parse.py)."""

    def __init__(self, data, server_ips=()):
        if isinstance(data, str):
            with open(data, encoding="utf-8") as f:
                data = json.load(f)
        self.data = data
        self.P = data["plugins"]
        self.H = data["hosts"]
        self.server_ips = set(server_ips)

    # findings
    def entries(self, pid, ip):
        """List of {port, svc, out} for one plugin on one host."""
        return self.P[pid]["hosts"].get(ip, []) if pid in self.P else []

    def hosts_of(self, *pids):
        out = set()
        for pid in pids:
            if pid in self.P:
                out |= set(self.P[pid]["hosts"])
        return sorted(out, key=ip_key)

    def hosts_matching(self, name_re=None, pids=()):
        """Hosts with any plugin whose ID is in pids or whose name matches name_re.
        Use on the prior quarter's scan to mark tasks that were already open then."""
        out = set()
        for pid, p in self.P.items():
            if pid in pids or (name_re and re.search(name_re, p["name"], re.I)):
                out |= set(p["hosts"])
        return out

    # host metadata
    def os_of(self, ip):
        raw = self.H.get(ip, {}).get("operating-system") or "Unknown"
        return " / ".join(l.strip() for l in raw.splitlines() if l.strip())

    def name_of(self, ip):
        h = self.H.get(ip, {})
        nm = (h.get("netbios-name") or h.get("host-fqdn") or h.get("hostname") or "").strip()
        if nm and not re.fullmatch(r"[\d.]+", nm):
            return nm
        o = self.os_of(ip).lower()
        for k, label in DEVICE_HINTS:
            if k in o:
                return label
        return ""

    def klass_of(self, ip):
        o = self.os_of(ip).lower()
        if "windows 11" in o or "windows 10" in o:
            return "Workstation"
        if "server" in o or "hyperflex" in o or "centos" in o or ip in self.server_ips:
            return "Server"
        if any(k in o for k in EMBEDDED_HINTS):
            return "Embedded"
        return "Embedded" if "linux" in o else "Server"

    # common detail builders
    def ver_task(self, pid, ip):
        """'<path> <installed> → <fixed> (<port>)' per entry, from the standard Nessus
        'Path/URL : … Installed version : … Fixed version : …' output block."""
        segs = []
        for e in self.entries(pid, ip):
            o = flat(e["out"])
            path = grab(r"(?:Path|URL)\s*:\s*(.+?)\s+Installed version", o)
            inst = grab(r"Installed version\s*:\s*(\S+)", o)
            fix = grab(r"Fixed version\s*:\s*(.+?)(?:\s+(?:Potential Vulnerability|CVE\(s\)|Path|URL)\s*:|$)", o)
            bits = [b for b in (path, f"{inst} → {fix}" if inst else "") if b]
            if bits:
                segs.append(" ".join(bits) + (f" ({e['port']})" if e["port"] not in ("0/tcp", "445/tcp") else ""))
        return segs

    def simple(self, pids, fmt=None):
        """Builder: one task per host across pids; detail = fmt(pid, ip) segments (default ver_task)."""
        fmt = fmt or self.ver_task

        def build():
            tasks = []
            for ip in self.hosts_of(*pids):
                segs = []
                for pid in pids:
                    segs += fmt(pid, ip)
                tasks.append((ip, " | ".join(dict.fromkeys(s for s in segs if s))))
            return tasks
        return build

    def one(self, pid, text_fn):
        """Builder: one task per host of pid; detail = text_fn(ip)."""
        return lambda: [(ip, text_fn(ip)) for ip in self.hosts_of(pid)]


# --------------------------------------------------------------------------- assemble

# builder() returns [(ip, detail), ...]; several tuples for one ip become task ::0, ::1, ...
# remediation and detail use ' | ' to separate list items; a segment ending in ':' renders as a header.
Issue = namedtuple("Issue", "key pids name workstream effort estimate cvss history builder remediation caveat prior_re")


def assemble(scan, issues, meta, slugger, prior=None, prior_label=None):
    """Build the schema v200 DATA object.

    issues      list of Issue (or 12-tuples in Issue field order)
    meta        {"scan": ..., "scan_date": "YYYY-MM-DD"}; dataSchemaVersion is added
    prior       optional Scan of the previous quarter; tasks whose host had a matching
                finding there get ' | Also present in the <prior_label> scan'
    Returns (DATA, tid_for) where tid_for(key, ip, n=0) gives a task id for PRE_NOTES/PRE_CHECKED.
    Slugs are drawn in a fixed order (issue, then hosts as first seen), so the same
    seed and catalogue give identical IDs.
    """
    issues = [Issue(*i) for i in issues]
    P = scan.P
    out_issues, machines, mslug, keyed = [], {}, {}, {}
    for it in issues:
        missing = [p for p in it.pids if p not in P]
        assert not missing, (it.key, missing)
        ps = [P[p] for p in it.pids]
        iss_slug = slugger("issue")
        prior_hosts = prior.hosts_matching(it.prior_re, it.pids) if prior else set()
        tasks, per_host = [], {}
        for ip, detail in it.builder():
            if ip not in mslug:
                mslug[ip] = slugger("host")
            m = mslug[ip]
            n = per_host.get(ip, 0)
            per_host[ip] = n + 1
            tid = f"{iss_slug}::{m}::{n}"
            if ip in prior_hosts and prior_label:
                detail += f" | Also present in the {prior_label} scan"
            tasks.append({"id": tid, "machine": m, "detail": detail})
            machines.setdefault(ip, []).append(tid)
        kev = next((p["kev_date"] for p in ps if p["kev_date"]), "")
        iss = {
            "slug": iss_slug, "pid": "+".join(it.pids), "name": it.name,
            "family": ps[0]["family"], "score": it.cvss, "src": "CVSSv3", "sev": max(p["sev"] for p in ps),
            "kev": bool(kev), "kevdate": kev, "exploit": any(p["exploit"] for p in ps),
            "maturity": next((p["maturity"] for p in ps if p["maturity"]), ""),
            "epss": round(max(p["epss"] for p in ps), 4),
            "cves": sorted({c for p in ps for c in p["cves"]}),
            "ports": sorted({x for p in ps for x in p["ports"]}),
            "workstream": it.workstream, "effort": it.effort, "estimate": it.estimate,
            "remediation": f"{it.history} | {it.remediation}" if it.history else it.remediation,
            "caveat": it.caveat,
            "nessus_solution": flat(ps[0]["solution"]), "tasks": tasks,
        }
        out_issues.append(iss)
        keyed[it.key] = iss

    machine_list = [
        {"slug": mslug[ip], "ips": [ip], "name": scan.name_of(ip), "os": scan.os_of(ip),
         "type": "general-purpose", "klass": scan.klass_of(ip), "subnet": subnet24(ip), "tasks": tids}
        for ip, tids in sorted(machines.items(), key=lambda kv: ip_key(kv[0]))
    ]
    data = {"meta": {**meta, "dataSchemaVersion": 200}, "issues": out_issues, "machines": machine_list}

    def tid_for(key, ip, n=0):
        m = mslug.get(ip)
        hits = [t["id"] for t in keyed[key]["tasks"] if t["machine"] == m]
        return hits[n] if len(hits) > n else None

    return data, tid_for


def validate(data):
    """Raise AssertionError if DATA would break the template."""
    tids = [t["id"] for i in data["issues"] for t in i["tasks"]]
    assert len(tids) == len(set(tids)), "duplicate task ids"
    assert set(tids) == {t for m in data["machines"] for t in m["tasks"]}, "issue and machine task lists differ"
    bad = [t for t in tids if not re.fullmatch(r"issue_[A-Za-z0-9]{8}::host_[A-Za-z0-9]{8}::\d+", t)]
    assert not bad, f"task ids fail the template's sanitize regex: {bad[:3]}"
    assert len({i["pid"] for i in data["issues"]}) == len(data["issues"]), "duplicate issue pid"
    blob = json.dumps(data, ensure_ascii=False)
    assert "};" not in blob and "</" not in blob, "payload contains '};' or '</', which breaks the inline script"


def summary(data, notes=None):
    from collections import Counter
    n = sum(len(i["tasks"]) for i in data["issues"])
    print(f'{len(data["issues"])} issues, {len(data["machines"])} machines, {n} tasks'
          + (f", {len(notes)} notes" if notes is not None else ""))
    print("klass:", dict(Counter(m["klass"] for m in data["machines"])))
    for i in data["issues"]:
        print(f'  [{i["workstream"][:22]:22}] {i["effort"]:6} {len(i["tasks"]):3}t  {i["name"][:60]}')
        print(f'        e.g. {i["tasks"][0]["detail"][:150]}')


# --------------------------------------------------------------------------- tracker IO

def extract_js_object(src, marker, open_c="{", close_c="}"):
    """(start, end) span of 'marker{...};' in src, string- and escape-aware.
    Use this rather than a regex: the JSON itself contains braces and semicolons."""
    start = src.index(marker)
    i, depth, in_str = start + len(marker), 0, False
    while i < len(src):
        c = src[i]
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == '"':
                in_str = False
        elif c == '"':
            in_str = True
        elif c == open_c:
            depth += 1
        elif c == close_c:
            depth -= 1
            if depth == 0:
                break
        i += 1
    end = i + 1
    if end < len(src) and src[end] == ";":
        end += 1
    return start, end


def _json_value(src, marker, open_c="{", close_c="}"):
    s, e = extract_js_object(src, marker, open_c, close_c)
    blob = src[s + len(marker):e].rstrip(";")
    try:
        return json.loads(blob)
    except json.JSONDecodeError:
        # Older trackers were hand-edited with raw newlines inside strings.
        blob = blob.replace("\n", "\\n").replace("\r", "\\r")
        blob = re.sub(r'\\n(\s*)(?=["{}\[\]\d-]|true|false|null)', r"\1", blob)
        return json.loads(blob)


def _str_const(src, name):
    m = re.search(rf"const {name} = '([^'\n]*)';", src)
    return m.group(1) if m else None


def read_tracker(path):
    """All eight embedded constants of a tracker HTML file as Python values."""
    with open(path, encoding="utf-8") as f:
        src = f.read()
    out = {"INITIAL_DATA": _json_value(src, "const INITIAL_DATA = ")}
    for name in ("PRE_CHECKED", "PRE_FP"):
        out[name] = _json_value(src, f"const {name} = ", "[", "]") if f"const {name} = " in src else []
    out["PRE_NOTES"] = _json_value(src, "const PRE_NOTES = ") if "const PRE_NOTES = " in src else {}
    for name in ("FILE_STAMP", "SAVED_THEME", "SAVED_DATE_STAMP", "SAVED_DATE"):
        out[name] = _str_const(src, name)
    m = re.search(r"TRACKER_VERSION = '([^']*)'", src)
    out["TRACKER_VERSION"] = m.group(1) if m else None
    return out


def _replace_js(html, marker, value, open_c="{", close_c="}"):
    s, e = extract_js_object(html, marker, open_c, close_c)
    return html[:s] + f"{marker}{value};" + html[e:]


def inject(template_path, out_path, data, notes=None, checked=None, fp=None):
    """Write a new tracker: template + DATA (+ optional PRE_NOTES / PRE_CHECKED / PRE_FP).
    SAVED_DATE is cleared so the header shows no save yet; theme and stamps keep template defaults."""
    import os
    validate(data)
    with open(template_path, encoding="utf-8") as f:
        html = f.read()
    dump = lambda v: json.dumps(v, ensure_ascii=False, indent=2)
    html = _replace_js(html, "const INITIAL_DATA = ", dump(data))
    html = _replace_js(html, "const PRE_NOTES = ", dump(notes or {}))
    html = _replace_js(html, "const PRE_CHECKED = ", json.dumps(checked or []), "[", "]")
    html = _replace_js(html, "const PRE_FP = ", json.dumps(fp or []), "[", "]")
    s = html.index("const SAVED_DATE = '")
    e = html.index("';", s) + 2
    html = html[:s] + "const SAVED_DATE = '';" + html[e:]
    assert "const FILE_STAMP = '';" in html, "template FILE_STAMP is not empty"
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"wrote {out_path} ({len(html):,} bytes)")
