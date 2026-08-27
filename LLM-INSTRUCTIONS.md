# LLM Instructions: Nessus to Remediation Tracker

Step by step workflow for generating the JSON payload from a `.nessus` file and placing it into the template. Intended for use as an LLM co-pilot prompt (Claude, GPT, etc.).

## Prerequisites

- Python 3.8+ with `lxml` installed (`pip install lxml`)
- The `.nessus` file (XML, can be hundreds of MB)
- A copy of `remediation_tracker_template.html`

## Step 1: Parse the .nessus file

Nessus files can be very large. Use streaming XML parsing (`iterparse`) to avoid loading the full DOM into memory.

```python
from lxml import etree
import json, collections

NESSUS_FILE = "/path/to/scan.nessus"
OUTPUT_FILE = "all_plugins.json"

plugins = {}  # pluginID -> aggregated data
hosts_data = {}  # ip -> host properties

context = etree.iterparse(NESSUS_FILE, events=("end",), tag=("ReportHost", "ReportItem"))
current_host = None
current_host_ip = None

for event, el in context:
    if el.tag == "ReportHost":
        ip = el.get("name")
        props = {}
        hp = el.find("HostProperties")
        if hp is not None:
            for t in hp.findall("tag"):
                props[t.get("name")] = (t.text or "").strip()
        hosts_data[ip] = props
        # Free memory
        el.clear()
        while el.getprevious() is not None:
            del el.getparent()[0]

    elif el.tag == "ReportItem":
        host_el = el.getparent()
        ip = host_el.get("name") if host_el is not None else "unknown"
        pid = el.get("pluginID")
        sev = int(el.get("severity", "0"))

        if sev == 0:
            el.clear()
            continue

        port = el.get("port", "0")
        proto = el.get("protocol", "tcp")
        port_str = f"{port}/{proto}"

        # Extract scores
        vpr = el.findtext("vpr_score", "")
        cvss3 = el.findtext("cvss3_base_score", "")
        score = float(vpr) if vpr else (float(cvss3) if cvss3 else 0.0)
        src = "VPR" if vpr else "CVSSv3"

        # Extract metadata
        exploit = el.findtext("exploit_available", "") == "true"
        maturity = el.findtext("exploit_code_maturity", "") or ""
        epss = float(el.findtext("epss_score", "0") or "0")
        solution = (el.findtext("solution", "") or "").strip()
        output = (el.findtext("plugin_output", "") or "").strip()

        cves = [c.text for c in el.findall("cve") if c.text]

        if pid not in plugins:
            plugins[pid] = {
                "pid": pid,
                "name": el.get("pluginName"),
                "family": el.get("pluginFamily"),
                "score": score,
                "src": src,
                "sev": sev,
                "exploit": exploit,
                "maturity": maturity,
                "epss": epss,
                "cves": list(set(cves)),
                "ports": set(),
                "solution": solution,
                "hosts": {}  # ip -> [output lines]
            }
        p = plugins[pid]
        p["ports"].add(port_str)
        if ip not in p["hosts"]:
            p["hosts"][ip] = []
        if output:
            # Collapse multi-line output into pipe-delimited
            collapsed = " | ".join(line.strip() for line in output.splitlines() if line.strip())
            p["hosts"][ip].append(collapsed)

        el.clear()

# Convert sets for JSON serialization
for p in plugins.values():
    p["ports"] = sorted(p["ports"])

with open(OUTPUT_FILE, "w") as f:
    json.dump({"plugins": plugins, "hosts": hosts_data}, f)

print(f"Parsed {len(plugins)} plugins across {len(hosts_data)} hosts")
```

This runs in under a second on files up to 300 MB and uses about 40 MB of RAM.

## Step 2: Filter and sort

Filter and sort the parsed plugins to surface the most impactful issues. The recommended default:

1. **Filter** by VPR >= 8.5 (fall back to CVSS >= 8.5 where no VPR is published)
2. **Sort** by affected host count descending (widest blast radius first)
3. **Then sort** by remediation effort ascending (most achievable first)

These defaults work well for a solo operator prioritizing quick wins across a large environment. Adjust freely based on the engagement: a smaller network might use a lower threshold, a compliance driven scan might filter by specific plugin families, or a team with more capacity might skip the effort sort and tackle everything above threshold.

```python
import json

with open("all_plugins.json") as f:
    raw = json.load(f)

plugins = raw["plugins"]
hosts_data = raw["hosts"]

THRESHOLD = 8.5  # adjust as needed

above = []
for pid, p in plugins.items():
    if p["score"] >= THRESHOLD:
        above.append(p)

# Primary sort: host count descending. Secondary: score descending.
above.sort(key=lambda p: (-len(p["hosts"]), -p["score"]))

print(f"{len(above)} plugins above {THRESHOLD}")
for p in above[:20]:
    print(f"  {p['pid']:>8s}  {p['score']:5.1f}  {len(p['hosts']):4d} hosts  {p['name'][:70]}")
```

## Step 3: Select the top achievable issues

From the sorted list, pick the top N most achievable remediation items. "Achievable" means a solo cybersecurity operator can realistically resolve them. Consider:

1. **Read the plugin output** for each issue. The same plugin ID can mean very different things (e.g., an outdated library in a running service vs. a dormant JAR on disk).
2. **Research the actual fix**, not just what Nessus says. Check vendor EOL dates, actual package availability, whether the fix requires downtime or change control.
3. **Classify effort** as Low / Medium / High based on:
   - Low: GPO push, config change, package update with no dependencies
   - Medium: Requires coordination, testing, or application owner involvement
   - High: Migration, replacement, or multi-step project
4. **Group into workstreams**: Cluster related issues so the remediation plan is coherent (e.g., all Windows registry hardening goes together).

Assign each selected issue:
- `workstream` (string)
- `effort` ("Low" / "Medium" / "High")
- `estimate` (time string like "2 to 4 hours")
- `remediation` (detailed, actionable steps)
- `caveat` (warnings or dependencies, empty string if none)

## Step 4: Build the DATA object

Every issue and machine gets a slug: a stable random identifier that enables cross referencing without depending on mutable data like IPs or hostnames.

- Issue slugs: `issue_XXXXXXXX` (8 random alphanumeric characters)
- Machine slugs: `host_XXXXXXXX` (8 random alphanumeric characters)
- Task IDs: `issueSlug::machineSlug::subIndex`

```python
import json, random, string

# Assumes: `selected` is your list of chosen plugin dicts with
# added workstream/effort/estimate/remediation/caveat fields.
# `hosts_data` is the host properties dict from Step 1.

def gen_slug(prefix):
    chars = string.ascii_letters + string.digits
    return prefix + "_" + "".join(random.choices(chars, k=8))

def classify_host(ip, props):
    """Derive klass from OS and hostname."""
    os_str = props.get("operating-system", "").lower()
    name = props.get("host-fqdn", props.get("netbios-name", "")).lower()
    if "server" in os_str or "server" in name:
        return "Server"
    if any(k in os_str for k in ["camera", "printer", "switch", "scada", "firmware"]):
        return "Embedded"
    if "xp" in os_str or "2003" in os_str or "2000" in os_str:
        return "Legacy"
    return "Workstation"

def derive_subnet(ip):
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return ""

# Assign a machine slug to each unique IP
machine_slugs = {}  # ip -> slug
for p in selected:
    for ip in p["hosts"]:
        if ip not in machine_slugs:
            machine_slugs[ip] = gen_slug("host")

# Build issues and collect machine task lists
issues = []
machine_tasks = {}  # ip -> [task_id, ...]

for p in selected:
    issue_slug = gen_slug("issue")
    tasks = []
    for ip, outputs in sorted(p["hosts"].items()):
        m_slug = machine_slugs[ip]
        for i, detail in enumerate(outputs if outputs else [""]):
            tid = f"{issue_slug}::{m_slug}::{i}"
            tasks.append({"id": tid, "machine": m_slug, "detail": detail})
            machine_tasks.setdefault(ip, []).append(tid)

    issues.append({
        "slug": issue_slug,
        "pid": p["pid"],
        "name": p["name"],
        "family": p["family"],
        "score": round(p["score"], 1),
        "src": p["src"],
        "sev": p["sev"],
        "kev": p.get("kev", False),          # see Step 5
        "kevdate": p.get("kevdate", ""),
        "exploit": p["exploit"],
        "maturity": p["maturity"],
        "epss": round(p["epss"], 4),
        "cves": p["cves"],
        "ports": p["ports"],
        "workstream": p["workstream"],
        "effort": p["effort"],
        "estimate": p["estimate"],
        "remediation": p["remediation"],
        "caveat": p.get("caveat", ""),
        "nessus_solution": p["solution"],
        "tasks": tasks
    })

# Build machines array (only hosts that appear in selected issues)
machines = []
for ip, task_ids in sorted(machine_tasks.items()):
    props = hosts_data.get(ip, {})
    machines.append({
        "slug": machine_slugs[ip],
        "ips": [ip],
        "name": props.get("host-fqdn", props.get("netbios-name", "")),
        "os": props.get("operating-system", "Unknown"),
        "type": "general-purpose",
        "klass": classify_host(ip, props),
        "subnet": derive_subnet(ip),
        "tasks": task_ids
    })

task_count = sum(len(iss["tasks"]) for iss in issues)

DATA = {
    "meta": {
        "scan": "Client Name QN YYYY Scan Type",  # <-- fill in
        "scan_date": "YYYY-MM-DD"                  # <-- fill in
    },
    "issues": issues,
    "machines": machines
}

with open("data_payload.json", "w") as f:
    json.dump(DATA, f)

print(f"Payload: {len(issues)} issues, {len(machines)} machines, {task_count} tasks")
```

### Machines with multiple IPs

The `ips` field is an array. If a host has multiple network interfaces discovered during the scan, merge them into one machine entry:

```python
# After building machines, merge entries that share a hostname
from collections import defaultdict

by_name = defaultdict(list)
for m in machines:
    if m["name"]:
        by_name[m["name"]].append(m)

for name, dupes in by_name.items():
    if len(dupes) > 1:
        primary = dupes[0]
        for other in dupes[1:]:
            primary["ips"].extend(other["ips"])
            primary["tasks"].extend(other["tasks"])
            machines.remove(other)
```

## Step 5: CISA KEV enrichment (optional but recommended)

Cross reference CVEs against the CISA Known Exploited Vulnerabilities catalog.

```python
import csv, urllib.request, io

KEV_URL = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"

response = urllib.request.urlopen(KEV_URL)
reader = csv.DictReader(io.TextIOWrapper(response))
kev_set = {}
for row in reader:
    kev_set[row["cveID"]] = row.get("dateAdded", "")

for iss in issues:
    for cve in iss["cves"]:
        if cve in kev_set:
            iss["kev"] = True
            iss["kevdate"] = kev_set[cve].replace("-", "/")
            break
```

## Step 6: Place JSON into the template

1. Copy `remediation_tracker_template.html` to a new file, e.g. `acme_q3_2026_remediation.html`.
2. Open the copy in a text editor.
3. Replace the `SCAN_NAME` value:
   ```js
   const SCAN_NAME = "Acme Q3 2026";
   ```
4. Replace the entire `const DATA = { ... };` block with your generated JSON:
   ```js
   const DATA = <paste contents of data_payload.json here>;
   ```
5. Save. Open in a browser. Done.

Alternatively, with Python:

```python
with open("remediation_tracker_template.html") as f:
    html = f.read()

with open("data_payload.json") as f:
    payload = f.read()

scan_name = "Acme Q3 2026"

# Replace SCAN_NAME
html = html.replace(
    'const SCAN_NAME = "Example Corp Q3 2026";',
    f'const SCAN_NAME = {json.dumps(scan_name)};'
)

# Replace DATA block: find the line that starts with const DATA and ends with };
import re
html = re.sub(
    r'const DATA = \{.*?\};',
    f'const DATA = {payload};',
    html,
    count=1,
    flags=re.DOTALL
)

output_file = scan_name.lower().replace(" ", "_") + "_remediation.html"
with open(output_file, "w") as f:
    f.write(html)

print(f"Written to {output_file}")
```

## Quick Reference: Full Workflow

```
1. pip install lxml
2. python parse.py          # Step 1: stream-parse .nessus -> all_plugins.json
3. python filter_sort.py    # Step 2: filter VPR>=8.5, sort by count
4. [analyst work]           # Step 3: select top N, write remediation/effort/workstream
5. python build_data.py     # Step 4+5: build DATA object with slugs + KEV enrichment
6. python inject.py         # Step 6: place into template copy
7. open output.html         # verify in browser
```

In practice, steps 2 through 5 are often done in a single script with the LLM co-pilot filling in the analyst judgment parts (workstream assignment, effort rating, remediation writing) based on the plugin output and independent research.
