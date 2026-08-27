# Remediation Tracker: Data Format and Sources

This document explains the JSON data schema consumed by `remediation_tracker_template.html` and where each field comes from in a Nessus scan.

## Overview

The template reads two top level variables from its `<script>` block:

- **`SCAN_NAME`** (string): Short label for the engagement, e.g. `"Acme Q3 2026"`. Used in the page title and as the localStorage key prefix so multiple scans do not overwrite each other.
- **`DATA`** (object): The full scan payload. Structure below.

## DATA Schema

```json
{
  "meta": { ... },
  "issues": [ ... ],
  "machines": [ ... ]
}
```

### meta

| Field              | Type   | Description |
|--------------------|--------|-------------|
| `scan`             | string | Full scan name from Nessus, e.g. `"Client Q3 2026 Internal Authenticated Scan"` |
| `scan_date`        | string | Date the scan ran, `YYYY-MM-DD` |
| `dataSchemaVersion`| number | Schema version of the DATA payload. Current version is `200`. The template validates this against its `COMPATIBLE_SCHEMA_VERSIONS` array on load and rejects incompatible data |

Issue count, machine count, and task count are computed automatically from the `issues` and `machines` arrays at render time.

### issues (array of objects)

Each object is one Nessus plugin that met the threshold. Issues are displayed grouped by `workstream`.

| Field             | Type     | Source | Description |
|-------------------|----------|--------|-------------|
| `slug`            | string   | Generated | Unique identifier, format `issue_XXXXXXXX` (8 random alphanumeric chars). Stable across renames |
| `pid`             | string   | `pluginID` attribute on `<ReportItem>` | Nessus plugin ID |
| `name`            | string   | `pluginName` attribute on `<ReportItem>` | Plugin display name |
| `family`          | string   | `pluginFamily` attribute on `<ReportItem>` | Nessus plugin family |
| `score`           | number   | `<vpr_score>` child, fallback `<cvss3_base_score>` | Highest score used for filtering |
| `src`             | string   | `"VPR"` or `"CVSSv3"` | Which scoring system `score` came from |
| `sev`             | number   | `severity` attribute on `<ReportItem>` | Nessus severity (0-4) |
| `kev`             | boolean  | Cross reference with CISA KEV catalog | Whether any CVE in this plugin is on the CISA Known Exploited Vulnerabilities list |
| `kevdate`         | string   | CISA KEV catalog | Date added to KEV, `YYYY/MM/DD` or empty |
| `exploit`         | boolean  | `<exploit_available>` child | Whether a public exploit exists |
| `maturity`        | string   | `<exploit_code_maturity>` child | `"High"`, `"Functional"`, `"Proof-of-Concept"`, or empty |
| `epss`            | number   | `<epss_score>` child or FIRST EPSS API | Exploit Prediction Scoring System score (0.0 to 1.0) |
| `cves`            | string[] | `<cve>` children | List of CVE identifiers |
| `ports`           | string[] | Aggregated from `port`/`protocol` attributes | Unique `"port/proto"` strings seen across all hosts |
| `workstream`      | string   | Human assigned | Logical remediation group, e.g. `"OS patching"`, `"Certificate management"` |
| `effort`          | string   | Human assigned | `"Low"`, `"Medium"`, or `"High"` |
| `estimate`        | string   | Human assigned | Time estimate, e.g. `"2 to 4 hours"` |
| `remediation`     | string   | Human written | Actionable remediation steps (not just the Nessus solution field) |
| `caveat`          | string   | Human written | Warnings, dependencies, or risk factors. Empty if none |
| `nessus_solution` | string   | `<solution>` child of `<ReportItem>` | Nessus's own solution text, kept as fallback reference |
| `tasks`           | array    | Aggregated per host | One entry per affected host |

#### tasks (within each issue)

| Field    | Type   | Description |
|----------|--------|-------------|
| `id`     | string | Format: `issueSlug::machineSlug::subIndex` (e.g. `issue_Ab3kX9mQ::host_Zt7pL2nR::0`). Unique checkbox key shared between Issues and Machines views. subIndex is usually `0` unless the same plugin fires multiple times on one host |
| `machine`| string | Machine slug (e.g. `host_Zt7pL2nR`). References a machine in the `machines` array by its `slug` field |
| `detail` | string | Extracted from `<plugin_output>` child, pipe delimited if multi line. Gives host specific context like exact version numbers |

### machines (array of objects)

Each object is one host that appears in at least one issue's task list.

| Field    | Type     | Source | Description |
|----------|----------|--------|-------------|
| `slug`   | string   | Generated | Unique identifier, format `host_XXXXXXXX` (8 random alphanumeric chars). Stable across IP changes and renames |
| `ips`    | string[] | `name` attribute on `<ReportHost>` | IP addresses associated with this machine. Array supports hosts with multiple IPs |
| `name`   | string   | `host-fqdn` or `netbios-name` from `<HostProperties>` | Hostname if available |
| `os`     | string   | `operating-system` tag from `<HostProperties>` | OS string |
| `type`   | string   | Derived or `system-type` tag | General description |
| `klass`  | string   | Derived from OS/type | `"Server"`, `"Workstation"`, `"Embedded"`, or `"Legacy"`. Controls the top level grouping in the Machines view |
| `subnet` | string   | Derived from IP | CIDR notation, e.g. `"10.0.1.0/24"` |
| `tasks`  | string[] | Collected from all issues | Array of task IDs (`issueSlug::machineSlug::subIndex`) for this machine. Must match exactly the `id` values in the issues array |

## Slugs and Cross Referencing

Every issue and machine gets a slug: a random stable identifier in the format `type_XXXXXXXX` (8 alphanumeric characters). Issues use the prefix `issue_`, machines use `host_`.

Slugs enable:
- **Multiple IPs per machine**: The `ips` field is an array, so a host with multiple network interfaces is one machine entry
- **Renames without breakage**: Changing a hostname or IP does not break task cross references
- **Stable task IDs**: Task IDs are composed from slugs (`issueSlug::machineSlug::subIndex`), not from mutable data like plugin IDs or IP addresses

Tasks reference machines by slug (the `machine` field), not by IP. The template resolves machine metadata (hostname, IPs, OS) by looking up the slug in the machines array.

## Critical Invariant

Every task ID in `machines[].tasks` must exist in exactly one `issues[].tasks[].id`, and vice versa. The Issues view and Machines view share a single checkbox state keyed by these IDs. A mismatch means a checkbox in one view has no counterpart in the other.

Every `tasks[].machine` value must match exactly one `machines[].slug`. A task referencing a nonexistent machine slug will fail to render host metadata.

## Task States

Each task has three possible states:

| State | Meaning | Visual | Progress |
|-------|---------|--------|----------|
| Unchecked | Not yet addressed | Normal text | Not counted |
| Done | Remediated | Strikethrough, dimmed | Counted as resolved |
| False Positive | Finding does not apply to this host | Italic, dimmed, FP tag | Counted as resolved, annotated separately |

Done and False Positive are mutually exclusive. Setting one clears the other. Both count toward progress (reducing remaining work), but FP counts are shown separately (e.g., "5 / 20 (3%) · 2 FP"). When Show Completed is off (default), resolved tasks are hidden from view.

FP state is persisted in localStorage alongside done state and included in save/load JSON files as `fpTasks`.

## Finding Massage Rules

Score overrides, plugin merges, and other transformations applied during DATA payload generation are defined in `LLM-FindingMassage.md`. Apply all rules in that file before sorting issues and building the final payload.

## Human Written Fields

The following fields are not extracted mechanically from the .nessus file and require analyst judgment:

- `workstream`: Logical grouping for related remediation work
- `effort`: Realistic effort rating considering the specific environment
- `estimate`: Time estimate for a solo operator
- `remediation`: Detailed, actionable steps (not just "update the software")
- `caveat`: Environment specific warnings
- `klass` (on machines): Classification based on OS, hostname patterns, and network segment

These are where the real value of the tracker lives. The Nessus `solution` field is kept in `nessus_solution` as a starting point, but the `remediation` field should contain environment specific guidance based on plugin output analysis and independent research.

## Data Schema Versioning

The DATA payload includes a `dataSchemaVersion` field in `meta`. The current schema version is `200`. The template declares a `COMPATIBLE_SCHEMA_VERSIONS` array listing all schema versions it can consume.

On load, the template checks `meta.dataSchemaVersion` against `COMPATIBLE_SCHEMA_VERSIONS`. If the version is not in the array, the load is rejected with an error. If `dataSchemaVersion` is absent, the template assumes compatibility (for backward compatibility with older payloads).

When generating DATA payloads, always set `meta.dataSchemaVersion` to the current version (`200`).

## Migrating a Project File to a New Template

When a project tracker (e.g., `Projects/UNAK/unak_q2_2026_remediation.html`) needs to be upgraded to a newer template version:

1. Check the `dataSchemaVersion` in the project file's `INITIAL_DATA.meta.dataSchemaVersion`.
2. Check the new template's `COMPATIBLE_SCHEMA_VERSIONS` array.
3. If the project's `dataSchemaVersion` is in the template's compatible list, the migration is a direct transfer: copy the entire `INITIAL_DATA` JSON block from the project file and paste it into the new template, replacing the template's example data. No data transformation needed.
4. If the version is not compatible, a data migration is required. Consult the changelog for what changed between schema versions.

The `checked`, `fpTasks`, and `remNotes` state is stored in localStorage and save/load JSON files, not in the HTML. After transferring the DATA payload to a new template, users can load their existing JSON save file to restore progress.

## Output Location

Generated tracker files go in `Projects/<client>/` (e.g. `Projects/UNAK/unak_q2_2026_remediation.html`). The `Projects/` directory is git ignored so client data stays local and never syncs to the template repository.
