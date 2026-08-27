# Finding Massage Rules

Rules applied to Nessus findings during DATA payload generation. These transform raw scan output into actionable remediation items by adjusting scores and merging related plugins.

Apply all rules in this file before sorting issues and building the final DATA payload.

## Score Overrides

Some plugins report inflated scores that do not reflect real exploitability. Cap the score when the raw value exceeds the listed maximum.

If the raw score from Nessus is at or below the cap, use the raw score. Only override when the raw score exceeds the cap.

| Plugin Name | Cap | Reason |
|-------------|-----|--------|
| SSL Certificate Cannot Be Trusted | 8.5 | Self signed or internal CA certificates on internal networks are a trust configuration issue, not an actively exploitable vulnerability. The default VPR/CVSS score overstates the risk in environments where the certificate chain is intentionally managed outside public PKI. Cap at 8.5 to keep it in scope without inflating priority above actively exploited findings. |

## Architecture Awareness

When a host has the same software installed in multiple architectures (e.g. x86 and x64 under `Program Files` vs `Program Files (x86)`), each architecture is a separate installation requiring its own remediation action. Create one task per architecture. Do not merge x86 and x64 findings into a single task even when the version matches.

## Version Consolidation

When multiple findings target the same path, service, or daemon on the same host and differ only in version thresholds, the remediation is a single upgrade to the highest version required to close all of them simultaneously. Do not create separate tasks that each target a different version of the same component.

For example, if three plugins fire on the same host for OpenSSL < 1.1.1w, OpenSSL < 3.0.12, and OpenSSL < 3.1.4, and the installed binary is the same OpenSSL instance, the remediation is one upgrade to >= 3.1.4 (or the latest stable in that branch). Write the remediation text to name the highest required version and list the CVEs from all consolidated findings.

When the findings clearly target the same component (same path in plugin output, same service port, same daemon), consolidate without asking. When it is ambiguous (e.g. the same library appears at different paths suggesting separate installations), ask the user before merging.

## Finding Merges

When separate findings on the same host describe components of a single remediation action, merge them into one unified task. Each affected host should have one task per (version, architecture) combination, not one per component finding. Combine the detail output from all merged findings into a single `detail` string separated by ` | `. Combine plugin IDs with `+` in the `pid` field.

| Rule | Reason |
|------|--------|
| ASP.NET Core and .NET Core findings for the same major version and architecture on the same host are one task | ASP.NET Core is a component of the .NET Core runtime. Updating or removing a specific version of the runtime addresses both findings for that version and architecture. A host with multiple EOL versions (e.g. 2.1 and 6.0) gets one task per version. A host with both x86 and x64 installations gets one task per architecture. Within a single version and architecture, ASP.NET Core and .NET Core are one remediation action. |

## Detail Text Formatting

The `detail` field in each task carries the Nessus plugin output for that host. The template renders pipe-delimited segments (` | `) as a bulleted list. Structure the detail text accordingly:

- Use ` | ` (space pipe space) to separate logical items: registry keys, paths, version entries, configuration settings, CVE lists. Each segment becomes one list item.
- Lead with the most actionable information: the installed path or version, then supporting context.
- When the plugin output contains a flat enumeration (e.g. recommended settings 1 through 4, each with its own registry key and value), give each entry its own segment rather than concatenating them into one wall of text.
- Short single line detail (e.g. one path and one version) does not need pipes; the template renders it as plain text when there is only one segment.
- Do not use pipes inside a single logical item. If a value itself contains a literal pipe character, replace it with a comma or semicolon to avoid splitting artifacts.

## Issue-Specific Remediation Guidance

### Windows Speculative Execution Configuration Check (CVE-2017-5753, CVE-2017-5715, CVE-2017-5754, CVE-2018-3615, CVE-2018-3620, CVE-2018-3639, CVE-2018-3646, CVE-2018-12126, CVE-2018-12127, CVE-2018-12130, CVE-2019-11135, CVE-2022-0001)

The Nessus plugin reports current and recommended registry settings for speculative execution mitigations. The recommended settings differ across two axes: **Hyper-Threading** and **CVE-2022-0001 (Branch History Injection)**.

| Setting | FeatureSettingsOverride | HT | BHI (CVE-2022-0001) |
|---------|----------------------|-----|-----|
| 1 | 0x48 (72) | enabled | no |
| 2 | 0x2048 (8264) | disabled | no |
| 3 | 0x802048 (8396872) | disabled | yes |
| 4 | 0x800048 (8388680) | enabled | yes |

FeatureSettingsOverrideMask is always 0x3. The override value is a bitmask combining:
- Bit 3 (0x8): Spectre v2 mitigation
- Bit 6 (0x40): Spectre v1/SSB mitigation
- Bit 13 (0x2000): disable Hyper-Threading
- Bit 23 (0x800000): BHI mitigation (CVE-2022-0001)

Settings 1 and 4 keep HT on, 2 and 3 disable it. Settings 3 and 4 add BHI coverage. Setting 3 (HT off, BHI covered) is most secure. Setting 4 covers BHI while keeping HT for workloads that need it.

When building the detail text for this plugin, show only the current settings per host. Replace the recommended settings with "Refer to remediation recommendations below" since the remediation text carries the full settings table and guidance. This keeps per-host detail focused on what needs to change rather than repeating the same four recommended settings on every host.

Hyper-V hosts require an additional registry value: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\MinVmVersionForCpuBasedMitigations = '1.0'` (String).
