# MDE & Trellix Coexistence — Required Mutual Exclusions

When Microsoft Defender for Endpoint (MDE) is deployed alongside a third-party antivirus (Trellix ENS in this case), **both products must be configured with mutual exclusions**. This is recommended even when Microsoft Defender Antivirus (MDAV) is in **passive mode**. These are exclusions that can be set in the tools ASAP to ensure proper operation throughout the deployment.

---

## Why Exclusions Are Needed

| Reason | Detail |
| --- | --- |
| **False-positive quarantine of the other engine** | A third-party AV can quarantine MDE binaries, breaking EDR telemetry, signature updates, or onboarding. |
| **Sensor health / reporting integrity** | If Trellix blocks `SenseCncProxy.exe` or `SenseSampleUploader.exe`, devices appear in the Defender portal as **Inactive** or with **Impaired communication** even though MDE is "installed." |
| **Tamper Protection conflicts** | MDE's Tamper Protection treats third-party writes to Defender registry/files as tampering. Exclusions on the Trellix side prevent Trellix from triggering tamper events. |
| **Microsoft supportability requirement** | Microsoft's official guidance requires these mutual exclusions for a supported coexistence configuration. Without them, support cases may be deferred back to the customer to remediate. |

**Microsoft guidance:** [Microsoft Defender Antivirus compatibility](https://learn.microsoft.com/defender-endpoint/microsoft-defender-antivirus-compatibility) · [Defender Antivirus in passive mode](https://learn.microsoft.com/defender-endpoint/microsoft-defender-passive-mode) · [Switch to MDE — Phase 2 (exclusions)](https://learn.microsoft.com/defender-endpoint/switch-to-mde-phase-2)

---

## MDE Exclusions Required in Trellix **

Add the following to **Trellix ENS → Threat Prevention → On-Access Scan → Exclusions** (as both path and process exclusions, by full path). Also add them to **Exploit Prevention** and **Access Protection** exclusions where applicable.

**Source:** [learn.microsoft.com — switch-to-mde-phase-2#step-2](https://learn.microsoft.com/defender-endpoint/switch-to-mde-phase-2#step-2-add-microsoft-defender-for-endpoint-to-the-exclusion-list-for-your-existing-solution)

### EDR Sensor

| Path |
| --- |
| `C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe` |
| `C:\Program Files\Windows Defender Advanced Threat Protection\SenseCncProxy.exe` |
| `C:\Program Files\Windows Defender Advanced Threat Protection\SenseSampleUploader.exe` |
| `C:\Program Files\Windows Defender Advanced Threat Protection\SenseIR.exe` |
| `C:\Program Files\Windows Defender Advanced Threat Protection\SenseCM.exe` |
| `C:\Program Files\Windows Defender Advanced Threat Protection\SenseNdr.exe` |
| `C:\Program Files\Windows Defender Advanced Threat Protection\SenseTVM.exe` |
| `C:\Program Files\Windows Defender Advanced Threat Protection\SenseTracer.exe` |
| `C:\Program Files\Windows Defender Advanced Threat Protection\SenseDlpProcessor.exe` |
| `C:\Program Files\Windows Defender Advanced Threat Protection\Classification\SenseCE.exe` |
| `C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\DataCollection` |

### Registry

| Key |
| --- |
| `HKLM\SOFTWARE\Microsoft\Windows Advanced Threat Protection\*` |

### Microsoft Defender Antivirus

| Path |
| --- |
| `C:\Program Files\Windows Defender\MsMpEng.exe` |
| `C:\Program Files\Windows Defender\NisSrv.exe` |
| `C:\Program Files\Windows Defender\ConfigSecurityPolicy.exe` |
| `C:\Program Files\Windows Defender\MpCmdRun.exe` |
| `C:\Program Files\Windows Defender\MpDefenderCoreService.exe` |
| `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.*\MsMpEng.exe` |
| `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.*\NisSrv.exe` |
| `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.*\ConfigSecurityPolicy.exe` |
| `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.*\MpCopyAccelerator.exe` |
| `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.*\MpCmdRun.exe` |
| `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.*\MpDefenderCoreService.exe` |
| `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.*\mpextms.exe` |

### Endpoint DLP

| Path |
| --- |
| `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.*\MpDlpService.exe` |
| `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.*\MpDlpCmd.exe` |
| `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.*\MipDlp.exe` |
| `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.*\DlpUserAgent.exe` |

### Additional — WS 2012 R2 / 2016 (modern unified solution, after KB5005292)

| Path |
| --- |
| `C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Platform\*\MsSense.exe` |
| `C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Platform\*\SenseCnCProxy.exe` |
| `C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Platform\*\SenseIR.exe` |
| `C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Platform\*\SenseCE.exe` |
| `C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Platform\*\SenseSampleUploader.exe` |
| `C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Platform\*\SenseCM.exe` |
| `C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Platform\*\SenseTVM.exe` |
| `C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\DataCollection` |

---

## Trellix Exclusions Required in Microsoft Defender Antivirus *IMPORTANT: Pull the version-exact Trellix list from Trellix KB* (e.g., KB88482 / KB90387 on the Trellix Knowledge Center) — process names changed during the McAfee → Trellix rebrand and vary by ENS 10.7.x vs 10.8.x.

Add these to MDAV (even in passive mode) via Intune / Configuration Manager / GPO. ([Phase 2 — Step 4](https://learn.microsoft.com/defender-endpoint/switch-to-mde-phase-2#step-4-add-your-existing-solution-to-the-exclusion-list-for-microsoft-defender-antivirus)).

### Trellix Agent

| Type | Value |
| --- | --- |
| Path | `C:\Program Files\McAfee\Agent\` |
| Path | `C:\Program Files (x86)\McAfee\Agent\` |
| Path | `C:\ProgramData\McAfee\Agent\` |
| Process | `macmnsvc.exe` |
| Process | `masvc.exe` |
| Process | `macompatsvc.exe` |
| Process | `mctray.exe` |
| Process | `mfemms.exe` |
| Process | `mfeesp.exe` |
| Process | `cmdagent.exe` |
| Process | `frminst.exe` |
| Process | `updaterui.exe` |

### Trellix Endpoint Security (ENS) — Threat Prevention / Firewall / Web Control

| Type | Value |
| --- | --- |
| Path | `C:\Program Files\McAfee\Endpoint Security\` |
| Path | `C:\Program Files (x86)\McAfee\Endpoint Security\` |
| Path | `C:\ProgramData\McAfee\Endpoint Security\` |
| Process | `mfetp.exe` |
| Process | `mfemms.exe` |
| Process | `mfehidin.exe` |
| Process | `mfewc.exe` |
| Process | `mfewch.exe` |
| Process | `mfefire.exe` |
| Process | `mfecanary.exe` |
| Process | `mfeesp.exe` |
| Process | `mfevtps.exe` |
| Process | `EpSecApiHost.exe` |
| Process | `EndpointSecurity.exe` |
| Process | `FireSvc.exe` |
| Process | `FireTray.exe` |

### Trellix ENS — Adaptive Threat Protection (ATP)

| Type | Value |
| --- | --- |
| Path | `C:\Program Files\McAfee\Endpoint Security\Adaptive Threat Protection\` |
| Process | `mfeatp.exe` |
| Process | `mfeavsvc.exe` |

### Trellix DLP Endpoint *(if installed)*

| Type | Value |
| --- | --- |
| Path | `C:\Program Files\McAfee\DLP\` |
| Path | `C:\ProgramData\McAfee\DLP\` |
| Process | `fcag.exe` |
| Process | `fcagswd.exe` |
| Process | `fcags.exe` |
| Process | `fcagte.exe` |

### Trellix EDR / MVISION EDR / XDR Sensor *(if installed)*

| Type | Value |
| --- | --- |
| Path | `C:\Program Files\McAfee\MVISION Endpoint Detection and Response\` |
| Path | `C:\Program Files\Trellix\EDR\` |
| Process | `mfeesp.exe` |
| Process | `mvedr.exe` |
| Process | `mvehost.exe` |

---

## Mirror All Exclusions Existing Trellix into MDE

3rd party AVs and EDRs normally accumulate a substantial library of exclusions over time for line-of-business apps, custom software, SQL / Exchange / file shares, developer toolchains, imaging tools, backup agents, EDI processes, etc. These are exclusions the security team added because those applications produced false positives, performance issues, or scan conflicts. This also ensures cutover readiness from passive to active when necessary.

**These exclusions should also be added to Microsoft Defender Antivirus**

| Reason | Detail |
| --- | --- |
| **MDAV still scans in passive mode** | Passive mode disables remediation, but real-time inspection by the minifilter continues. Any historical FP that Trellix was excluding will now be hit by MDAV instead |
| **Same business reasons still apply** | The reason the exclusion exists (custom-signed binary, large DB files, hot file I/O on a production app) is independent of which AV product is reading the disk. |
| **Active-mode cutover is already done** | When Trellix is decommissioned and MDAV flips to active mode, you do **not** want to discover missing exclusions during a production outage. Mirroring them up-front means the cutover is a configuration change, not a re-tuning exercise. |
| **Audit and change-control parity** | Security review boards expect both products to be configured identically during coexistence. Drift between Trellix and MDE exclusion lists is an audit finding. |

### Recommended approach

1. **Export the full Trellix exclusion list** from ePO / Trellix ENS policy:
   - Threat Prevention → On-Access Scan → **Exclusions**
   - Threat Prevention → On-Demand Scan exclusions (if any are unique)
   - Exploit Prevention → **Exclusions / Signatures excluded**
   - Access Protection → **Exclusions**
   - Adaptive Threat Protection → **Exclusions**
   - Firewall and Web Control trusted apps / URLs (separate config, but often paired)
2. **Categorize** entries into:
   - **Business / application exclusions** — must be mirrored into MDE.
   - **Stale / obsolete** — flag for cleanup. Do not migrate exclusions for apps no longer in use; coexistence is the right time to prune.
3. **Translate to MDE exclusion types** (Defender Antivirus exclusions are more granular than Trellix):
   - Path exclusions → **Path exclusions**
   - Process exclusions → **Process exclusions** (use **full path**, not name only — Microsoft guidance)
   - File extension exclusions → **Extension exclusions**
   - For binaries that need both, add as **both** a path and a process exclusion (per Microsoft [Phase 2 — Step 4 guidance](https://learn.microsoft.com/defender-endpoint/switch-to-mde-phase-2#step-4-add-your-existing-solution-to-the-exclusion-list-for-microsoft-defender-antivirus)).
4. **Deploy via Intune / Configuration Manager / GPO** — not local registry edits — so the exclusions are version-controlled and survive reimaging.
5. **Review against MDE-specific exclusion guidance** before applying:
   - [Manage exclusions for Microsoft Defender for Endpoint and Microsoft Defender Antivirus](https://learn.microsoft.com/defender-endpoint/defender-endpoint-antivirus-exclusions)
   - [Recommendations for defining exclusions](https://learn.microsoft.com/defender-endpoint/configure-exclusions-microsoft-defender-antivirus)
   - [Common mistakes to avoid when defining exclusions](https://learn.microsoft.com/defender-endpoint/common-exclusion-mistakes-microsoft-defender-antivirus)
   - Microsoft maintains [automatic server-role exclusions](https://learn.microsoft.com/defender-endpoint/configure-server-exclusions-microsoft-defender-antivirus) for AD DS, DHCP, DNS, File Server, Hyper-V, Print Server, etc. **Do not re-add these** — they are already covered.
6. **Document the mapping** — keep a record of "Trellix exclusion X → MDE exclusion Y, business justification Z." This becomes the source of truth for the active-mode cutover review.

---

## Implementation Notes

1. **Apply both directions** — exclusions on only one side will still produce conflicts.
2. **Use full paths for process exclusions** in MDAV. Name-only process exclusions are less secure and are not recommended by Microsoft.
3. **Enable Tamper Protection** in MDE after exclusions are in place.

---

## References

- [Microsoft Defender Antivirus compatibility](https://learn.microsoft.com/defender-endpoint/microsoft-defender-antivirus-compatibility)
- [Microsoft Defender Antivirus in passive mode](https://learn.microsoft.com/defender-endpoint/microsoft-defender-passive-mode)
- [Migrate to MDE — Phase 2: Setup (mutual exclusions)](https://learn.microsoft.com/defender-endpoint/switch-to-mde-phase-2)
- [Exclusions overview for MDE / MDAV](https://learn.microsoft.com/defender-endpoint/navigate-defender-endpoint-antivirus-exclusions)
- Trellix Knowledge Center: <https://kcm.trellix.com/corporate/> *(search "Defender for Endpoint exclusions")*
