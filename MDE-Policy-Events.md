# MDE Policy Events (SSM / "Managed by Defender for Endpoint")

Finding on-device history of attempts to apply Defender / Endpoint Security policy on a Windows device managed by **Microsoft Defender for Endpoint Security Settings Management (SSM)**.

> SSM devices use the same OMA-DM client (`omadmclient.exe`) and the same Windows event log as classic Intune MDM. The only difference is the **enrollment GUID** the events belong to — `ProviderID = MicrosoftSense` instead of `MS DM Server`.

---

## 1. The log

**Event Viewer path:**
```
Applications and Services Logs
   → Microsoft
       → Windows
           → DeviceManagement-Enterprise-Diagnostics-Provider
               ├── Admin        
               └── Operational   

**Log names:**
```
Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin
Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Operational
```

## 2. Find the SSM enrollment GUID

```powershell
$ssmGuid = (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Enrollments' |
    ForEach-Object { Get-ItemProperty $_.PSPath -EA 0 } |
    Where-Object ProviderID -eq 'MicrosoftSense').PSChildName
$ssmGuid
```
Row where `ProviderID = MicrosoftSense` is the synthetic enrollment SSM uses.

## 3. Query the log for SSM-delivered Defender policy attempts (adjust days as needed)

```powershell
$since = (Get-Date).AddDays(-7)

Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin'
    StartTime = $since
} |
Where-Object {
    $_.Id -in 209,210,211,813,814,1700,1701,1703,1704,1709,404,405,413 -and
    $_.Message -match $ssmGuid -and
    $_.Message -match 'Defender|PolicyManager|FirewallRules|ASR|ExploitGuard|SmartScreen'
} |
Select-Object TimeCreated, Id, LevelDisplayName,
    @{n='OmaUri'; e={ if ($_.Message -match 'NodeUri:\s*(\S+)')   { $matches[1] } }},
    @{n='Data';   e={ if ($_.Message -match 'Data:\s*([^\r\n]+)') { $matches[1] } }},
    @{n='Result'; e={ if ($_.Message -match 'Result:\s*\(?(0x[0-9A-Fa-f]+|\d+)\)?') { $matches[1] } else { 'Success' } }} |
Sort-Object TimeCreated -Descending |
Format-Table -AutoSize -Wrap
```

### If you want to use GUI/Event Viewer instead - Make sure to copy the GUID from the first step to use here.

Right-click the **Admin** log → **Filter Current Log…**
- **Logged:** Last 7 days
- **Event level:** Critical, Warning, Error, Information
- **Event IDs:** `209,210,211,813,814,1700,1701,1703,1704,1709,404,405,413`
- **Find…** (Ctrl-F) inside the filtered view: paste your `$ssmGuid` value, then `Defender`, `PolicyManager`, `ASR`, etc.

## 4. Event IDs

| ID | Meaning |
|---|---|
| 209 / 813 | MDM sync **started** |
| 210 / 814 | MDM sync **ended** |
| **211** | MDM sync **failed** (HRESULT) |
| 1700 / 1701 | CSP node Add/Replace **started** (NodeUri = the setting) |
| 1703 / 1704 | CSP node **succeeded** |
| **1709** | CSP node **failed** — NodeUri + Data + HRESULT |
| 404 / 405 / 413 | Config request rejected / parse error |
| 75 / 76 | SSM enrollment success / failure |

## 5. Important Fields

```
NodeUri: ./Device/Vendor/MSFT/Defender/Configuration/EnableNetworkProtection
Data:    1
Result:  (0x87D101F4)
```
- **NodeUri** — which Defender / ASR / SmartScreen setting
- **Data** — value the policy tried to push
- **Result** — HRESULT (Success = applied; anything else = why it failed)

### Common HRESULTs

| HRESULT | Meaning |
|---|---|
| `0x87D101F4` | CSP node not found / unsupported on this OS build |
| `0x86000C06` | Conflict with existing policy (often a GPO tattoo) |
| `0x80190194` | Server returned 404 — stale device record |
| `0x82AA0008` | Token expired — SSM needs re-enrollment |
| `0x80072EE7` / `0x80072EFD` | Network / proxy / TLS — can't reach `*.manage.microsoft.com` |
| `0x87D1B001` | Device offline during session |
| `0x80180005` | Malformed CSP value — typo in custom OMA-URI |

