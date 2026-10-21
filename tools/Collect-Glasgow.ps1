<#
  Collect-Glasgow.ps1  v2  -  read-only evidence snapshot for the Glasgow audit
  v1 written 2026-09-30 (Superseded\Collect-Glasgow_2026-09-30_v1_recovered.ps1).
  v2 written 2026-10-19 by Claude for Mike Sloan. Repo: D:\REPOS\Glasgow_Evidence\tools

  HOW TO RUN ON GLASGOW (offline, about 5-10 minutes):
    1. Copy this file to the root of the snapshot USB stick.
    2. Glasgow: power on, boot straight into Windows. Do NOT enter BIOS or change anything.
    3. Log in. Plug in the stick. Note its drive letter in File Explorer.
    4. Right-click Start > "Terminal (Admin)". Type (swap E: for the stick's letter):
         powershell -ExecutionPolicy Bypass -File E:\Collect-Glasgow.ps1
    5. When it asks, type your PHONE's time (example 9:41) and press Enter.
    6. Wait for the line "RESULT: DONE". Take a phone photo of the screen.
    7. Start > Power > Shut down. Bring the stick to JENNY.

  WHAT IT DOES: reads and exports only. Changes no settings, enables nothing,
  deletes nothing. Running it does add normal log entries (your logon, PowerShell
  start, wevtutil). Those are expected and will be labelled in the audit.
  Output: <stick>\Glasgow_Snapshot_<yyyyMMdd_HHmmss>\ with a SHA-256 manifest.

  BITLOCKER: No recovery key for Glasgow exists in Mike's Microsoft account (Mike, 10/3).
  If BitLocker protection is ON, this script saves the recovery key to
  _SECRET_bitlocker\ on the stick so a later BIOS or battery change cannot lock
  Mike out. Claude seals it on JENNY. To skip that, add:  -NoBitLockerKey

  TEST RUN ON ANOTHER PC (optional): -OutRoot C:\Temp\gtest  collects THAT PC's data.
#>
param(
  [string]$OutRoot = (Split-Path -Parent $MyInvocation.MyCommand.Path),
  [switch]$NoBitLockerKey
)

$ErrorActionPreference = 'Continue'
$start = Get-Date
$stamp = $start.ToString('yyyyMMdd_HHmmss')
$out   = Join-Path $OutRoot "Glasgow_Snapshot_$stamp"
foreach ($d in 'EventLogs','EventLogs_Archived','Registry','System','Prefetch','Files') {
  New-Item -ItemType Directory -Path (Join-Path $out $d) -Force | Out-Null
}
$log  = Join-Path $out '_run_log.txt'
$errs = 0
function Note($m) { "{0}  {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff zzz'), $m | Tee-Object -FilePath $log -Append }
function Step($name, [scriptblock]$body) {
  Note "[STEP] $name"
  try { & $body } catch { $script:errs++; Note "[FAIL] $name : $($_.Exception.Message)" }
}
function SysOut($file) { Join-Path $out "System\$file" }

# --- Preflight ---------------------------------------------------------------
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Write-Host "[FAIL] Not an ADMIN terminal. Nothing collected. Close this window and redo step 4."; exit 1 }

$drive = (Get-Item $OutRoot).PSDrive
if ($drive -and $drive.Free -lt 3GB) { Write-Host "[FAIL] Less than 3 GB free on the output drive. Nothing collected."; exit 1 }

Note "START  host=$env:COMPUTERNAME  user=$env:USERNAME  local=$($start.ToString('o'))  utc=$($start.ToUniversalTime().ToString('o'))"
$phone = Read-Host "Type your PHONE's current time (example 9:41), then Enter"
Note "CLOCK  phone=$phone  pc_local=$((Get-Date).ToString('HH:mm:ss'))"

# --- 1. Log folder metadata FIRST, before anything reads the logs (F1) ------------
Step 'winevt\Logs file times' {
  Get-ChildItem "$env:windir\System32\winevt\Logs" -Force |
    Select-Object Name, Length, CreationTimeUtc, LastWriteTimeUtc, LastAccessTimeUtc, Attributes |
    Export-Csv (SysOut 'winevt_Logs_listing.csv') -NoTypeInformation
}
Step 'Event log channel settings' {
  Get-WinEvent -ListLog * -ErrorAction SilentlyContinue |
    Select-Object LogName, IsEnabled, LogMode, MaximumSizeInBytes, FileSize, RecordCount, LastWriteTime, LogFilePath |
    Export-Csv (SysOut 'eventlog_channels.csv') -NoTypeInformation
}

# --- 2. Every event channel with records (finds 11101) ------------------------
Step 'Export event channels' {
  $n = 0
  foreach ($c in (wevtutil el)) {
    $info = wevtutil gli "$c" 2>$null
    $m = ($info | Select-String 'numberOfLogRecords:\s*(\d+)')
    if ($m -and [int]$m.Matches[0].Groups[1].Value -gt 0) {
      $safe = ($c -replace '[\\/:*?"<>| %]','_')
      wevtutil epl "$c" (Join-Path $out "EventLogs\$safe.evtx") 2>$null
      if ($LASTEXITCODE -eq 0) { $n++ } else { Note "  [WARN] export failed: $c" }
    }
  }
  Note "  exported $n channels"
}
Step 'Archived logs (Archive-*.evtx)' {
  Get-ChildItem "$env:windir\System32\winevt\Logs" -Filter 'Archive-*.evtx' -Force -ErrorAction SilentlyContinue |
    Copy-Item -Destination (Join-Path $out 'EventLogs_Archived') -Force
}

# --- 3. Shadow copies and restore points (may hold an OLDER Security.evtx) ----------
Step 'Shadow copies' { vssadmin list shadows > (SysOut 'vss_shadows.txt') 2>&1 }
Step 'Restore points' { Get-ComputerRestorePoint -ErrorAction SilentlyContinue | Format-List * > (SysOut 'restore_points.txt') 2>&1 }

# --- 4. Registry -------------------------------------------------------------
Step 'Registry keys' {
  $regs = [ordered]@{
    'EventLog_Services' = 'HKLM\SYSTEM\CurrentControlSet\Services\EventLog'
    'Enum_PCI'          = 'HKLM\SYSTEM\CurrentControlSet\Enum\PCI'
    'Net_Class'         = 'HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}'
    'Display_Class'     = 'HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}'
    'NetworkList'       = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList'
    'BitLocker_Policy'  = 'HKLM\SOFTWARE\Policies\Microsoft\FVE'
    'Run_HKLM'          = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
    'Run_HKCU'          = 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
    'TimeZone'          = 'HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation'
    'W32Time'           = 'HKLM\SYSTEM\CurrentControlSet\Services\W32Time'
  }
  foreach ($k in $regs.Keys) { reg export $regs[$k] (Join-Path $out "Registry\$k.reg") /y 2>$null | Out-Null }
}
Step 'Registry hives (SYSTEM, SOFTWARE, current user)' {
  foreach ($h in 'SYSTEM','SOFTWARE') { reg save "HKLM\$h" (Join-Path $out "Registry\$h.hiv") /y 2>$null | Out-Null }
  reg save HKCU (Join-Path $out 'Registry\NTUSER_current.hiv') /y 2>$null | Out-Null
}

# --- 5. Files that record what ran and what was installed ------------------------
Step 'Device install logs (setupapi)' {
  Copy-Item "$env:windir\INF\setupapi.dev.log*","$env:windir\INF\setupapi.setup.log" (Join-Path $out 'Files') -Force -ErrorAction SilentlyContinue
}
Step 'PowerShell command history (all users)' {
  Get-ChildItem 'C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt' -Force -ErrorAction SilentlyContinue |
    ForEach-Object { Copy-Item $_.FullName (Join-Path $out ("Files\PSHistory_{0}.txt" -f $_.FullName.Split('\')[2])) -Force }
}
Step 'Prefetch' { Copy-Item "$env:windir\Prefetch\*" (Join-Path $out 'Prefetch') -Force -ErrorAction SilentlyContinue }

# --- 6. Live device and system state (read-only queries) ---------------------------
Step 'Devices' {
  Get-PnpDevice | Select-Object Present, Status, Class, FriendlyName, InstanceId, Problem, ConfigManagerErrorCode |
    Export-Csv (SysOut 'pnp_devices.csv') -NoTypeInformation
  pnputil /enum-devices /problem      > (SysOut 'pnputil_problem_devices.txt') 2>&1
  pnputil /enum-devices /class Net     > (SysOut 'pnputil_net.txt') 2>&1
  pnputil /enum-devices /class Display > (SysOut 'pnputil_display.txt') 2>&1
  Get-CimInstance Win32_VideoController | Format-List * > (SysOut 'video_controllers.txt') 2>&1
}
Step 'Network and Wi-Fi' {
  Get-NetAdapter -IncludeHidden | Format-List * > (SysOut 'net_adapters.txt') 2>&1
  Get-NetAdapterBinding -IncludeHidden -ErrorAction SilentlyContinue | Export-Csv (SysOut 'net_bindings.csv') -NoTypeInformation
  netsh wlan show interfaces > (SysOut 'wlan_interfaces.txt') 2>&1
  netsh wlan show drivers    > (SysOut 'wlan_drivers.txt') 2>&1
  netsh wlan show profiles   > (SysOut 'wlan_profiles_names_only.txt') 2>&1
}
Step 'Board, BIOS, time' {
  Get-CimInstance Win32_BaseBoard | Format-List * > (SysOut 'baseboard.txt') 2>&1
  Get-CimInstance Win32_BIOS      | Format-List * > (SysOut 'bios.txt') 2>&1
  w32tm /query /status > (SysOut 'w32tm_status.txt') 2>&1
}
Step 'Services, tasks, accounts, programs' {
  Get-CimInstance Win32_Service | Select-Object Name, DisplayName, State, StartMode, PathName, StartName |
    Export-Csv (SysOut 'services.csv') -NoTypeInformation
  Get-ScheduledTask | ForEach-Object {
    [pscustomobject]@{ Path=$_.TaskPath; Name=$_.TaskName; State=$_.State; Author=$_.Author; Date=$_.Date;
      Actions=($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | ' }
  } | Export-Csv (SysOut 'scheduled_tasks.csv') -NoTypeInformation
  Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, Description |
    Export-Csv (SysOut 'local_users.csv') -NoTypeInformation
  Get-LocalGroupMember Administrators -ErrorAction SilentlyContinue | Export-Csv (SysOut 'local_admins.csv') -NoTypeInformation
  Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Sort-Object InstallDate |
    Export-Csv (SysOut 'installed_programs.csv') -NoTypeInformation
}

# --- 7. BitLocker: status always; recovery key only if protection is ON ----------------
$blOn = $false
Step 'BitLocker status' {
  manage-bde -status > (SysOut 'bitlocker_status.txt') 2>&1
  $v = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue
  if ($v) {
    "ProtectionStatus=$($v.ProtectionStatus)  VolumeStatus=$($v.VolumeStatus)  EncryptionPercentage=$($v.EncryptionPercentage)" |
      Out-File (SysOut 'bitlocker_summary.txt')
    $script:blOn = ($v.ProtectionStatus -eq 'On')
  }
}
if ($blOn -and -not $NoBitLockerKey) {
  Step 'BitLocker recovery key backup' {
    New-Item -ItemType Directory -Path (Join-Path $out '_SECRET_bitlocker') -Force | Out-Null
    manage-bde -protectors -get $env:SystemDrive > (Join-Path $out '_SECRET_bitlocker\recovery_key.txt') 2>&1
    Note "  BitLocker is ON. Recovery key saved to _SECRET_bitlocker. Keep this stick safe."
  }
} else { Note "  BitLocker key backup: not needed or skipped (protection on = $blOn)." }

# --- 8. Hash manifest ------------------------------------------------------------
$end = Get-Date
Note "END  elapsed=$([int]($end-$start).TotalSeconds)s  step_failures=$errs"
Get-ChildItem $out -Recurse -File | Where-Object Name -ne '_manifest_sha256.csv' |
  Get-FileHash -Algorithm SHA256 |
  Select-Object Hash, @{n='File';e={$_.Path.Substring($out.Length+1)}}, @{n='Bytes';e={(Get-Item $_.Path).Length}} |
  Export-Csv (Join-Path $out '_manifest_sha256.csv') -NoTypeInformation
$mh = (Get-FileHash (Join-Path $out '_manifest_sha256.csv') -Algorithm SHA256).Hash
$fc = (Get-ChildItem $out -Recurse -File).Count

Write-Host ""
Write-Host "RESULT: DONE   step failures: $errs   files: $fc"
Write-Host "Manifest SHA-256 (photo this screen): $mh"
Write-Host "Output: $out"
Write-Host "Now: Start > Power > Shut down. Change nothing first."
