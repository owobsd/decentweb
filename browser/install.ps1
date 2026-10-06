# Installs the dweb resolver and a dedicated LibreWolf profile (Windows).
#
# Run from an unpacked release folder:  powershell -ExecutionPolicy Bypass -File browser\install.ps1
# 1. copies the programs and network.toml to %LOCALAPPDATA%\dweb
# 2. runs the resolver at logon (scheduled task) on 127.0.0.1:7780
# 3. creates a LibreWolf profile that uses the resolver and trusts its local
#    certificate authority (this profile only, never the Windows store)
# 4. adds a "dweb browser" shortcut to the Start menu
$ErrorActionPreference = "Stop"

$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Src = Split-Path -Parent $Here
$Dest = Join-Path $env:LOCALAPPDATA "dweb"
$BinDir = Join-Path $Dest "bin"
$ProfileDir = Join-Path $Dest "librewolf-profile"
$Data = Join-Path $Dest "resolver"
New-Item -ItemType Directory -Force -Path $BinDir, $ProfileDir, $Data | Out-Null

foreach ($b in "dweb-resolver", "dweb-wallet", "dweb-site", "dweb-node") {
    $found = @("$Src\bin\$b.exe", "$Src\target\release\$b.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $found) { throw "cannot find $b.exe" }
    Copy-Item $found $BinDir -Force
}
if (-not (Test-Path "$Dest\network.toml")) { Copy-Item "$Src\network.toml" $Dest }

$Resolver = Join-Path $BinDir "dweb-resolver.exe"
$TaskArgs = "--config `"$Dest\network.toml`" --data-dir `"$Data`""
& $Resolver --config "$Dest\network.toml" --data-dir "$Data" --export-ca "$Dest\ca.pem" | Out-Null

# Background resolver at logon.
$action = New-ScheduledTaskAction -Execute $Resolver -Argument $TaskArgs
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit 0
Register-ScheduledTask -TaskName "dweb-resolver" -Action $action -Trigger $trigger -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName "dweb-resolver"
Write-Host "resolver running (scheduled task dweb-resolver)"

# Profile.
Copy-Item "$Here\user.js" $ProfileDir -Force
$certutil = Get-Command certutil.exe -ErrorAction SilentlyContinue |
    Where-Object { $_.Source -notlike "*\System32\*" } | Select-Object -First 1
if ($certutil) {
    if (-not (Test-Path "$ProfileDir\cert9.db")) { & $certutil.Source -N --empty-password -d "sql:$ProfileDir" }
    & $certutil.Source -A -n "dweb local resolver CA" -t "C,," -i "$Dest\ca.pem" -d "sql:$ProfileDir"
    Write-Host "local CA trusted in the dweb profile only"
} else {
    Write-Host "NSS certutil not found. In the dweb browser, import $Dest\ca.pem via"
    Write-Host "Settings > Privacy & Security > Certificates > View Certificates > Authorities > Import,"
    Write-Host "and tick 'Trust this CA to identify websites'. Do NOT add it to the Windows store."
}

# Shortcut.
$lw = @("$env:ProgramFiles\LibreWolf\librewolf.exe", "${env:ProgramFiles(x86)}\LibreWolf\librewolf.exe") |
    Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $lw) { Write-Host "LibreWolf not found: install it from https://librewolf.net, then re-run"; $lw = "librewolf.exe" }
$lnk = Join-Path ([Environment]::GetFolderPath("Programs")) "dweb browser.lnk"
$sh = (New-Object -ComObject WScript.Shell).CreateShortcut($lnk)
$sh.TargetPath = $lw
$sh.Arguments = "--no-remote --profile `"$ProfileDir`""
$sh.Save()
Write-Host "Done. Open 'dweb browser' from the Start menu. Your normal browser is unchanged."
