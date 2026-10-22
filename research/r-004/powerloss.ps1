# SPDX-License-Identifier: MIT OR Apache-2.0
<#
R-004 power-loss run on an existing VirtualBox VM inside a dedicated snapshot.

Takes the snapshot pakomichi-r004-before while the VM is saved or powered
off, starts it, installs r004-snapshotd and powerloss.sh, and repeats:
start the publisher loop, wait a random time, hard power-off the VM
(VBoxManage controlvm poweroff), boot, verify. Afterwards the VM is powered
off, restored to the snapshot, and the snapshot is deleted. Requires an
exclusive lease (see the VM sharing rules) created by the caller.

The SSH target (user@address) and the sudo password file are parameters and
are never written to the repository. SSH runs from the WSL distribution
that holds the key.
#>
param(
    [Parameter(Mandatory = $true)][string]$Vm,
    [Parameter(Mandatory = $true)][string]$SshTarget,
    [Parameter(Mandatory = $true)][string]$PassFile,
    [string]$SshDistro = 'Ubuntu-24.04',
    [int]$Cycles = 3
)

$ErrorActionPreference = 'Continue'
Set-StrictMode -Version Latest
$env:WSL_UTF8 = '1'

$vbox = Join-Path (Get-ItemProperty 'HKLM:\SOFTWARE\Oracle\VirtualBox').InstallDir 'VBoxManage.exe'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$drive = $projectRoot.Substring(0, 1).ToLowerInvariant()
$linuxRoot = "/mnt/$drive" + ($projectRoot.Substring(2) -replace '\\', '/')
$passFull = (Resolve-Path -LiteralPath $PassFile).Path
$linuxPass = '/mnt/' + $passFull.Substring(0, 1).ToLowerInvariant() + ($passFull.Substring(2) -replace '\\', '/')
$helper = "$linuxRoot/research/r-004/vm-ssh.sh"
$snapshot = 'pakomichi-r004-before'
$log = Join-Path $projectRoot '.research-local\r-004\powerloss.log'
$root = '/var/lib/pakomichi-r004-pl'

function Say([string]$Text) {
    $line = "$(Get-Date -Format 'HH:mm:ss') $Text"
    Write-Output $line
    Add-Content -LiteralPath $log -Value $line -Encoding utf8
}
function Vm([string[]]$Arguments) {
    $out = (wsl.exe -d $SshDistro --cd /tmp -- bash $helper $SshTarget $linuxPass @Arguments 2>&1 | Out-String).Trim()
    return @{ Code = $LASTEXITCODE; Out = $out }
}
function VmState { ((& $vbox showvminfo $Vm --machinereadable) -match '^VMState=' -replace 'VMState="(.*)"', '$1') }
function Boot {
    & $vbox startvm $Vm --type headless | Out-Null
    $r = Vm @('wait')
    if ($r.Code -ne 0) { throw "SSH to the VM did not come up" }
}

New-Item -ItemType Directory -Force -Path (Split-Path $log) | Out-Null
$state = VmState
if ($state -notin 'saved', 'poweroff') { throw "VM must be saved or powered off, it is $state" }
Say "VM $Vm state=$state; taking snapshot $snapshot"
& $vbox snapshot $Vm take $snapshot --description 'Pakomichi R-004 power-loss run; restored and deleted afterwards' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'snapshot failed' }

try {
    Boot
    $r = Vm @('copy', '/mnt/c/temp/pakomichi/r004/bin/r004-snapshotd', "$linuxRoot/research/r-004/powerloss.sh")
    if ($r.Code -ne 0) { throw "copy failed: $($r.Out)" }
    $r = Vm @('root', 'install -m 0755 /tmp/r004-snapshotd /usr/local/bin/r004-snapshotd && install -m 0755 /tmp/powerloss.sh /root/r004-powerloss.sh && uname -r && systemctl --version | head -1 && findmnt -no FSTYPE,OPTIONS -T /var/lib')
    Say "installed: $($r.Out -replace "`r?`n", '; ')"

    for ($cycle = 1; $cycle -le $Cycles; $cycle++) {
        $r = Vm @('root', "systemd-run --quiet --unit=r004-pl-load --collect bash /root/r004-powerloss.sh load $root")
        if ($r.Code -ne 0) { throw "load start failed: $($r.Out)" }
        $delay = Get-Random -Minimum 20 -Maximum 50
        Start-Sleep -Seconds $delay
        $r = Vm @('root', "systemctl is-active r004-pl-load; wc -l < $root.ack")
        Say "cycle $cycle`: load after ${delay}s: $($r.Out -replace "`r?`n", ' ')"
        & $vbox controlvm $Vm poweroff | Out-Null
        Say "cycle $cycle`: hard power-off ($LASTEXITCODE)"
        Start-Sleep -Seconds 3
        Boot
        $r = Vm @('root', "bash /root/r004-powerloss.sh verify $root")
        Say "cycle $cycle`: verify: $($r.Out)"
    }
}
finally {
    if ((VmState) -ne 'poweroff') { & $vbox controlvm $Vm poweroff | Out-Null; Start-Sleep -Seconds 3 }
    & $vbox snapshot $Vm restore $snapshot | Out-Null
    Say "restore $snapshot ($LASTEXITCODE)"
    & $vbox snapshot $Vm delete $snapshot | Out-Null
    Say "delete $snapshot ($LASTEXITCODE); VM state now $(VmState)"
}
