#!/usr/bin/env pwsh
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest


if (-not (Test-Command apt-get) -and (-not $Global:PWSHRC_FORCE_MODULES_EXPORT_UNSUPPORTED)) {
    return
}

[bool] $hasAptitude = Test-Command aptitude
[bool] $hasApt = Test-Command apt

if ($hasAptitude) {
    Set-EnvVar -Process -Name apt_pref -Value "aptitude"
    Set-EnvVar -Process -Name apt_upgr -Value "safe-upgrade"
} elseif ($hasApt) {
    Set-EnvVar -Process -Name apt_pref -Value "apt"
    Set-EnvVar -Process -Name apt_upgr -Value "upgrade"
} else {
    Set-EnvVar -Process -Name apt_pref -Value "apt-get"
    Set-EnvVar -Process -Name apt_upgr -Value "upgrade"
}
[bool] $hasSudo = Test-Command sudo


function Invoke-AptPreferred {
    sudo $apt_pref @args
}
Set-Alias -Name age -Value Invoke-AptPreferred

if ($hasAptitude -and (-not $Global:PWSHRC_FORCE_MODULES_EXPORT_UNSUPPORTED)) {
    Set-Alias -Name api -Value aptitude
}

function Invoke-AptCacheSearch {
    apt-cache search @args
}
Set-Alias -Name acse -Value Invoke-AptCacheSearch

if ($hasAptitude -and (-not $Global:PWSHRC_FORCE_MODULES_EXPORT_UNSUPPORTED)) {
    function Invoke-AptitudeSearch {
        aptitude search @args
    }
    Set-Alias -Name aps -Value Invoke-AptitudeSearch

    function Invoke-AptitudeSearchCompact {
        aptitude -F '* %p -> %d \n(%v/%V)' --no-gui --disable-columns search @args
    }
    Set-Alias -Name as -Value Invoke-AptitudeSearchCompact
}

function Invoke-AptFileSearchByRegex {
    apt-file search @args
}
Set-Alias -Name afs -Value Invoke-AptFileSearchByRegex

function Invoke-AptGetSource {
    apt-get source @args
}
Set-Alias -Name asrc -Value Invoke-AptGetSource

function Invoke-AptCachePolicy {
    apt-cache policy @args
}
Set-Alias -Name app -Value Invoke-AptCachePolicy
Set-Alias -Name acp -Value Invoke-AptCachePolicy

function Invoke-AptListInstalled {
    &$apt_pref list --installed @args
}
Set-Alias -Name agli -Value Invoke-AptListInstalled

function Invoke-AptListUpgradable {
    &$apt_pref list --upgradable @args
}
Set-Alias -Name aglu -Value Invoke-AptListUpgradable

function Invoke-AptCacheShowpkg {
    apt-cache showpkg @args
}
Set-Alias -Name acsp -Value Invoke-AptCacheShowpkg

if ($hasSudo -and (-not $Global:PWSHRC_FORCE_MODULES_EXPORT_UNSUPPORTED)) {
    function Invoke-AptAutoclean {
        sudo $apt_pref autoclean @args
    }
    Set-Alias -Name aac -Value Invoke-AptAutoclean
    Set-Alias -Name aga -Value Invoke-AptAutoclean

    function Invoke-AptBuildDep {
        sudo $apt_pref build-dep @args
    }
    Set-Alias -Name abd -Value Invoke-AptBuildDep
    Set-Alias -Name agb -Value Invoke-AptBuildDep

    function Invoke-AptClean {
        sudo $apt_pref clean @args
    }
    Set-Alias -Name ac -Value Invoke-AptClean
    Set-Alias -Name agc -Value Invoke-AptClean

    function Invoke-AptUpdate {
        sudo $apt_pref update @args
    }
    Set-Alias -Name ad -Value Invoke-AptUpdate
    Set-Alias -Name agu -Value Invoke-AptUpdate

    function Invoke-AptUpdateAndUpgrade {
        sudo $apt_pref update
        sudo $apt_pref $apt_upgr @args
    }
    Set-Alias -Name adg -Value Invoke-AptUpdateAndUpgrade
    Set-Alias -Name aguu -Value Invoke-AptUpdateAndUpgrade

    function Invoke-AptUpdateAndDistUpgrade {
        sudo $apt_pref update
        sudo $apt_pref dist-upgrade @args
    }
    Set-Alias -Name adu -Value Invoke-AptUpdateAndDistUpgrade
    Set-Alias -Name agud -Value Invoke-AptUpdateAndDistUpgrade

    function Invoke-AptFileUpdate {
        sudo apt-file update @args
    }
    Set-Alias -Name afu -Value Invoke-AptFileUpdate

    function Invoke-AptUpgrade {
        sudo $apt_pref $apt_upgr @args
    }
    Set-Alias -Name au -Value Invoke-AptUpgrade
    Set-Alias -Name agug -Value Invoke-AptUpgrade

    function Invoke-AptInstall {
        sudo $apt_pref install @args
    }
    Set-Alias -Name ai -Value Invoke-AptInstall
    Set-Alias -Name agi -Value Invoke-AptInstall

    function Invoke-AptInstallBatch {
        sed -e 's/  */ /g' -e 's/ *//' | cut -s -d ' ' -f 1 | xargs sudo $apt_pref install
    }
    Set-Alias -Name ail -Value Invoke-AptInstallBatch

    function Invoke-AptRemove {
        sudo $apt_pref remove @args
    }
    Set-Alias -Name agr -Value Invoke-AptRemove

    function Invoke-AptPurge {
        sudo $apt_pref purge @args
    }
    Set-Alias -Name ap -Value Invoke-AptPurge
    Set-Alias -Name agp -Value Invoke-AptPurge

    function Invoke-AptAutoremove {
        sudo $apt_pref autoremove @args
    }
    Set-Alias -Name aar -Value Invoke-AptAutoremove
    Set-Alias -Name agar -Value Invoke-AptAutoremove

    function Invoke-AptDselectUpgrade {
        sudo $apt_pref dselect-upgrade @args
    }
    Set-Alias -Name ads -Value Invoke-AptDselectUpgrade
    Set-Alias -Name agd -Value Invoke-AptDselectUpgrade

    function Invoke-AptUpdateUpgradeVerbosely {
        sudo apt update
        apt list -u
        sudo apt upgrade
    }
    Set-Alias -Name alu -Value Invoke-AptUpdateUpgradeVerbosely

    function Invoke-DebInstallAllFromPwd {
        sudo dpkg -i ./*.deb
    }
    Set-Alias -Name dia -Value Invoke-DebInstallAllFromPwd

    function Invoke-PpaPurge {
        sudo ppa-purge @args
    }
    Set-Alias -Name ppap -Value Invoke-PpaPurge

    function Invoke-DebInstall {
        sudo dpkg -i @args
    }
    Set-Alias -Name di -Value Invoke-DebInstall

    if ($hasAptitude -and (-not $Global:PWSHRC_FORCE_MODULES_EXPORT_UNSUPPORTED)) {
        function Invoke-AptRemoveExcessKernelImages {
            sudo aptitude remove -P "?and(~i~nlinux-(ima|hea) ?not(~n$(uname -r)))"
        }
        Set-Alias -Name kclean -Value Invoke-AptRemoveExcessKernelImages
    }
} else {
    append_profile_suggestions "# TODO: 🧙 Install 'sudo'."
}

function Get-AptInstalledPackages {
    dpkg --get-selections | grep -v deinstall
}
Set-Alias -Name allpkgs -Value Get-AptInstalledPackages

<#
.SYNOPSIS
    Invokes apt-add-repository followed by automatic install/upgrade of the indicated package.
.EXAMPLE
    aar ppa:xxxxxx/xxxxxx [packagename]
#>
function aar {
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $aptRepository,

        [Parameter(Mandatory = $false, Position = 1)]
        [string] $packageName
    )

    if (-not $packageName) {
        $packageName = $aptRepository.Split("/")[-1]
        Write-Debug "No package name specified. Using '$packageName'."
    }

	sudo apt-add-repository $aptRepository
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    sudo $apt_pref update
	sudo $apt_pref install $packageName
}

if ($hasAptitude -and (-not $Global:PWSHRC_FORCE_MODULES_EXPORT_UNSUPPORTED)) {
    function New-DebBasic {
        time dpkg-buildpackage -rfakeroot -us -uc @args
    }
    Set-Alias -Name mydeb -Value New-DebBasic

    <#
    .SYNOPSIS
        Create a script that will install all packages that are installed on this system.
    #>
    function apt-copy {
        print '#!/bin/sh'"\n" > apt-copy.sh

        $cmd="$apt_pref install"

        foreach ($p in Get-AptInstalledPackages) {
            cmd="${cmd} ${p}"
        }

        $cmd+"`n" | Out-File -Append apt-copy.sh

        chmod +x apt-copy.sh
    }
}


    <#
    .EXAMPLE
        apt-history -Install
    .EXAMPLE
        apt-history -Upgrade
    .EXAMPLE
        apt-history -Remove
    .EXAMPLE
        apt-history -Rollback [arg] [arg]
    .EXAMPLE
        apt-history -List
    .NOTES
        Based On: https://linuxcommando.blogspot.com/2008/08/how-to-show-apt-log-history.html
    #>
function apt-history {
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "Install")]
        [switch] $Install,

        [Parameter(Mandatory = $true, ParameterSetName = "Upgrade")]
        [switch] $Upgrade,

        [Parameter(Mandatory = $true, ParameterSetName = "Remove")]
        [switch] $Remove,

        [Parameter(Mandatory = $true, ParameterSetName = "Rollback")]
        [switch] $Rollback,

        [Parameter(Mandatory = $true, ParameterSetName = "Rollback")]
        [string] $2,

        [Parameter(Mandatory = $true, ParameterSetName = "Rollback")]
        [string] $3,

        [Parameter(Mandatory = $true, ParameterSetName = "List")]
        [switch] $List
    )
    if ($install) {
        $dpkgLogFiles = Get-ChildItem -Path /var/log -Filter dpkg* -File | Sort-Object -Property LastWriteTime -Descending
        zgrep --no-filename 'install ' @dpkgLogFiles
    } elseif ($upgrade) {
        $dpkgLogFiles = Get-ChildItem -Path /var/log -Filter dpkg* -File | Sort-Object -Property LastWriteTime -Descending
        zgrep --no-filename upgrade @dpkgLogFiles
    } elseif ($remove) {
        $dpkgLogFiles = Get-ChildItem -Path /var/log -Filter dpkg* -File | Sort-Object -Property LastWriteTime -Descending
        zgrep --no-filename remove @dpkgLogFiles
    } elseif ($rollback) {
        $dpkgLogFiles = Get-ChildItem -Path /var/log -Filter dpkg* -File | Sort-Object -Property LastWriteTime -Descending
        zgrep --no-filename upgrade @dpkgLogFiles | `
        grep $2 -A10000000 | `
        grep $3 -B10000000 | `
        awk '{print $4"="$5}'
    } elseif ($list) {
        $dpkgLogFiles = Get-ChildItem -Path /var/log -Filter dpkg* -File | Sort-Object -Property LastWriteTime -Descending
        zgrep --no-filename '' @dpkgLogFiles
    } else {
        throw "apt-history: no action specified"
    }
}

<#
.SYNOPSIS
    # Kernel-package building shortcut.
#>
function kerndeb {
    # temporarily unset MAKEFLAGS ( '-j3' will fail )
    $newMakeflags = $Env:MAKEFLAGS | perl -pe 's/-j\s*[\d]+//g'
    Set-EnvVar -Process -Name MAKEFLAGS -Value $newMakeflags
    Write-Output "MAKEFLAGS set to '$newMakeflags'"
    $appendage='-custom' # this shows up in $(uname -r )

    $revision=(Get-Date -Format "yyyyMMdd") # this shows up in the .deb file name

    make-kpkg clean

    time fakeroot make-kpkg --append-to-version "$appendage" --revision `
        "$revision" kernel_image kernel_headers
}

function apt-list-packages {
    dpkg-query -W --showformat='${Installed-Size} ${Package} ${Status}\n' | `
    grep -v deinstall | `
    Sort-Object | `
    awk '{print $1" "$2}'
}


Export-ModuleMember -Function * -Alias *
