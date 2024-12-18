#!/usr/bin/env pwsh
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
#Requires -Modules @{ ModuleName = "poshy-env-var"; RequiredVersion = "0.6.0" }
#Requires -Modules @{ ModuleName = "poshy-lucidity"; RequiredVersion = "0.4.1" }



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
Export-ModuleMember -Function Invoke-AptPreferred -Alias age

if ($hasAptitude -and (-not (Get-Variable -Name PWSHRC_FORCE_MODULES_EXPORT_UNSUPPORTED -Scope Global -ValueOnly -ErrorAction SilentlyContinue))) {
    Set-Alias -Name api -Value aptitude
    Export-ModuleMember -Alias api
}

function Invoke-AptCacheSearch {
    apt-cache search @args
}
Set-Alias -Name acse -Value Invoke-AptCacheSearch
Export-ModuleMember -Function Invoke-AptCacheSearch -Alias acse

if ($hasAptitude -and (-not (Get-Variable -Name PWSHRC_FORCE_MODULES_EXPORT_UNSUPPORTED -Scope Global -ValueOnly -ErrorAction SilentlyContinue))) {
    function Invoke-AptitudeSearch {
        aptitude search @args
    }
    Set-Alias -Name aps -Value Invoke-AptitudeSearch
    Export-ModuleMember -Function Invoke-AptitudeSearch -Alias aps

    function Invoke-AptitudeSearchCompact {
        aptitude -F '* %p -> %d \n(%v/%V)' --no-gui --disable-columns search @args
    }
    Set-Alias -Name as -Value Invoke-AptitudeSearchCompact
    Export-ModuleMember -Function Invoke-AptitudeSearchCompact -Alias as
}

function Invoke-AptFileSearchByRegex {
    apt-file search @args
}
Set-Alias -Name afs -Value Invoke-AptFileSearchByRegex
Export-ModuleMember -Function Invoke-AptFileSearchByRegex -Alias afs

function Invoke-AptGetSource {
    apt-get source @args
}
Set-Alias -Name asrc -Value Invoke-AptGetSource
Export-ModuleMember -Function Invoke-AptGetSource -Alias asrc

function Invoke-AptCachePolicy {
    apt-cache policy @args
}
Set-Alias -Name app -Value Invoke-AptCachePolicy
Set-Alias -Name acp -Value Invoke-AptCachePolicy
Export-ModuleMember -Function Invoke-AptCachePolicy -Alias app, acp

function Invoke-AptListInstalled {
    &$apt_pref list --installed @args
}
Set-Alias -Name agli -Value Invoke-AptListInstalled
Export-ModuleMember -Function Invoke-AptListInstalled -Alias agli

function Invoke-AptListUpgradable {
    &$apt_pref list --upgradable @args
}
Set-Alias -Name aglu -Value Invoke-AptListUpgradable
Export-ModuleMember -Function Invoke-AptListUpgradable -Alias aglu

function Invoke-AptCacheShowpkg {
    apt-cache showpkg @args
}
Set-Alias -Name acsp -Value Invoke-AptCacheShowpkg
Export-ModuleMember -Function Invoke-AptCacheShowpkg -Alias acsp

if ($hasSudo -and (-not (Get-Variable -Name PWSHRC_FORCE_MODULES_EXPORT_UNSUPPORTED -Scope Global -ValueOnly -ErrorAction SilentlyContinue))) {
    function Invoke-AptAutoclean {
        sudo $apt_pref autoclean @args
    }
    Set-Alias -Name aac -Value Invoke-AptAutoclean
    Set-Alias -Name aga -Value Invoke-AptAutoclean
    Export-ModuleMember -Function Invoke-AptAutoclean -Alias aac, aga

    function Invoke-AptBuildDep {
        sudo $apt_pref build-dep @args
    }
    Set-Alias -Name abd -Value Invoke-AptBuildDep
    Set-Alias -Name agb -Value Invoke-AptBuildDep
    Export-ModuleMember -Function Invoke-AptBuildDep -Alias abd, agb

    function Invoke-AptClean {
        sudo $apt_pref clean @args
    }
    Set-Alias -Name ac -Value Invoke-AptClean
    Set-Alias -Name agc -Value Invoke-AptClean
    Export-ModuleMember -Function Invoke-AptClean -Alias ac, agc

    function Invoke-AptUpdate {
        sudo $apt_pref update @args
    }
    Set-Alias -Name ad -Value Invoke-AptUpdate
    Set-Alias -Name agu -Value Invoke-AptUpdate
    Export-ModuleMember -Function Invoke-AptUpdate -Alias ad, agu

    function Invoke-AptUpdateAndUpgrade {
        sudo $apt_pref update
        sudo $apt_pref $apt_upgr @args
    }
    Set-Alias -Name adg -Value Invoke-AptUpdateAndUpgrade
    Set-Alias -Name aguu -Value Invoke-AptUpdateAndUpgrade
    Export-ModuleMember -Function Invoke-AptUpdateAndUpgrade -Alias adg, aguu

    function Invoke-AptUpdateAndDistUpgrade {
        sudo $apt_pref update
        sudo $apt_pref dist-upgrade @args
    }
    Set-Alias -Name adu -Value Invoke-AptUpdateAndDistUpgrade
    Set-Alias -Name agud -Value Invoke-AptUpdateAndDistUpgrade
    Export-ModuleMember -Function Invoke-AptUpdateAndDistUpgrade -Alias adu, agud

    function Invoke-AptFileUpdate {
        sudo apt-file update @args
    }
    Set-Alias -Name afu -Value Invoke-AptFileUpdate
    Export-ModuleMember -Function Invoke-AptFileUpdate -Alias afu

    function Invoke-AptUpgrade {
        sudo $apt_pref $apt_upgr @args
    }
    Set-Alias -Name au -Value Invoke-AptUpgrade
    Set-Alias -Name agug -Value Invoke-AptUpgrade
    Export-ModuleMember -Function Invoke-AptUpgrade -Alias au, agug

    function Invoke-AptInstall {
        sudo $apt_pref install @args
    }
    Set-Alias -Name ai -Value Invoke-AptInstall
    Set-Alias -Name agi -Value Invoke-AptInstall
    Export-ModuleMember -Function Invoke-AptInstall -Alias ai, agi

    function Invoke-AptInstallBatch {
        sed -e 's/  */ /g' -e 's/ *//' | cut -s -d ' ' -f 1 | xargs sudo $apt_pref install
    }
    Set-Alias -Name ail -Value Invoke-AptInstallBatch
    Export-ModuleMember -Function Invoke-AptInstallBatch -Alias ail

    function Invoke-AptRemove {
        sudo $apt_pref remove @args
    }
    Set-Alias -Name agr -Value Invoke-AptRemove
    Export-ModuleMember -Function Invoke-AptRemove -Alias agr

    function Invoke-AptPurge {
        sudo $apt_pref purge @args
    }
    Set-Alias -Name ap -Value Invoke-AptPurge
    Set-Alias -Name agp -Value Invoke-AptPurge
    Export-ModuleMember -Function Invoke-AptPurge -Alias ap, agp

    function Invoke-AptAutoremove {
        sudo $apt_pref autoremove @args
    }
    Set-Alias -Name aar -Value Invoke-AptAutoremove
    Set-Alias -Name agar -Value Invoke-AptAutoremove
    Export-ModuleMember -Function Invoke-AptAutoremove -Alias aar, agar

    function Invoke-AptDselectUpgrade {
        sudo $apt_pref dselect-upgrade @args
    }
    Set-Alias -Name ads -Value Invoke-AptDselectUpgrade
    Set-Alias -Name agd -Value Invoke-AptDselectUpgrade
    Export-ModuleMember -Function Invoke-AptDselectUpgrade -Alias ads, agd

    function Invoke-AptUpdateUpgradeVerbosely {
        sudo apt update
        apt list -u
        sudo apt upgrade
    }
    Set-Alias -Name alu -Value Invoke-AptUpdateUpgradeVerbosely
    Export-ModuleMember -Function Invoke-AptUpdateUpgradeVerbosely -Alias alu

    function Invoke-DebInstallAllFromPwd {
        sudo dpkg -i ./*.deb
    }
    Set-Alias -Name dia -Value Invoke-DebInstallAllFromPwd
    Export-ModuleMember -Function Invoke-DebInstallAllFromPwd -Alias dia

    function Invoke-PpaPurge {
        sudo ppa-purge @args
    }
    Set-Alias -Name ppap -Value Invoke-PpaPurge
    Export-ModuleMember -Function Invoke-PpaPurge -Alias ppap

    function Invoke-DebInstall {
        sudo dpkg -i @args
    }
    Set-Alias -Name di -Value Invoke-DebInstall
    Export-ModuleMember -Function Invoke-DebInstall -Alias di

    if ($hasAptitude -and (-not (Get-Variable -Name PWSHRC_FORCE_MODULES_EXPORT_UNSUPPORTED -Scope Global -ValueOnly -ErrorAction SilentlyContinue))) {
        function Invoke-AptRemoveExcessKernelImages {
            sudo aptitude remove -P "?and(~i~nlinux-(ima|hea) ?not(~n$(uname -r)))"
        }
        Set-Alias -Name kclean -Value Invoke-AptRemoveExcessKernelImages
        Export-ModuleMember -Function Invoke-AptRemoveExcessKernelImages -Alias kclean
    }
}

function Get-AptInstalledPackages {
    dpkg --get-selections | grep -v deinstall
}
Set-Alias -Name allpkgs -Value Get-AptInstalledPackages
Export-ModuleMember -Function Get-AptInstalledPackages -Alias allpkgs

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
Export-ModuleMember -Function aar

if ($hasAptitude -and (-not (Get-Variable -Name PWSHRC_FORCE_MODULES_EXPORT_UNSUPPORTED -Scope Global -ValueOnly -ErrorAction SilentlyContinue))) {
    function New-DebBasic {
        time dpkg-buildpackage -rfakeroot -us -uc @args
    }
    Set-Alias -Name mydeb -Value New-DebBasic
    Export-ModuleMember -Function New-DebBasic -Alias mydeb

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
    Export-ModuleMember -Function apt-copy
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
Export-ModuleMember -Function apt-history

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
Export-ModuleMember -Function kerndeb

function apt-list-packages {
    dpkg-query -W --showformat='${Installed-Size} ${Package} ${Status}\n' | `
    grep -v deinstall | `
    Sort-Object | `
    awk '{print $1" "$2}'
}
Export-ModuleMember -Function apt-list-packages

