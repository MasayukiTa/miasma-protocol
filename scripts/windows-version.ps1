# windows-version.ps1 -- map a release version such as 0.3.2-beta.12 to the
# numeric versions that Windows Installer and the bootstrapper need.
#
# Dot-source it:  . "$PSScriptRoot\windows-version.ps1"
#
# WHY A MAPPING IS NEEDED
#   * MSI ProductVersion is numeric only: major.minor.build with major <= 255,
#     minor <= 255, build <= 65535 (a fourth field is allowed but Windows
#     Installer IGNORES it when it compares versions for an upgrade). So
#     "0.3.2-beta.12" cannot be used, and "0.3.2.12" would make beta.12 and
#     beta.13 look identical to the MSI upgrade logic.
#   * The ordering we need for one release series is
#         beta.N  <  beta.N+1  <  rc.N  <  final (0.3.2)
#     and a later final must replace an installed beta.
#
# THE SCHEME
#   rank   = N            for beta.N   (1..899)
#            900 + N      for rc.N     (1..98)
#            999          for a final release
#   MsiVersion    = major.minor.(patch * 1000 + rank)   -- the third field
#                   carries the pre-release rank, so Windows Installer orders
#                   every release correctly using only its first three fields.
#                   patch must be <= 65 so that the third field stays <= 65535.
#   BundleVersion = major.minor.patch.rank              -- the bootstrapper
#                   (Burn) compares all four fields, and this form is readable
#                   in Programs and Features (for example 0.3.2.12 = beta.12).
#   The UpgradeCode values in miasma.wxs and bundle.wxs never change.
#
#   Examples: 0.3.2-beta.11 -> MSI 0.3.2011 / bundle 0.3.2.11
#             0.3.2-beta.12 -> MSI 0.3.2012 / bundle 0.3.2.12
#             0.3.2-beta.13 -> MSI 0.3.2013 / bundle 0.3.2.13
#             0.3.2         -> MSI 0.3.2999 / bundle 0.3.2.999
#             0.3.3-beta.1  -> MSI 0.3.3001 / bundle 0.3.3.1   (above 0.3.2)

function ConvertTo-MiasmaWindowsVersion {
    param([Parameter(Mandatory = $true)][string]$Version)

    $v = $Version.Trim()
    if ($v.StartsWith("v")) { $v = $v.Substring(1) }

    if ($v -notmatch '^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$') {
        throw "Version '$Version' is not of the form MAJOR.MINOR.PATCH or MAJOR.MINOR.PATCH-LABEL."
    }
    $major = [int]$Matches[1]; $minor = [int]$Matches[2]; $patch = [int]$Matches[3]
    $label = $Matches[4]

    if ($major -gt 255 -or $minor -gt 255) {
        throw "Version '$Version': major and minor must be <= 255 (MSI ProductVersion limit)."
    }
    if ($patch -gt 65) {
        throw "Version '$Version': patch must be <= 65 so that patch*1000+rank fits the 65535 limit of the MSI third field."
    }

    if (-not $label) {
        $rank = 999
    } elseif ($label -match '^beta\.([1-9]\d{0,2})$') {
        $rank = [int]$Matches[1]
        if ($rank -gt 899) { throw "Version '$Version': beta number must be <= 899." }
    } elseif ($label -match '^rc\.([1-9]\d?)$') {
        $rank = 900 + [int]$Matches[1]
        if ($rank -gt 998) { throw "Version '$Version': rc number must be <= 98." }
    } else {
        throw "Version '$Version': pre-release label '$label' is not supported (use beta.N or rc.N)."
    }

    [PSCustomObject]@{
        Semver        = $v
        Core          = "$major.$minor.$patch"
        Label         = $label
        Rank          = $rank
        MsiVersion    = "$major.$minor.$($patch * 1000 + $rank)"
        BundleVersion = "$major.$minor.$patch.$rank"
    }
}

# Compare two dotted numeric versions using only the first three fields, the way
# Windows Installer does. Returns -1, 0 or 1.
function Compare-MsiVersion {
    param([string]$A, [string]$B)
    $pa = $A.Split('.') | Select-Object -First 3 | ForEach-Object { [int]$_ }
    $pb = $B.Split('.') | Select-Object -First 3 | ForEach-Object { [int]$_ }
    for ($i = 0; $i -lt 3; $i++) {
        if ($pa[$i] -lt $pb[$i]) { return -1 }
        if ($pa[$i] -gt $pb[$i]) { return 1 }
    }
    return 0
}
