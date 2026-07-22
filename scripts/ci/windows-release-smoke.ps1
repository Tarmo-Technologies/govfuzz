# SPDX-License-Identifier: Apache-2.0

param(
    [Parameter(Mandatory = $true)]
    [string]$BinaryDir
)

$ErrorActionPreference = "Stop"
$binaryRoot = (Resolve-Path $BinaryDir).Path
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$fixture = Join-Path $repoRoot "tests\fixtures\engine_parity\magic_byte"
$govfuzz = Join-Path $binaryRoot "govfuzz.exe"
$daemon = Join-Path $binaryRoot "govfuzz-daemon.exe"

Get-CimInstance Win32_OperatingSystem |
    Select-Object Caption, Version, BuildNumber |
    Format-List
& $govfuzz --version
& $daemon --help | Out-Null
& $govfuzz scan $fixture `
    --work-dir "$env:RUNNER_TEMP\govfuzz-windows-scan"
& $govfuzz auto $fixture `
    --work-dir "$env:RUNNER_TEMP\govfuzz-windows-plan" `
    --languages c --list-targets --no-discovery-cache

if (-not (Get-Command clang -ErrorAction SilentlyContinue)) {
    choco install llvm --yes --no-progress
}
if (-not (Get-Command make -ErrorAction SilentlyContinue)) {
    choco install make --yes --no-progress
}

# Chocolatey updates the persistent machine/user PATH, but PowerShell keeps the
# process environment it inherited. Refresh it so tools installed above are
# immediately usable in clean OpenSSH and CI sessions.
$env:Path = (@(
        [Environment]::GetEnvironmentVariable("Path", "Machine")
        [Environment]::GetEnvironmentVariable("Path", "User")
        $env:Path
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join ";"
clang --version
make --version

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vsPath = & $vswhere -latest -products * `
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
    -property installationPath
if (-not $vsPath) {
    throw "Visual Studio C++ Build Tools were not found"
}
Import-Module (Join-Path $vsPath "Common7\Tools\Microsoft.VisualStudio.DevShell.dll")
Enter-VsDevShell -VsInstallPath $vsPath -SkipAutomaticLocation `
    -DevCmdArguments "-arch=x64 -host_arch=x64"
Get-Command link.exe | Format-List Source

$work = "$env:RUNNER_TEMP\govfuzz-windows-fuzz"
& $govfuzz auto $fixture `
    --work-dir $work `
    --languages c `
    --target parse_frame `
    --iterations 32 `
    --single-pass `
    --sanitizers none `
    --per-target-time 5 `
    --no-discovery-cache `
    --verbose
$report = Get-Content "$work\auto\run.json" -Raw | ConvertFrom-Json
if ($report.summary.built_and_fuzzed -ne 1) {
    Get-ChildItem $work -Recurse -File |
        Where-Object {
            $_.Name -in @(
                "Makefile",
                "result.json",
                "run.json",
                "missing-deps.txt",
                "bug-report.md"
            )
        } |
        ForEach-Object {
            Write-Host "--- $($_.FullName)"
            Get-Content $_.FullName
        }
    throw "Windows smoke did not build and fuzz parse_frame: $($report.summary | ConvertTo-Json -Compress)"
}
