# Builds a self-contained Blazma Sandbox for Windows x64 into ./publish/BlazmaSandbox
#   pwsh scripts/publish.ps1 [-Configuration Release]
# The monitoring agent is published separately and placed in the app's "agent" folder;
# the app copies it into the read-only folder mapped into each Windows Sandbox.
param([string]$Configuration = "Release")
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$out = Join-Path $root "publish/BlazmaSandbox"
if (Test-Path $out) { Remove-Item $out -Recurse -Force }

dotnet test (Join-Path $root "Blazma.Sandbox.slnx") -c $Configuration
if ($LASTEXITCODE -ne 0) { throw "Tests failed" }

dotnet publish (Join-Path $root "src/Blazma.App") -c $Configuration -r win-x64 --self-contained true -p:PublishSingleFile=true -o $out
if ($LASTEXITCODE -ne 0) { throw "App publish failed" }

# "blazma" command line, next to the app so it finds the same agent folder.
dotnet publish (Join-Path $root "src/Blazma.Cli") -c $Configuration -r win-x64 --self-contained true -p:PublishSingleFile=true -o $out
if ($LASTEXITCODE -ne 0) { throw "Command line publish failed" }

dotnet publish (Join-Path $root "src/Blazma.Agent") -c $Configuration -r win-x64 -o (Join-Path $out "agent")
if ($LASTEXITCODE -ne 0) { throw "Agent publish failed" }

# Installer (Inno Setup 6, preinstalled on GitHub's Windows runners; skipped when missing).
$version = ([xml](Get-Content (Join-Path $root "Directory.Build.props"))).Project.PropertyGroup.Version | Where-Object { $_ } | Select-Object -First 1
$candidates = @(
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
)
$onPath = Get-Command iscc -ErrorAction SilentlyContinue
if ($onPath) { $candidates = @($onPath.Source) + $candidates }
$iscc = $candidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if ($iscc) {
    & $iscc "/DAppVersion=$version" "/DSourceDir=$out" "/DOutputDir=$(Join-Path $root 'publish')" (Join-Path $root "installer/BlazmaSandbox.iss")
    if ($LASTEXITCODE -ne 0) { throw "Installer build failed" }
    Write-Host "Installer: publish/BlazmaSandbox-$version-setup.exe"
} else {
    Write-Host "Inno Setup 6 not found; skipping the installer (install it from https://jrsoftware.org/isinfo.php)."
}

Write-Host "Published to $out"
