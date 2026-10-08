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

dotnet publish (Join-Path $root "src/Blazma.Agent") -c $Configuration -r win-x64 -o (Join-Path $out "agent")
if ($LASTEXITCODE -ne 0) { throw "Agent publish failed" }

Write-Host "Published to $out"
