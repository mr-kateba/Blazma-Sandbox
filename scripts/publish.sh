#!/usr/bin/env bash
# Cross-builds the Windows x64 package from Linux or macOS (the sandbox itself needs Windows).
#   ./scripts/publish.sh [Release]
set -euo pipefail
config="${1:-Release}"
root="$(cd "$(dirname "$0")/.." && pwd)"
out="$root/publish/BlazmaSandbox"
rm -rf "$out"
dotnet test "$root/Blazma.Sandbox.slnx" -c "$config"
dotnet publish "$root/src/Blazma.App" -c "$config" -r win-x64 --self-contained true -p:PublishSingleFile=true -o "$out"
dotnet publish "$root/src/Blazma.Cli" -c "$config" -r win-x64 --self-contained true -p:PublishSingleFile=true -o "$out"
dotnet publish "$root/src/Blazma.Agent" -c "$config" -r win-x64 -o "$out/agent"
echo "Published to $out (the installer is built on Windows by scripts/publish.ps1)"
