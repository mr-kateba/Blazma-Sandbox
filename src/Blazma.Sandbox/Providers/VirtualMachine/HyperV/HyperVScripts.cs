using System.Globalization;
using System.Text;
using static Blazma.Sandbox.Providers.VirtualMachine.PowerShellText;

namespace Blazma.Sandbox.Providers.VirtualMachine.HyperV;

/// <summary>
/// The PowerShell the Hyper-V provider runs on the host. Every user value is a single-quoted
/// literal (<see cref="PowerShellText.Quote"/>) assigned to a variable at the top of the script;
/// the code below only refers to the variables. VM and checkpoint names are resolved to ids once
/// and compared with <c>-eq</c> (never passed to a wildcard parameter). Each script starts with a
/// <c># blazma:&lt;operation&gt;</c> line.
/// </summary>
internal static class HyperVScripts
{
    /// <summary>Mirrors <see cref="Contracts.Protocol.IsAllowedOutboxName"/> as a guest-side pre-filter; the host checks every name again.</summary>
    public const string AllowedOutboxPattern = @"^((hello|heartbeat|done|baseline|after)\.json|capture\.pcapng|events-\d{6}\.ndjson|screen-\d{6}\.raw|(dropped|memory)-\d{4}\.(bin|json))$";

    /// <summary>Hyper-V Administrators, a built-in local group.</summary>
    private const string HyperVAdministratorsSid = "S-1-5-32-578";

    public static string Availability(string vmName, string checkpointName) => Script("availability", $$"""
        $vmName = {{Quote(vmName)}}
        $checkpointName = {{Quote(checkpointName)}}
        $module = [bool](Get-Module -ListAvailable -Name Hyper-V)
        'module=' + $module
        if ($module) {
          Import-Module Hyper-V
          $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
          $access = $principal.IsInRole([Security.Principal.SecurityIdentifier]'{{HyperVAdministratorsSid}}') -or $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
          $all = $null
          if ($access) { try { $all = @(Get-VM) } catch { $access = $false } }
          'access=' + $access
          if ($access) {
            $vm = @($all | Where-Object { $_.Name -eq $vmName })
            'vms=' + $vm.Count
            if ($vm.Count -eq 1) {
              'state=' + $vm[0].State
              'checkpoints=' + @(Get-VMCheckpoint -VM $vm[0] | Where-Object { $_.Name -eq $checkpointName }).Count
              {{ConnectedAdapters("$vm[0]")}}
            }
          }
        }
        """);

    public static string Inspect(string vmName, string checkpointName) => Script("inspect", $$"""
        $vmName = {{Quote(vmName)}}
        $checkpointName = {{Quote(checkpointName)}}
        $vm = @(Get-VM | Where-Object { $_.Name -eq $vmName })
        if ($vm.Count -ne 1) { throw "Found $($vm.Count) virtual machines with the configured name." }
        $cp = @(Get-VMCheckpoint -VM $vm[0] | Where-Object { $_.Name -eq $checkpointName })
        if ($cp.Count -ne 1) { throw "Found $($cp.Count) checkpoints with the configured name." }
        'id=' + $vm[0].Id
        'checkpoint=' + $cp[0].Id
        'state=' + $vm[0].State
        """);

    /// <summary>Restores the checkpoint and lists the adapters connected in the restored configuration.</summary>
    public static string Restore(Guid vmId, Guid checkpointId) => Script("restore", $$"""
        {{VmById(vmId)}}
        {{Checkpoint(checkpointId)}}
        Restore-VMCheckpoint -VMCheckpoint $cp -Confirm:$false
        {{ConnectedAdapters("$vm")}}
        """);

    public static string Start(Guid vmId, TimeSpan bootTimeout) => Script("start", $$"""
        {{VmById(vmId)}}
        Start-VM -VM $vm
        $deadline = (Get-Date).AddSeconds({{Seconds(bootTimeout)}})
        while ((Get-VM -Id $vm.Id).Heartbeat -notlike 'Ok*') {
          if ((Get-Date) -gt $deadline) { throw 'The guest did not report a heartbeat in time. Check that the integration services are enabled.' }
          Start-Sleep -Seconds 2
        }
        """);

    public static string Probe(Guid vmId, Credentials credentials, TimeSpan wait) => Guest("probe", vmId, credentials, wait, "", """
        Invoke-Command -Session $session -ScriptBlock { $true } | Out-Null
        """);

    public static string CreateFolders(Guid vmId, Credentials credentials, TimeSpan wait, IEnumerable<string> folders) => Guest("mkdir", vmId, credentials, wait,
        $"$folders = {QuoteArray(folders)}", """
        Invoke-Command -Session $session -ArgumentList (,$folders) -ScriptBlock { param($list) foreach ($f in $list) { [void][IO.Directory]::CreateDirectory($f) } }
        """);

    public static string CopyTo(Guid vmId, Credentials credentials, TimeSpan wait, IEnumerable<string> hostFiles, string guestFolder) => Guest("copyto", vmId, credentials, wait,
        $$"""
        $hostFiles = {{QuoteArray(hostFiles)}}
        $guestFolder = {{Quote(guestFolder)}}
        """, """
        Copy-Item -ToSession $session -LiteralPath $hostFiles -Destination $guestFolder -Force
        """);

    /// <summary>
    /// A process started inside a PowerShell Direct session dies with the session, so the agent runs
    /// as a scheduled task: the guest account, its interactive desktop, highest privileges (the full
    /// administrator token even with UAC on). The task outlives the session; the checkpoint restore
    /// removes it.
    /// </summary>
    public static string StartAgent(Guid vmId, Credentials credentials, TimeSpan wait, string agent, string inFolder, string outFolder, string taskUser, string taskName) =>
        Guest("start-agent", vmId, credentials, wait, $$"""
        $agent = {{Quote(agent)}}
        $inFolder = {{Quote(inFolder)}}
        $outFolder = {{Quote(outFolder)}}
        $taskUser = {{Quote(taskUser)}}
        $taskName = {{Quote(taskName)}}
        """, """
        Invoke-Command -Session $session -ArgumentList $agent, $inFolder, $outFolder, $taskUser, $taskName -ScriptBlock {
          param($exe, $inDir, $outDir, $user, $name)
          $action = New-ScheduledTaskAction -Execute $exe -Argument ('"' + $inDir + '" "' + $outDir + '"') -WorkingDirectory ([IO.Path]::GetDirectoryName($exe))
          $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
          $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 2) -MultipleInstances IgnoreNew
          Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Settings $settings -Force | Out-Null
          Start-ScheduledTask -TaskName $name
          $deadline = (Get-Date).AddSeconds(15)
          do { Start-Sleep -Milliseconds 500; $state = [string](Get-ScheduledTask -TaskName $name).State } while ($state -ne 'Running' -and (Get-Date) -lt $deadline)
          if ($state -ne 'Running') { throw "The agent task did not start (state: $state). The guest account must be signed in inside the VM when the checkpoint is taken, or sign in automatically." }
        }
        """);

    /// <summary>
    /// Lists the guest output folder (printed as <c>file=length|name</c>) and copies the files the host
    /// does not have yet into <paramref name="incoming"/>, within the byte budget. <c>done.json</c> is
    /// considered last.
    /// </summary>
    public static string Fetch(Guid vmId, Credentials credentials, TimeSpan wait, string guestOut, string incoming, IEnumerable<string> have, long budget, long maxFileBytes) =>
        Guest("fetch", vmId, credentials, wait, $$"""
        $guestOut = {{Quote(guestOut)}}
        $incoming = {{Quote(incoming)}}
        $have = {{QuoteArray(have)}}
        $budget = [long]{{budget.ToString(CultureInfo.InvariantCulture)}}
        $maxFile = [long]{{maxFileBytes.ToString(CultureInfo.InvariantCulture)}}
        $pattern = {{Quote(AllowedOutboxPattern)}}
        """, """
        $files = @(Invoke-Command -Session $session -ArgumentList $guestOut -ScriptBlock {
          param($p)
          Get-ChildItem -LiteralPath $p -File -Force | Where-Object { -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) } | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Length = $_.Length } }
        })
        $skip = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        foreach ($n in $have) { [void]$skip.Add($n) }
        $paths = New-Object 'System.Collections.Generic.List[string]'
        foreach ($f in ($files | Sort-Object @{ Expression = { $_.Name -eq 'done.json' } }, Name)) {
          'file=' + $f.Length + '|' + $f.Name
          if ($f.Name -cnotmatch $pattern -or $skip.Contains([string]$f.Name) -or $f.Length -gt $maxFile) { continue }
          if ($f.Length -gt $budget) { break }
          $budget -= $f.Length
          $paths.Add($guestOut + '\' + $f.Name)
        }
        if ($paths.Count -gt 0) { Copy-Item -FromSession $session -LiteralPath $paths.ToArray() -Destination $incoming -Force }
        """);

    /// <summary>Turns the VM off (if it is not already off or saved) and restores the checkpoint.</summary>
    public static string Reset(Guid vmId, Guid checkpointId) => Script("reset", $$"""
        {{VmById(vmId)}}
        if ($vm.State -notin 'Off', 'Saved') { Stop-VM -VM $vm -TurnOff -Force -Confirm:$false }
        {{Checkpoint(checkpointId)}}
        Restore-VMCheckpoint -VMCheckpoint $cp -Confirm:$false
        """);

    internal sealed record Credentials(string User, string Password)
    {
        public override string ToString() => $"{User} (password hidden)";
    }

    private static string VmById(Guid id) => $"$vm = Get-VM -Id {Quote(id.ToString())}";

    private static string Checkpoint(Guid id) => $$"""
        $cp = @(Get-VMCheckpoint -VM $vm | Where-Object { $_.Id -eq {{Quote(id.ToString())}} })
        if ($cp.Count -ne 1) { throw 'The checkpoint no longer exists.' }
        $cp = $cp[0]
        """;

    private static string ConnectedAdapters(string vm) =>
        $"foreach ($a in @(Get-VMNetworkAdapter -VM {vm})) {{ if ($a.SwitchName) {{ 'adapter=' + $a.Name + ' (' + $a.SwitchName + ')' }} }}";

    /// <summary>Opens a PowerShell Direct session (retrying until <paramref name="wait"/>), runs <paramref name="body"/>, closes the session.</summary>
    private static string Guest(string operation, Guid vmId, Credentials credentials, TimeSpan wait, string data, string body) => Script(operation, $$"""
        {{VmById(vmId)}}
        {{data}}
        $guestUser = {{Quote(credentials.User)}}
        $guestPassword = {{Quote(credentials.Password)}}
        $credential = New-Object System.Management.Automation.PSCredential -ArgumentList $guestUser, (ConvertTo-SecureString -String $guestPassword -AsPlainText -Force)
        $guestPassword = $null
        $deadline = (Get-Date).AddSeconds({{Seconds(wait)}})
        while ($true) {
          try { $session = New-PSSession -VMId $vm.Id -Credential $credential -ErrorAction Stop; break }
          catch { if ((Get-Date) -gt $deadline) { throw } ; Start-Sleep -Seconds 2 }
        }
        try {
        {{body}}
        } finally { Remove-PSSession -Session $session -ErrorAction SilentlyContinue }
        """);

    private static string Script(string operation, string body)
    {
        var builder = new StringBuilder();
        builder.Append("# blazma:").Append(operation).Append('\n');
        builder.Append("$ErrorActionPreference = 'Stop'\n");
        builder.Append("$ProgressPreference = 'SilentlyContinue'\n");
        builder.Append("try {\n").Append(body.ReplaceLineEndings("\n")).Append('\n');
        builder.Append('\'').Append(PowerShellHost.OkMarker).Append("'\n");
        builder.Append("} catch {\n");
        builder.Append('\'').Append(PowerShellHost.ErrorMarker).Append("' + ($_.Exception.Message -replace '\\s+', ' ')\n");
        builder.Append("}\n");
        return builder.ToString();
    }

    private static string Seconds(TimeSpan t) => ((long)Math.Max(1, t.TotalSeconds)).ToString(CultureInfo.InvariantCulture);
}
