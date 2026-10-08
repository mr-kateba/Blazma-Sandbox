using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

namespace Blazma.Sandbox.Processes;

/// <summary>
/// A short-lived file holding one secret (a guest password) for a program that can only read
/// secrets from a file (<c>VBoxManage --passwordfile</c>). Created with an access list that only
/// grants the current user, written without a trailing newline, and overwritten and deleted
/// on dispose. Keeps the secret off every command line.
/// </summary>
public sealed class SecretFile : IDisposable
{
    public string Path { get; }

    private SecretFile(string path) => Path = path;

    public static SecretFile Create(string folder, string secret)
    {
        Directory.CreateDirectory(folder);
        var path = System.IO.Path.Combine(folder, "s-" + Guid.NewGuid().ToString("N") + ".tmp");
        var bytes = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false).GetBytes(secret);
        try
        {
            using var stream = OpenRestricted(path);
            stream.Write(bytes);
        }
        catch
        {
            TryDelete(path, bytes.Length);
            throw;
        }
        finally
        {
            Array.Clear(bytes);
        }
        return new SecretFile(path);
    }

    private static FileStream OpenRestricted(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            var user = WindowsIdentity.GetCurrent().User ?? throw new InvalidOperationException("Cannot determine the current user.");
            var security = new FileSecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            security.SetOwner(user);
            security.AddAccessRule(new FileSystemAccessRule(user, FileSystemRights.FullControl, AccessControlType.Allow));
            return new FileInfo(path).Create(FileMode.CreateNew, FileSystemRights.Write | FileSystemRights.Read, FileShare.None, 4096, FileOptions.WriteThrough, security);
        }
        return new FileStream(path, new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.Write,
            Share = FileShare.None,
            UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
        });
    }

    public void Dispose() => TryDelete(Path, null);

    private static void TryDelete(string path, int? length)
    {
        try
        {
            if (!File.Exists(path)) return;
            var size = length ?? (int)Math.Min(new FileInfo(path).Length, 64 * 1024);
            using (var stream = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.None))
                stream.Write(new byte[size]);
            File.Delete(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            try { File.Delete(path); }
            catch (Exception inner) when (inner is IOException or UnauthorizedAccessException) { }
        }
    }
}
