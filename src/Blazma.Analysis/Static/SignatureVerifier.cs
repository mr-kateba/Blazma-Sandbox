using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;
using Blazma.Core.Samples;

namespace Blazma.Analysis.Static;

public interface ISignatureVerifier
{
    SignatureInfo Verify(string path, bool hasSignatureDirectory);
}

/// <summary>
/// Authenticode verification. On Windows it calls WinVerifyTrust with revocation checks
/// and URL retrieval disabled, so verification never touches the network (no hashes or
/// certificate lookups leave the machine). Elsewhere a present signature is reported as
/// "present, not verified" rather than guessed.
/// </summary>
public sealed class SignatureVerifier : ISignatureVerifier
{
    public SignatureInfo Verify(string path, bool hasSignatureDirectory)
    {
        if (!hasSignatureDirectory) return new SignatureInfo(SignatureStatus.NotSigned);
        if (!OperatingSystem.IsWindows())
            return new SignatureInfo(SignatureStatus.PresentUnverified, Detail: "Signature verification requires Windows.");

        return VerifyOnWindows(path);
    }

    [SupportedOSPlatform("windows")]
    private static SignatureInfo VerifyOnWindows(string path)
    {
        string? publisher = null;
        try
        {
#pragma warning disable SYSLIB0057
            using var cert = X509Certificate.CreateFromSignedFile(path);
#pragma warning restore SYSLIB0057
            publisher = new X509Certificate2(cert).GetNameInfo(X509NameType.SimpleName, false);
        }
        catch (Exception ex) when (ex is System.Security.Cryptography.CryptographicException or PlatformNotSupportedException)
        {
            // No readable certificate: verification below reports the reason.
        }

        var result = WinTrust.Verify(path);
        return result == 0
            ? new SignatureInfo(SignatureStatus.Valid, publisher)
            : new SignatureInfo(SignatureStatus.Invalid, publisher, $"WinVerifyTrust returned 0x{result:X8}");
    }

    [SupportedOSPlatform("windows")]
    private static class WinTrust
    {
        private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
        private const uint UiNone = 2;
        private const uint RevokeNone = 0;
        private const uint ChoiceFile = 1;
        private const uint StateIgnore = 0;
        private const uint CacheOnlyUrlRetrieval = 0x00001000;
        private const uint DisableMd2Md4 = 0x00002000;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct FileInfo
        {
            public uint cbStruct;
            [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct Data
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pFile;
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
            public IntPtr pSignatureSettings;
        }

        [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false, CharSet = CharSet.Unicode)]
        private static extern int WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid action, ref Data data);

        public static int Verify(string path)
        {
            var file = new FileInfo { cbStruct = (uint)Marshal.SizeOf<FileInfo>(), pcwszFilePath = path };
            var filePtr = Marshal.AllocHGlobal(Marshal.SizeOf<FileInfo>());
            try
            {
                Marshal.StructureToPtr(file, filePtr, false);
                var data = new Data
                {
                    cbStruct = (uint)Marshal.SizeOf<Data>(),
                    dwUIChoice = UiNone,
                    fdwRevocationChecks = RevokeNone,
                    dwUnionChoice = ChoiceFile,
                    pFile = filePtr,
                    dwStateAction = StateIgnore,
                    dwProvFlags = CacheOnlyUrlRetrieval | DisableMd2Md4,
                };
                return WinVerifyTrust(IntPtr.Zero, GenericVerifyV2, ref data);
            }
            finally
            {
                Marshal.DestroyStructure<FileInfo>(filePtr);
                Marshal.FreeHGlobal(filePtr);
            }
        }
    }
}
