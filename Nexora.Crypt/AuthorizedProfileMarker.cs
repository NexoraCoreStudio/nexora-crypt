using System.Security.Cryptography;
using System.Text;

namespace Nexora.Crypt;

/// <summary>
/// Per-user, per-vault local hint. Kept in AppData, not on the portable USB device.
/// IMPORTANT: this marker is never an authorization credential: VaultStore must still
/// verify a DPAPI-wrapped master key from the vault and its AES-GCM authentication tag.
/// Hidden/System attributes are for Explorer presentation, not security.
/// </summary>
internal static class AuthorizedProfileMarker
{
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("Nexora.Crypt/AuthorizedProfileMarker/v1");

    private static string PathForVault(VaultEnvelope envelope)
    {
        byte[] salt = Convert.FromBase64String(envelope.RecoverySalt);
        byte[] fingerprint = SHA256.HashData(salt);
        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Nexora", "System", Convert.ToHexString(fingerprint) + ".bin");
    }

    public static bool IsKnown(VaultEnvelope envelope)
    {
        if (!OperatingSystem.IsWindows()) return false;
        try
        {
            string path = PathForVault(envelope);
            if (!File.Exists(path)) return false;
            byte[] stored = File.ReadAllBytes(path);
            if (stored.Length > 4096) return false;
            byte[] actual = ProtectedData.Unprotect(stored, Entropy, DataProtectionScope.CurrentUser);
            byte[] expected = SHA256.HashData(Convert.FromBase64String(envelope.RecoverySalt));
            try { return CryptographicOperations.FixedTimeEquals(actual, expected); }
            finally { CryptographicOperations.ZeroMemory(actual); }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException or FormatException)
        {
            return false;
        }
    }

    public static void TryRemember(VaultEnvelope envelope)
    {
        if (!OperatingSystem.IsWindows()) return;
        try
        {
            string path = PathForVault(envelope);
            string directory = Path.GetDirectoryName(path)!;
            Directory.CreateDirectory(directory);
            byte[] fingerprint = SHA256.HashData(Convert.FromBase64String(envelope.RecoverySalt));
            byte[] protectedFingerprint = ProtectedData.Protect(fingerprint, Entropy, DataProtectionScope.CurrentUser);
            try { File.WriteAllBytes(path, protectedFingerprint); }
            finally { CryptographicOperations.ZeroMemory(fingerprint); }

            // Cosmetic only: neither these flags nor the local marker grant access.
            var attributes = File.GetAttributes(directory);
            File.SetAttributes(directory, attributes | FileAttributes.Hidden | FileAttributes.System);
            var fileAttributes = File.GetAttributes(path);
            File.SetAttributes(path, fileAttributes | FileAttributes.Hidden | FileAttributes.System);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException or FormatException)
        {
            // The vault remains usable when AppData is read-only, missing, or roamed.
            // Real authorization always comes from an authenticated DPAPI key slot.
        }
    }
}
