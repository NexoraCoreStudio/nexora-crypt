using System.Security.Cryptography;
using System.Text;

namespace Nexora.Crypt;

internal static class VaultCrypto
{
    private static readonly byte[] DeviceEntropy = Encoding.UTF8.GetBytes("Nexora.Crypt/DeviceSlot/v1");
    private static readonly byte[] RecoveryInfo = Encoding.UTF8.GetBytes("Nexora.Crypt/RecoveryKey/v1");
    private static readonly byte[] PayloadAad = Encoding.UTF8.GetBytes("Nexora.Crypt/Payload/v1");
    private static readonly byte[] RecoveryAad = Encoding.UTF8.GetBytes("Nexora.Crypt/RecoveryWrap/v1");
    private const int PinIterations = 600_000;

    public static byte[] CreateMasterKey() => RandomNumberGenerator.GetBytes(32);

    public static string CreateRecoveryCode()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        try
        {
            string hex = Convert.ToHexString(bytes);
            return string.Join('-', Enumerable.Range(0, 8).Select(i => hex.Substring(i * 8, 8)));
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private static byte[] DecodeRecoveryCode(string code)
    {
        ArgumentNullException.ThrowIfNull(code);
        if (code.Any(c => !(Uri.IsHexDigit(c) || c is '-' or ' ')))
            throw new FormatException("Le code de recuperation doit contenir 64 caracteres hexadecimaux.");
        string hex = string.Concat(code.Where(Uri.IsHexDigit));
        if (hex.Length != 64)
            throw new FormatException("Le code de recuperation doit contenir 256 bits (64 caracteres hexadecimaux).");
        return Convert.FromHexString(hex);
    }

    public static byte[] RecoveryEncryptionKey(string recoveryCode, byte[] salt)
    {
        byte[] input = DecodeRecoveryCode(recoveryCode);
        try { return HKDF.DeriveKey(HashAlgorithmName.SHA256, input, 32, salt, RecoveryInfo); }
        finally { CryptographicOperations.ZeroMemory(input); }
    }

    public static byte[] ProtectForThisWindowsAccount(byte[] key)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Nexora Crypt necessite Windows pour DPAPI.");
        return ProtectedData.Protect(key, DeviceEntropy, DataProtectionScope.CurrentUser);
    }

    public static byte[] UnprotectForThisWindowsAccount(byte[] wrapped)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Nexora Crypt necessite Windows pour DPAPI.");
        return ProtectedData.Unprotect(wrapped, DeviceEntropy, DataProtectionScope.CurrentUser);
    }

    public static EncryptedBlob EncryptPayload(byte[] key, byte[] data) => Encrypt(key, data, PayloadAad);
    public static byte[] DecryptPayload(byte[] key, EncryptedBlob blob) => Decrypt(key, blob, PayloadAad);
    public static EncryptedBlob WrapForRecovery(byte[] key, byte[] masterKey) => Encrypt(key, masterKey, RecoveryAad);
    public static byte[] UnwrapForRecovery(byte[] key, EncryptedBlob blob) => Decrypt(key, blob, RecoveryAad);

    private static EncryptedBlob Encrypt(byte[] key, byte[] plaintext, byte[] aad)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];
        using (var aes = new AesGcm(key, 16))
            aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);
        return new EncryptedBlob
        {
            Nonce = Convert.ToBase64String(nonce),
            Ciphertext = Convert.ToBase64String(ciphertext),
            Tag = Convert.ToBase64String(tag)
        };
    }

    private static byte[] Decrypt(byte[] key, EncryptedBlob blob, byte[] aad)
    {
        byte[] nonce = Convert.FromBase64String(blob.Nonce);
        byte[] cipher = Convert.FromBase64String(blob.Ciphertext);
        byte[] tag = Convert.FromBase64String(blob.Tag);
        if (nonce.Length != 12 || tag.Length != 16)
            throw new CryptographicException("En-tete cryptographique invalide.");
        byte[] plaintext = new byte[cipher.Length];
        try
        {
            using var aes = new AesGcm(key, 16);
            aes.Decrypt(nonce, cipher, tag, plaintext, aad);
            return plaintext;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw;
        }
    }

    public static void SetPin(VaultDocument document, string pin)
    {
        if (pin.Length != 4 || pin.Any(c => c is < '0' or > '9'))
            throw new ArgumentException("Le PIN Nexora doit comporter exactement quatre chiffres.", nameof(pin));
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] verifier = Rfc2898DeriveBytes.Pbkdf2(pin, salt, PinIterations, HashAlgorithmName.SHA256, 32);
        document.PinSalt = Convert.ToBase64String(salt);
        document.PinVerifier = Convert.ToBase64String(verifier);
        CryptographicOperations.ZeroMemory(verifier);
    }

    public static bool CheckPin(VaultDocument document, string pin)
    {
        byte[] salt = Convert.FromBase64String(document.PinSalt);
        byte[] expected = Convert.FromBase64String(document.PinVerifier);
        // Limit input length, but still check a regular 4-digit PIN in constant-time.
        if (pin.Length > 128) return false;
        byte[] actual = Rfc2898DeriveBytes.Pbkdf2(pin, salt, PinIterations, HashAlgorithmName.SHA256, expected.Length);
        try
        {
            return pin.Length == 4 && pin.All(c => c is >= '0' and <= '9') &&
                   CryptographicOperations.FixedTimeEquals(actual, expected);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actual);
            CryptographicOperations.ZeroMemory(expected);
        }
    }

    public static DateTimeOffset NextLockoutUtc(int consecutiveFailures)
    {
        int minutes = consecutiveFailures >= 7 ? 24 * 60 : 15 * (1 << Math.Max(0, consecutiveFailures - 1));
        return DateTimeOffset.UtcNow.AddMinutes(minutes);
    }
}
