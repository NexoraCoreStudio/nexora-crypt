using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Nexora.Crypt;

/// <summary>
/// Fortress v2 cryptography. V1 is never changed implicitly.
/// Each item receives a new independent AES-256 data key; that key is wrapped by a
/// separate HKDF-derived vault key. The manifest is encrypted independently.
/// This is defense in depth, not a claim that AES is 'ten times stronger'.
/// </summary>
internal static class VaultFortressCrypto
{
    private static readonly byte[] ManifestInfo = Encoding.UTF8.GetBytes("Nexora.Crypt/Fortress/v2/manifest-key");
    private static readonly byte[] WrapInfo = Encoding.UTF8.GetBytes("Nexora.Crypt/Fortress/v2/wrapping-key");
    private const int KeyBytes = 32;
    private const int MaxItemBytes = 16 * 1024 * 1024;

    internal sealed class ItemEnvelope
    {
        public ItemEnvelope() { }
        public int Version { get; set; } = 2;
        public EncryptedBlob WrappedKey { get; set; } = new();
        public EncryptedBlob Content { get; set; } = new();
    }

    internal static byte[] NewSalt() => RandomNumberGenerator.GetBytes(32);

    private static byte[] Salt(VaultEnvelope envelope)
    {
        if (envelope.Version != 2) throw new InvalidDataException("Le coffre n'utilise pas Fortress v2.");
        byte[] salt = Convert.FromBase64String(envelope.KdfSalt);
        if (salt.Length != 32)
        {
            CryptographicOperations.ZeroMemory(salt);
            throw new InvalidDataException("Sel Fortress invalide.");
        }
        return salt;
    }

    private static byte[] Derive(byte[] masterKey, byte[] salt, byte[] info)
    {
        if (masterKey.Length != KeyBytes) throw new CryptographicException("Cle maitresse de taille invalide.");
        return HKDF.DeriveKey(HashAlgorithmName.SHA256, masterKey, KeyBytes, salt, info);
    }

    private static byte[] Context(string purpose, string value) =>
        Encoding.UTF8.GetBytes("Nexora.Crypt/Fortress/v2/" + purpose + "/" + value);

    internal static EncryptedBlob EncryptManifest(VaultEnvelope envelope, byte[] masterKey, byte[] data)
    {
        byte[] salt = Salt(envelope);
        byte[] key = Derive(masterKey, salt, ManifestInfo);
        try { return Seal(key, data, Context("manifest", envelope.RevisionToken + "/" + envelope.KdfSalt)); }
        finally { CryptographicOperations.ZeroMemory(key); CryptographicOperations.ZeroMemory(salt); }
    }

    internal static byte[] DecryptManifest(VaultEnvelope envelope, byte[] masterKey)
    {
        byte[] salt = Salt(envelope);
        byte[] key = Derive(masterKey, salt, ManifestInfo);
        try { return Open(key, envelope.Payload, Context("manifest", envelope.RevisionToken + "/" + envelope.KdfSalt)); }
        finally { CryptographicOperations.ZeroMemory(key); CryptographicOperations.ZeroMemory(salt); }
    }

    internal static string EncryptItem(VaultEnvelope envelope, byte[] masterKey, string logicalPath, byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        if (data.Length > MaxItemBytes) throw new ArgumentOutOfRangeException(nameof(data), "Element trop volumineux.");
        byte[] salt = Salt(envelope);
        byte[] wrappingKey = Derive(masterKey, salt, WrapInfo);
        byte[] itemKey = RandomNumberGenerator.GetBytes(KeyBytes);
        try
        {
            var item = new ItemEnvelope
            {
                WrappedKey = Seal(wrappingKey, itemKey, Context("item-key", logicalPath)),
                Content = Seal(itemKey, data, Context("item-data", logicalPath))
            };
            byte[] serialized = JsonSerializer.SerializeToUtf8Bytes(item);
            try { return Convert.ToBase64String(serialized); }
            finally { CryptographicOperations.ZeroMemory(serialized); }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(wrappingKey);
            CryptographicOperations.ZeroMemory(itemKey);
            CryptographicOperations.ZeroMemory(salt);
        }
    }

    internal static byte[] DecryptItem(VaultEnvelope envelope, byte[] masterKey, string logicalPath, string encoded)
    {
        byte[] serialized = Convert.FromBase64String(encoded);
        if (serialized.Length > 2 * MaxItemBytes + 4096) throw new InvalidDataException("Element Fortress trop volumineux.");
        try
        {
            var item = JsonSerializer.Deserialize<ItemEnvelope>(serialized)
                ?? throw new InvalidDataException("Entete d'element Fortress invalide.");
            if (item.Version != 2) throw new InvalidDataException("Version d'element Fortress inconnue.");
            byte[] salt = Salt(envelope);
            byte[] wrappingKey = Derive(masterKey, salt, WrapInfo);
            try
            {
                byte[] itemKey = Open(wrappingKey, item.WrappedKey, Context("item-key", logicalPath));
                try
                {
                    if (itemKey.Length != KeyBytes) throw new CryptographicException("Cle d'element invalide.");
                    byte[] data = Open(itemKey, item.Content, Context("item-data", logicalPath));
                    if (data.Length <= MaxItemBytes) return data;
                    CryptographicOperations.ZeroMemory(data);
                    throw new InvalidDataException("Element dechiffre trop volumineux.");
                }
                finally { CryptographicOperations.ZeroMemory(itemKey); }
            }
            finally { CryptographicOperations.ZeroMemory(wrappingKey); CryptographicOperations.ZeroMemory(salt); }
        }
        finally { CryptographicOperations.ZeroMemory(serialized); }
    }

    private static EncryptedBlob Seal(byte[] key, byte[] plaintext, byte[] aad)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];
        using (var aes = new AesGcm(key, 16)) aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);
        return new EncryptedBlob
        {
            Nonce = Convert.ToBase64String(nonce),
            Ciphertext = Convert.ToBase64String(ciphertext),
            Tag = Convert.ToBase64String(tag)
        };
    }

    private static byte[] Open(byte[] key, EncryptedBlob blob, byte[] aad)
    {
        byte[] nonce = Convert.FromBase64String(blob.Nonce);
        byte[] tag = Convert.FromBase64String(blob.Tag);
        if (nonce.Length != 12 || tag.Length != 16) throw new CryptographicException("Nonce ou tag invalide.");
        byte[] ciphertext = Convert.FromBase64String(blob.Ciphertext);
        byte[] data = new byte[ciphertext.Length];
        try
        {
            using var aes = new AesGcm(key, 16);
            aes.Decrypt(nonce, ciphertext, tag, data, aad);
            return data;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(data);
            throw;
        }
        finally { CryptographicOperations.ZeroMemory(ciphertext); }
    }
}
