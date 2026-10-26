using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Nexora.Crypt;

/// <summary>
/// Password-encrypted, portable copy of the ALREADY ENCRYPTED Nexora.vault file.
/// It never exports an unwrapped FIDO key, the vault master key or a recovery code.
/// On another Windows profile the original 256-bit recovery code and vault PIN are still required.
/// </summary>
public static class VaultBackupService
{
    private const string FormatName = "NEXORA-VAULT-BACKUP";
    private const int FormatVersion = 1;
    private const int KdfIterations = 600_000;
    private const int MaximumVaultBytes = 64 * 1024 * 1024;
    private const long MaximumBackupBytes = 96L * 1024 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new() { MaxDepth = 16 };

    public sealed record BackupInformation(DateTimeOffset CreatedUtc, long VaultBytes);
    public sealed record RestoreResult(string VaultPath, string? PreviousVaultCopy);

    private sealed class BackupEnvelope
    {
        public string Format { get; set; } = FormatName;
        public int Version { get; set; } = FormatVersion;
        public string CreatedUtc { get; set; } = string.Empty;
        public string Kdf { get; set; } = "PBKDF2-SHA256";
        public int Iterations { get; set; } = KdfIterations;
        public string Salt { get; set; } = string.Empty;
        public string Nonce { get; set; } = string.Empty;
        public string Ciphertext { get; set; } = string.Empty;
        public string Tag { get; set; } = string.Empty;
    }

    /// <summary>Reads only public metadata; password authentication takes place when decrypting.</summary>
    public static BackupInformation InspectBackup(string backupPath)
    {
        var envelope = ReadBackup(backupPath);
        return new BackupInformation(ParseDate(envelope.CreatedUtc),
            Convert.FromBase64String(envelope.Ciphertext).LongLength);
    }

    /// <summary>
    /// Takes a consistent snapshot under the vault mutation mutex, encrypts it again using a
    /// separate backup password, verifies that the staged backup decrypts, then atomically publishes it.
    /// Existing backup files are never overwritten.
    /// </summary>
    public static BackupInformation CreateBackup(string vaultPath, string backupPath, string password)
    {
        ValidatePassword(password);
        string source = VaultPersistence.AbsolutePath(vaultPath);
        string target = VaultPersistence.AbsolutePath(backupPath);
        if (SamePath(source, target)) throw new IOException("Destination identique au coffre actif.");
        if (File.Exists(target)) throw new IOException("La sauvegarde existe deja. Choisissez un autre nom.");
        EnsureRegularFile(source);

        byte[] vaultBytes;
        Mutex snapshotLock = VaultPersistence.AcquireLock(source);
        {
            try
            {
                VaultPersistence.Read(source); // Version and size constraints.
                vaultBytes = File.ReadAllBytes(source);
                ValidateVaultBytes(vaultBytes);
            }
            finally { VaultPersistence.ReleaseLock(snapshotLock); }
        }
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] key = DeriveKey(password, salt);
        byte[] cipher = new byte[vaultBytes.Length];
        byte[] tag = new byte[16];
        string created = DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture);
        string temporary = target + ".partial-" + Guid.NewGuid().ToString("N");
        try
        {
            using (var aes = new AesGcm(key, 16))
                aes.Encrypt(nonce, vaultBytes, cipher, tag, AssociatedData(created));

            var envelope = new BackupEnvelope
            {
                CreatedUtc = created,
                Salt = Convert.ToBase64String(salt),
                Nonce = Convert.ToBase64String(nonce),
                Ciphertext = Convert.ToBase64String(cipher),
                Tag = Convert.ToBase64String(tag)
            };
            string directory = Path.GetDirectoryName(target)
                ?? throw new IOException("Dossier de sauvegarde invalide.");
            Directory.CreateDirectory(directory);
            byte[] archive = JsonSerializer.SerializeToUtf8Bytes(envelope, JsonOptions);
            try
            {
                if (archive.LongLength > MaximumBackupBytes)
                    throw new InvalidDataException("Sauvegarde trop volumineuse.");
                WriteNewFile(temporary, archive);
            }
            finally { CryptographicOperations.ZeroMemory(archive); }

            // Verify both AES-GCM authentication and exact snapshot bytes before publication.
            byte[] test = DecryptBackup(ReadBackup(temporary), password);
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(vaultBytes), SHA256.HashData(test)))
                    throw new CryptographicException("La verification de la sauvegarde a echoue.");
            }
            finally { CryptographicOperations.ZeroMemory(test); }

            File.Move(temporary, target, overwrite: false);
            return new BackupInformation(ParseDate(created), vaultBytes.LongLength);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(vaultBytes);
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(cipher);
            CryptographicOperations.ZeroMemory(salt);
            CryptographicOperations.ZeroMemory(tag);
            CryptographicOperations.ZeroMemory(nonce);
            try { if (File.Exists(temporary)) File.Delete(temporary); } catch (IOException) { }
        }
    }

    /// <summary>Authenticates the archive before any active key is disconnected or vault is replaced.</summary>
    public static BackupInformation VerifyBackupPassword(string backupPath, string password)
    {
        ValidatePassword(password);
        BackupEnvelope envelope = ReadBackup(backupPath);
        byte[] verified = DecryptBackup(envelope, password);
        try { return new BackupInformation(ParseDate(envelope.CreatedUtc), verified.LongLength); }
        finally { CryptographicOperations.ZeroMemory(verified); }
    }

    /// <summary>
    /// Restores the original encrypted vault, without bypassing its PIN or DPAPI/recovery protection.
    /// A complete SHA-256-verified copy of the old vault is made BEFORE replacement.
    /// The caller must disconnect FIDO/USB devices, dispose the active vault session,
    /// and restart Nexora after this operation; this method does not do either action.
    /// </summary>
    public static RestoreResult RestoreBackup(string backupPath, string vaultPath, string password,
        string rollbackDirectory)
    {
        ValidatePassword(password);
        string backup = VaultPersistence.AbsolutePath(backupPath);
        string target = VaultPersistence.AbsolutePath(vaultPath);
        string rollbackRoot = VaultPersistence.AbsolutePath(rollbackDirectory);
        if (SamePath(backup, target)) throw new IOException("La sauvegarde ne peut pas etre le coffre actif.");
        byte[] plaintext = DecryptBackup(ReadBackup(backup), password);
        string? oldVaultBackup = null;
        string staging = Path.Combine(Path.GetDirectoryName(target)!,
            ".Nexora-vault-restore-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            ValidateVaultBytes(plaintext);
            string targetFolder = Path.GetDirectoryName(target)
                ?? throw new IOException("Dossier du coffre invalide.");
            Directory.CreateDirectory(targetFolder);
            Mutex restoreLock = VaultPersistence.AcquireLock(target);
            {
                try
                {
                    if (File.Exists(target))
                    {
                        EnsureRegularFile(target);
                        if (SamePath(rollbackRoot, targetFolder))
                            throw new IOException("Le dossier de sauvegarde de secours doit etre separe du coffre.");
                        Directory.CreateDirectory(rollbackRoot);
                        oldVaultBackup = Path.Combine(rollbackRoot, "Nexora-before-restore-" +
                            DateTimeOffset.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture) + "-" +
                            Guid.NewGuid().ToString("N")[..8] + ".vault");
                        File.Copy(target, oldVaultBackup, overwrite: false);
                        byte[] sourceHash;
                        byte[] copyHash;
                        using (var source = File.OpenRead(target)) sourceHash = SHA256.HashData(source);
                        using (var copy = File.OpenRead(oldVaultBackup)) copyHash = SHA256.HashData(copy);
                        if (!CryptographicOperations.FixedTimeEquals(sourceHash, copyHash))
                        {
                            File.Delete(oldVaultBackup);
                            oldVaultBackup = null;
                            throw new IOException("Copie de secours non verifiee. Aucune restauration effectuee.");
                        }
                    }

                    WriteNewFile(staging, plaintext);
                    VaultPersistence.Read(staging); // Check the completed on-disk candidate.
                    // Atomic same-directory replacement: the original exists until the final move.
                    File.Move(staging, target, overwrite: true);
                    return new RestoreResult(target, oldVaultBackup);
                }
                finally { VaultPersistence.ReleaseLock(restoreLock); }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            try { if (File.Exists(staging)) File.Delete(staging); } catch (IOException) { }
        }
    }

    private static byte[] DecryptBackup(BackupEnvelope envelope, string password)
    {
        byte[] salt = Convert.FromBase64String(envelope.Salt);
        byte[] nonce = Convert.FromBase64String(envelope.Nonce);
        byte[] tag = Convert.FromBase64String(envelope.Tag);
        byte[] cipher = Convert.FromBase64String(envelope.Ciphertext);
        byte[] key = DeriveKey(password, salt);
        byte[] result = new byte[cipher.Length];
        try
        {
            using (var aes = new AesGcm(key, 16))
                aes.Decrypt(nonce, cipher, tag, result, AssociatedData(envelope.CreatedUtc));
            ValidateVaultBytes(result);
            return result;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(result);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(salt);
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(tag);
            CryptographicOperations.ZeroMemory(cipher);
        }
    }

    private static BackupEnvelope ReadBackup(string backupPath)
    {
        string path = VaultPersistence.AbsolutePath(backupPath);
        EnsureRegularFile(path);
        var size = new FileInfo(path).Length;
        if (size is <= 0 or > MaximumBackupBytes)
            throw new InvalidDataException("Taille de sauvegarde non prise en charge.");
        var data = JsonSerializer.Deserialize<BackupEnvelope>(File.ReadAllBytes(path), JsonOptions)
            ?? throw new InvalidDataException("Format de sauvegarde invalide.");
        if (data.Format != FormatName || data.Version != FormatVersion || data.Kdf != "PBKDF2-SHA256" ||
            data.Iterations != KdfIterations)
            throw new InvalidDataException("Format ou parametres de chiffrement non reconnus.");
        ParseDate(data.CreatedUtc);
        if (Convert.FromBase64String(data.Salt).Length != 16 ||
            Convert.FromBase64String(data.Nonce).Length != 12 ||
            Convert.FromBase64String(data.Tag).Length != 16 ||
            Convert.FromBase64String(data.Ciphertext).LongLength is <= 0 or > MaximumVaultBytes)
            throw new InvalidDataException("Sauvegarde incomplète ou endommagee.");
        return data;
    }

    private static void ValidateVaultBytes(byte[] bytes)
    {
        if (bytes.Length is <= 0 or > MaximumVaultBytes)
            throw new InvalidDataException("Taille du coffre invalide.");
        var vault = JsonSerializer.Deserialize<VaultEnvelope>(bytes, JsonOptions)
            ?? throw new InvalidDataException("Coffre absent de la sauvegarde.");
        if (vault.Format != "NEXORA-VAULT" || vault.Version is not (1 or 2) ||
            (vault.Version == 2 && (string.IsNullOrWhiteSpace(vault.KdfSalt) ||
                Convert.FromBase64String(vault.KdfSalt).Length != 32)) ||
            string.IsNullOrWhiteSpace(vault.RevisionToken) ||
            vault.AuthorizedDevices is null || vault.AuthorizedDevices.Count is < 1 or > 16 ||
            vault.RecoveryKeySlot is null || vault.Payload is null ||
            Convert.FromBase64String(vault.RecoverySalt).Length != 32 ||
            Convert.FromBase64String(vault.RecoveryKeySlot.Nonce).Length != 12 ||
            Convert.FromBase64String(vault.RecoveryKeySlot.Tag).Length != 16 ||
            Convert.FromBase64String(vault.RecoveryKeySlot.Ciphertext).Length != 32 ||
            Convert.FromBase64String(vault.Payload.Nonce).Length != 12 ||
            Convert.FromBase64String(vault.Payload.Tag).Length != 16 ||
            Convert.FromBase64String(vault.Payload.Ciphertext).Length == 0 ||
            vault.AuthorizedDevices.Any(slot => slot is null || string.IsNullOrWhiteSpace(slot.DpapiCiphertext) ||
                Convert.FromBase64String(slot.DpapiCiphertext).Length is < 16 or > 16384))
            throw new InvalidDataException("Le contenu chiffre du coffre n'est pas valide.");
    }

    private static byte[] AssociatedData(string timestamp) =>
        Encoding.UTF8.GetBytes("Nexora.Crypt/VaultBackup/v1\n" + timestamp);

    private static DateTimeOffset ParseDate(string text)
    {
        if (!DateTimeOffset.TryParseExact(text, "O", CultureInfo.InvariantCulture,
            DateTimeStyles.RoundtripKind, out var date))
            throw new InvalidDataException("Date de sauvegarde invalide.");
        return date;
    }

    private static byte[] DeriveKey(string password, byte[] salt) =>
        Rfc2898DeriveBytes.Pbkdf2(password, salt, KdfIterations, HashAlgorithmName.SHA256, 32);

    private static void ValidatePassword(string password)
    {
        ArgumentNullException.ThrowIfNull(password);
        if (password.Length is < 12 or > 256 || string.IsNullOrWhiteSpace(password))
            throw new ArgumentException("Le mot de passe de sauvegarde doit compter entre 12 et 256 caracteres.");
    }

    private static bool SamePath(string first, string second) =>
        Path.TrimEndingDirectorySeparator(first).Equals(Path.TrimEndingDirectorySeparator(second),
            StringComparison.OrdinalIgnoreCase);

    private static void EnsureRegularFile(string path)
    {
        if (!File.Exists(path)) throw new FileNotFoundException("Fichier introuvable.", path);
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Les liens symboliques ne sont pas acceptes pour les coffres et sauvegardes.");
    }

    private static void WriteNewFile(string path, byte[] data)
    {
        using var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None,
            bufferSize: 64 * 1024, options: FileOptions.WriteThrough);
        file.Write(data);
        file.Flush(flushToDisk: true);
    }
}
