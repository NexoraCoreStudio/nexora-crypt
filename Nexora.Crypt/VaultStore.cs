using System.Security.Cryptography;

namespace Nexora.Crypt;

/// <summary>
/// Portable AES-GCM vault. DPAPI restricts the local account; a 256-bit recovery code
/// authorizes use on another Windows profile after PIN verification. The short PIN and
/// lockout are APPLICATION-level controls, not TPM-backed authentication.
/// Fortress v2 is opt-in and NEVER automatically migrates a user's vault.
/// </summary>
public static class VaultStore
{
    public static string DefaultVaultPath => Path.Combine(AppContext.BaseDirectory, "Nexora.vault");

    /// <summary>Create a backward-compatible v1 vault. Store recovery code offline.</summary>
    public static VaultCreationResult Create(string vaultPath, string initialPin)
    {
        string path = VaultPersistence.AbsolutePath(vaultPath);
        var @lock = VaultPersistence.AcquireLock(path);
        byte[] masterKey = VaultCrypto.CreateMasterKey();
        try
        {
            if (File.Exists(path)) throw new IOException("Le coffre existe deja. Sa creation ne peut pas l'ecraser.");
            string recoveryCode = VaultCrypto.CreateRecoveryCode();
            byte[] recoverySalt = RandomNumberGenerator.GetBytes(32);
            byte[] recoveryKey = VaultCrypto.RecoveryEncryptionKey(recoveryCode, recoverySalt);
            try
            {
                var document = new VaultDocument();
                VaultCrypto.SetPin(document, initialPin);
                document.Audit.Add(new VaultAuditEntry(DateTimeOffset.UtcNow, "vault-created"));
                var envelope = new VaultEnvelope
                {
                    AuthorizedDevices =
                    [
                        new DeviceKeySlot
                        {
                            DpapiCiphertext = Convert.ToBase64String(VaultCrypto.ProtectForThisWindowsAccount(masterKey))
                        }
                    ],
                    RecoverySalt = Convert.ToBase64String(recoverySalt),
                    RecoveryKeySlot = VaultCrypto.WrapForRecovery(recoveryKey, masterKey)
                };
                VaultPersistence.EncryptDocument(envelope, document, masterKey);
                VaultPersistence.WriteEnvelope(path, envelope, overwrite: false);
                AuthorizedProfileMarker.TryRemember(envelope);
                return new VaultCreationResult(path, recoveryCode);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(recoveryKey);
                CryptographicOperations.ZeroMemory(recoverySalt);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(masterKey);
            VaultPersistence.ReleaseLock(@lock);
        }
    }

    public static int ReadVaultFormatVersion(string vaultPath) =>
        VaultPersistence.Read(VaultPersistence.AbsolutePath(vaultPath)).Version;

    /// <summary>Actual DPAPI key slot + authenticated payload, not a local marker.</summary>
    public static bool IsAuthorizedOnThisWindowsProfile(string vaultPath)
    {
        if (!OperatingSystem.IsWindows()) return false;
        var envelope = VaultPersistence.Read(VaultPersistence.AbsolutePath(vaultPath));
        bool localHintExists = AuthorizedProfileMarker.IsKnown(envelope);
        foreach (var slot in envelope.AuthorizedDevices)
        {
            byte[]? candidate = null;
            try
            {
                candidate = VaultCrypto.UnprotectForThisWindowsAccount(Convert.FromBase64String(slot.DpapiCiphertext));
                if (candidate.Length != 32) continue;
                VaultPersistence.VerifyPayload(candidate, envelope);
                if (!localHintExists) AuthorizedProfileMarker.TryRemember(envelope);
                return true;
            }
            catch (Exception ex) when (ex is CryptographicException or FormatException)
            {
                // Different profile or tampered key slot.
            }
            finally
            {
                if (candidate is not null) CryptographicOperations.ZeroMemory(candidate);
            }
        }
        return false;
    }

    public static VaultSession OpenOnAuthorizedComputer(string vaultPath, string pin)
    {
        string path = VaultPersistence.AbsolutePath(vaultPath);
        var envelope = VaultPersistence.Read(path);
        byte[]? masterKey = null;
        foreach (var slot in envelope.AuthorizedDevices)
        {
            try
            {
                masterKey = VaultCrypto.UnprotectForThisWindowsAccount(Convert.FromBase64String(slot.DpapiCiphertext));
                if (masterKey.Length != 32)
                {
                    CryptographicOperations.ZeroMemory(masterKey);
                    masterKey = null;
                    continue;
                }
                break;
            }
            catch (CryptographicException) { }
        }
        if (masterKey is null)
            throw new UnauthorizedAccessException("Ce PC/compte Windows n'est pas autorise. Code de recuperation necessaire.");
        var session = Authenticate(path, envelope, masterKey, pin);
        AuthorizedProfileMarker.TryRemember(envelope);
        return session;
    }

    public static VaultSession OpenWithRecoveryCode(string vaultPath, string pin, string recoveryCode)
    {
        string path = VaultPersistence.AbsolutePath(vaultPath);
        var envelope = VaultPersistence.Read(path);
        byte[] salt = Convert.FromBase64String(envelope.RecoverySalt);
        byte[] recoveryKey = VaultCrypto.RecoveryEncryptionKey(recoveryCode, salt);
        byte[] masterKey;
        try { masterKey = VaultCrypto.UnwrapForRecovery(recoveryKey, envelope.RecoveryKeySlot); }
        catch (CryptographicException ex)
        {
            throw new UnauthorizedAccessException("Code de recuperation invalide ou coffre modifie.", ex);
        }
        finally { CryptographicOperations.ZeroMemory(recoveryKey); CryptographicOperations.ZeroMemory(salt); }
        if (masterKey.Length != 32)
        {
            CryptographicOperations.ZeroMemory(masterKey);
            throw new CryptographicException("Cle maitresse invalide.");
        }
        return Authenticate(path, envelope, masterKey, pin);
    }

    private static VaultSession Authenticate(string path, VaultEnvelope envelope, byte[] masterKey, string pin)
    {
        try
        {
            var doc = VaultPersistence.Decode(masterKey, envelope);
            var now = DateTimeOffset.UtcNow;
            if (doc.LockedUntilUtc is { } blocked && now < blocked)
                throw new VaultLockedException(blocked);
            if (!VaultCrypto.CheckPin(doc, pin))
            {
                doc.FailedAttempts = Math.Min(doc.FailedAttempts + 1, 100);
                doc.LockedUntilUtc = VaultCrypto.NextLockoutUtc(doc.FailedAttempts);
                VaultSession.AppendAudit(doc, "pin-rejected");
                VaultPersistence.SaveExisting(path, envelope, doc, masterKey);
                throw new InvalidVaultPinException(doc.LockedUntilUtc.Value);
            }
            doc.FailedAttempts = 0;
            doc.LockedUntilUtc = null;
            VaultSession.AppendAudit(doc, "vault-opened");
            VaultPersistence.SaveExisting(path, envelope, doc, masterKey);
            return new VaultSession(path, envelope, doc, masterKey);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(masterKey);
            throw;
        }
    }
}
