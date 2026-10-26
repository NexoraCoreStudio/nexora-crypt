using System.Security.Cryptography;

namespace Nexora.Crypt;

public sealed record FortressMigrationResult(string VaultPath, string PreservedV1Vault, int MigratedItems);

/// <summary>
/// Explicit, non-destructive migration. Only a previously authenticated VaultSession
/// may migrate, ideally after disconnecting every USB/IP authenticator.
/// No installation or update code is permitted to perform an implicit migration.
/// </summary>
public static class VaultFortressMigration
{
    public static FortressMigrationResult Migrate(VaultSession session, string backupDirectory)
    {
        ArgumentNullException.ThrowIfNull(session);
        return session.MigrateToFortressV2(backupDirectory);
    }

    internal static FortressMigrationResult Perform(string path, VaultEnvelope current, VaultDocument document,
        byte[] masterKey, string backupDirectory, out VaultEnvelope migrated, out VaultDocument migratedDocument)
    {
        if (current.Version != 1) throw new InvalidOperationException("Migration disponible seulement pour Vault v1.");
        if (string.IsNullOrWhiteSpace(backupDirectory)) throw new ArgumentException("Dossier de sauvegarde requis.", nameof(backupDirectory));
        backupDirectory = Path.GetFullPath(backupDirectory);
        string vaultDirectory = Path.GetDirectoryName(path)!;
        if (backupDirectory.Equals(vaultDirectory, StringComparison.OrdinalIgnoreCase))
            throw new IOException("Les sauvegardes de migration doivent etre conservees hors du dossier du coffre.");
        if (File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint))
            throw new IOException("Un coffre symbolique ou redirige ne peut pas etre migre.");

        // This lock is held through staging, backup verification and atomic replacement.
        var mutex = VaultPersistence.AcquireLock(path);
        string? staged = null;
        string? backupTemp = null;
        try
        {
            var disk = VaultPersistence.Read(path);
            if (disk.Version != 1 || disk.RevisionToken != current.RevisionToken)
                throw new IOException("Le coffre a change. Verrouillez et rouvrez Nexora avant de migrer.");
            // Authenticate the exact on-disk source against the unlocked session key.
            byte[] onDisk = VaultCrypto.DecryptPayload(masterKey, disk.Payload);
            CryptographicOperations.ZeroMemory(onDisk);

            var next = new VaultDocument
            {
                PinSalt = document.PinSalt,
                PinVerifier = document.PinVerifier,
                FailedAttempts = document.FailedAttempts,
                LockedUntilUtc = document.LockedUntilUtc,
                Audit = document.Audit.ToList(),
                Items = new Dictionary<string, string>(StringComparer.Ordinal)
            };
            byte[] salt = VaultFortressCrypto.NewSalt();
            var nextEnvelope = new VaultEnvelope
            {
                Format = current.Format,
                Version = 2,
                RevisionToken = Guid.NewGuid().ToString("N"),
                KdfSalt = Convert.ToBase64String(salt),
                AuthorizedDevices = current.AuthorizedDevices.ToList(),
                RecoverySalt = current.RecoverySalt,
                RecoveryKeySlot = current.RecoveryKeySlot
            };
            CryptographicOperations.ZeroMemory(salt);

            foreach (var item in document.Items)
            {
                byte[] plaintext = Convert.FromBase64String(item.Value);
                try { next.Items.Add(item.Key, VaultFortressCrypto.EncryptItem(nextEnvelope, masterKey, item.Key, plaintext)); }
                finally { CryptographicOperations.ZeroMemory(plaintext); }
            }
            VaultSession.AppendAudit(next, "fortress-v2-migrated");
            VaultPersistence.EncryptDocument(nextEnvelope, next, masterKey);

            // Validate staged file completely (manifest and every separately encrypted item).
            staged = Path.Combine(vaultDirectory, ".nexora-fortress-" + Guid.NewGuid().ToString("N") + ".tmp");
            VaultPersistence.WriteEnvelope(staged, nextEnvelope, overwrite: false);
            var stagedEnvelope = VaultPersistence.Read(staged);
            var stageDocument = VaultPersistence.Decode(masterKey, stagedEnvelope);
            if (stageDocument.Items.Count != document.Items.Count)
                throw new CryptographicException("La migration n'a pas conserve tous les elements.");
            foreach (var item in document.Items)
            {
                byte[] expected = Convert.FromBase64String(item.Value);
                byte[] actual = VaultFortressCrypto.DecryptItem(stagedEnvelope, masterKey, item.Key, stageDocument.Items[item.Key]);
                try
                {
                    if (!CryptographicOperations.FixedTimeEquals(expected, actual))
                        throw new CryptographicException("Echec de verification d'un element migre.");
                }
                finally { CryptographicOperations.ZeroMemory(expected); CryptographicOperations.ZeroMemory(actual); }
            }

            Directory.CreateDirectory(backupDirectory);
            string preserved = Path.Combine(backupDirectory,
                "Nexora-Before-Fortress-" + DateTimeOffset.UtcNow.ToString("yyyyMMdd-HHmmss") +
                "-" + Guid.NewGuid().ToString("N")[..8] + ".vault");
            backupTemp = preserved + ".partial";
            File.Copy(path, backupTemp, overwrite: false);
            byte[] oldHash = SHA256.HashData(File.ReadAllBytes(path));
            byte[] copyHash = SHA256.HashData(File.ReadAllBytes(backupTemp));
            if (!CryptographicOperations.FixedTimeEquals(oldHash, copyHash))
                throw new IOException("Echec de verification SHA-256 de la copie v1.");
            File.Move(backupTemp, preserved);
            backupTemp = null;

            // Single atomic filesystem rename on same volume; v1 remains in the preserved backup.
            File.Move(staged, path, overwrite: true);
            staged = null;
            migrated = nextEnvelope;
            migratedDocument = next;
            return new FortressMigrationResult(path, preserved, next.Items.Count);
        }
        finally
        {
            if (staged is not null && File.Exists(staged)) File.Delete(staged);
            if (backupTemp is not null && File.Exists(backupTemp)) File.Delete(backupTemp);
            VaultPersistence.ReleaseLock(mutex);
        }
    }
}
