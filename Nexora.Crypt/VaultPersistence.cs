using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Nexora.Crypt;

internal static class VaultPersistence
{
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = false };
    private const int MaxEncryptedFileBytes = 64 * 1024 * 1024;
    internal static string AbsolutePath(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        return Path.GetFullPath(path);
    }

    internal static Mutex AcquireLock(string fullPath)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Nexora Crypt necessite Windows.");
        var fingerprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(fullPath.ToUpperInvariant())));
        var mutex = new Mutex(false, @"Local\Nexora.Crypt." + fingerprint);
        try
        {
            try
            {
                if (!mutex.WaitOne(0)) throw new IOException("Ce coffre est deja ouvert par un autre processus.");
            }
            catch (AbandonedMutexException)
            {
                // Previous process crashed: OS has released the lock.
            }
            return mutex;
        }
        catch
        {
            mutex.Dispose();
            throw;
        }
    }

    internal static void ReleaseLock(Mutex mutex)
    {
        try { mutex.ReleaseMutex(); }
        finally { mutex.Dispose(); }
    }

    internal static VaultEnvelope Read(string path)
    {
        if (!File.Exists(path)) throw new FileNotFoundException("Coffre Nexora introuvable.", path);
        var info = new FileInfo(path);
        if (info.Length > MaxEncryptedFileBytes) throw new InvalidDataException("Coffre trop volumineux.");
        var envelope = JsonSerializer.Deserialize<VaultEnvelope>(File.ReadAllBytes(path), Options)
            ?? throw new InvalidDataException("Contenu de coffre invalide.");
        if (envelope.Format != "NEXORA-VAULT" || envelope.Version != 1 || string.IsNullOrWhiteSpace(envelope.RevisionToken))
            throw new InvalidDataException("Version de coffre non prise en charge.");
        return envelope;
    }

    internal static VaultDocument Decode(byte[] masterKey, VaultEnvelope envelope)
    {
        byte[] serialized = VaultCrypto.DecryptPayload(masterKey, envelope.Payload);
        try
        {
            return JsonSerializer.Deserialize<VaultDocument>(serialized, Options)
                ?? throw new InvalidDataException("Donnees du coffre invalides.");
        }
        finally { CryptographicOperations.ZeroMemory(serialized); }
    }

    internal static void EncryptDocument(VaultEnvelope envelope, VaultDocument document, byte[] masterKey)
    {
        byte[] plaintext = JsonSerializer.SerializeToUtf8Bytes(document, Options);
        try { envelope.Payload = VaultCrypto.EncryptPayload(masterKey, plaintext); }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }

    internal static void SaveExisting(string path, VaultEnvelope envelope, VaultDocument document, byte[] masterKey)
    {
        var mutationLock = AcquireLock(path);
        try
        {
            string current = Read(path).RevisionToken;
            if (current != envelope.RevisionToken)
                throw new IOException("Le coffre a ete modifie par un autre processus. Fermez-le puis rouvrez-le.");
            envelope.RevisionToken = Guid.NewGuid().ToString("N");
            EncryptDocument(envelope, document, masterKey);
            WriteEnvelope(path, envelope, overwrite: true);
        }
        finally { ReleaseLock(mutationLock); }
    }

    internal static void WriteEnvelope(string path, VaultEnvelope envelope, bool overwrite)
    {
        byte[] data = JsonSerializer.SerializeToUtf8Bytes(envelope, Options);
        if (data.Length > MaxEncryptedFileBytes) throw new InvalidDataException("Le coffre a depasse sa taille maximale.");
        string dir = Path.GetDirectoryName(path) ?? throw new InvalidOperationException("Dossier introuvable.");
        Directory.CreateDirectory(dir);
        string tempPath = path + ".new." + Guid.NewGuid().ToString("N");
        try
        {
            using (var fs = new FileStream(tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                4096, FileOptions.WriteThrough))
            {
                fs.Write(data);
                fs.Flush(flushToDisk: true);
            }
            File.Move(tempPath, path, overwrite);
        }
        finally { if (File.Exists(tempPath)) File.Delete(tempPath); }
    }
}
