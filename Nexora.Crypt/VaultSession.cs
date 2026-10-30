using System.Security.Cryptography;
using System.Text.Json;

namespace Nexora.Crypt;

/// <summary>
/// Authenticated vault session. The storage API remains identical for FIDO2 consumers.
/// V1 uses encrypted outer payload. Fortress v2 additionally encrypts each item using
/// its own random data key. Callers must synchronize access to a session.
/// </summary>
public sealed class VaultSession : IDisposable
{
    private readonly string _path;
    private VaultEnvelope _envelope;
    private VaultDocument _document;
    private readonly byte[] _masterKey;
    private bool _disposed;
    private byte[] _committedEnvelope;

    internal VaultSession(string path, VaultEnvelope envelope, VaultDocument document, byte[] masterKey)
    {
        _path = path;
        _envelope = envelope;
        _document = document;
        _masterKey = masterKey;
        _committedEnvelope = JsonSerializer.SerializeToUtf8Bytes(envelope);
    }

    public bool IsFortressV2 { get { EnsureOpen(); return _envelope.Version == 2; } }

    public IReadOnlyList<string> ListPaths()
    {
        EnsureOpen();
        return _document.Items.Keys.OrderBy(s => s, StringComparer.Ordinal).ToArray();
    }

    public IReadOnlyList<VaultAuditEntry> GetAudit()
    {
        EnsureOpen();
        return _document.Audit.ToArray();
    }

    public byte[]? ReadFile(string logicalPath)
    {
        EnsureOpen();
        ValidateLogicalPath(logicalPath);
        if (!_document.Items.TryGetValue(logicalPath, out string? encoded)) return null;
        return _envelope.Version switch
        {
            1 => Convert.FromBase64String(encoded),
            2 => VaultFortressCrypto.DecryptItem(_envelope, _masterKey, logicalPath, encoded),
            _ => throw new InvalidDataException("Version du coffre inconnue.")
        };
    }

    public void WriteFile(string logicalPath, byte[] contents)
    {
        EnsureOpen();
        ValidateLogicalPath(logicalPath);
        ArgumentNullException.ThrowIfNull(contents);
        if (contents.Length > 16 * 1024 * 1024)
            throw new ArgumentOutOfRangeException(nameof(contents), "Fichier limite a 16 Mo.");
        if (!_document.Items.ContainsKey(logicalPath) && _document.Items.Count >= 10_000)
            throw new InvalidOperationException("Nombre maximal de fichiers atteint.");
        _document.Items[logicalPath] = _envelope.Version switch
        {
            1 => Convert.ToBase64String(contents),
            2 => VaultFortressCrypto.EncryptItem(_envelope, _masterKey, logicalPath, contents),
            _ => throw new InvalidDataException("Version du coffre inconnue.")
        };
        AppendAudit(_document, "vault-entry-written");
        Save();
    }

    public bool DeleteFile(string logicalPath)
    {
        EnsureOpen();
        ValidateLogicalPath(logicalPath);
        if (!_document.Items.Remove(logicalPath)) return false;
        AppendAudit(_document, "vault-entry-removed");
        Save();
        return true;
    }

    /// <summary>
    /// Explicit opt-in, with verified immutable V1 backup. Call only when USB/IP has been
    /// detached and the GUI's shared VaultAccessController.SyncRoot is held.
    /// The session remains open and switches to V2 only after a verified atomic commit.
    /// </summary>
    internal FortressMigrationResult MigrateToFortressV2(string backupDirectory)
    {
        EnsureOpen();
        if (_envelope.Version != 1) throw new InvalidOperationException("Ce coffre utilise deja Fortress v2.");
        var result = VaultFortressMigration.Perform(_path, _envelope, _document, _masterKey,
            backupDirectory, out var migratedEnvelope, out var migratedDocument);
        _envelope = migratedEnvelope;
        _document = migratedDocument;
        _committedEnvelope = JsonSerializer.SerializeToUtf8Bytes(_envelope);
        return result;
    }

    /// <summary>Explicitly register the CURRENT Windows user/profile as an authorized endpoint.</summary>
    public void AuthorizeThisComputer()
    {
        EnsureOpen();
        if (_envelope.AuthorizedDevices.Count >= 16)
            throw new InvalidOperationException("Maximum de 16 appareils autorises atteint.");
        byte[] wrapped = VaultCrypto.ProtectForThisWindowsAccount(_masterKey);
        _envelope.AuthorizedDevices.Add(new DeviceKeySlot { DpapiCiphertext = Convert.ToBase64String(wrapped) });
        AppendAudit(_document, "windows-profile-authorized");
        Save();
        AuthorizedProfileMarker.TryRemember(_envelope);
    }

    /// <summary>Enforce the same persistent lockout when approving a FIDO2 operation.</summary>
    public bool VerifyPin(string pin, out DateTimeOffset blockedUntil)
    {
        EnsureOpen();
        if (_document.LockedUntilUtc is { } locked && DateTimeOffset.UtcNow < locked)
        {
            blockedUntil = locked;
            return false;
        }
        if (VaultCrypto.CheckPin(_document, pin))
        {
            _document.FailedAttempts = 0;
            _document.LockedUntilUtc = null;
            blockedUntil = DateTimeOffset.MinValue;
            Save();
            return true;
        }
        _document.FailedAttempts = Math.Min(_document.FailedAttempts + 1, 100);
        _document.LockedUntilUtc = VaultCrypto.NextLockoutUtc(_document.FailedAttempts);
        blockedUntil = _document.LockedUntilUtc.Value;
        AppendAudit(_document, "pin-rejected");
        Save();
        return false;
    }

    /// <summary>Allowlisted, non-secret operational events inside encrypted payload.</summary>
    public void RecordAudit(string eventType)
    {
        EnsureOpen();
        if (eventType.Length is < 1 or > 48 || eventType.Any(c => !(c is >= 'a' and <= 'z' or >= '0' and <= '9' or '-')))
            throw new ArgumentException("Invalid audit event type.", nameof(eventType));
        AppendAudit(_document, eventType);
        Save();
    }

    public void ChangePin(string oldPin, string newPin)
    {
        EnsureOpen();
        if (!VerifyPin(oldPin, out var blocked))
            throw new InvalidVaultPinException(blocked);
        VaultCrypto.SetPin(_document, newPin);
        AppendAudit(_document, "pin-changed");
        Save();
    }

    /// <summary>Record an event type without inserting PIN values, credentials or user-supplied text.</summary>
    public void RecordSecurityEvent(VaultSecurityEvent eventType)
    {
        EnsureOpen();
        AppendAudit(_document, eventType switch
        {
            VaultSecurityEvent.SuspiciousInput => "suspicious-input",
            VaultSecurityEvent.UsbAttachRejected => "usb-attach-rejected",
            VaultSecurityEvent.PinPromptCancelled => "pin-prompt-cancelled",
            VaultSecurityEvent.IntegrityAlert => "integrity-alert",
            VaultSecurityEvent.ManualLock => "manual-lock",
            _ => throw new ArgumentOutOfRangeException(nameof(eventType))
        });
        Save();
    }

    private void Save()
    {
        try
        {
            VaultPersistence.SaveExisting(_path, _envelope, _document, _masterKey);
            _committedEnvelope = JsonSerializer.SerializeToUtf8Bytes(_envelope);
        }
        catch
        {
            // Restore the last authenticated committed document, not the mutated state.
            _envelope = JsonSerializer.Deserialize<VaultEnvelope>(_committedEnvelope)!;
            _document = VaultPersistence.Decode(_masterKey, _envelope);
            throw;
        }
    }

    internal static void AppendAudit(VaultDocument document, string eventType)
    {
        document.Audit.Add(new VaultAuditEntry(DateTimeOffset.UtcNow, eventType));
        if (document.Audit.Count > 500) document.Audit.RemoveRange(0, document.Audit.Count - 500);
    }

    private static void ValidateLogicalPath(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (path.Length > 512 || path.StartsWith('/') || path.EndsWith('/') ||
            path.Contains('\\') || path.Contains(':') || path.Contains("//", StringComparison.Ordinal) ||
            path.Split('/').Any(s => s is "." or ".." or "" || s.Any(char.IsControl)))
            throw new ArgumentException("Chemin interne invalide.", nameof(path));
    }

    private void EnsureOpen()
    {
        if (_disposed) throw new ObjectDisposedException(nameof(VaultSession));
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        CryptographicOperations.ZeroMemory(_masterKey);
        GC.SuppressFinalize(this);
    }
}

public enum VaultSecurityEvent
{
    SuspiciousInput,
    UsbAttachRejected,
    PinPromptCancelled,
    IntegrityAlert,
    ManualLock
}
