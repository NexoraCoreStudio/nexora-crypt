using System.Security.Cryptography;

namespace Nexora.Crypt;

/// <summary>Use from one caller at a time. Disposing clears the master key as far as managed memory permits.</summary>
public sealed class VaultSession : IDisposable
{
    private readonly string _path;
    private readonly VaultEnvelope _envelope;
    private readonly VaultDocument _document;
    private readonly byte[] _masterKey;
    private bool _disposed;

    internal VaultSession(string path, VaultEnvelope envelope, VaultDocument document, byte[] masterKey)
    {
        _path = path;
        _envelope = envelope;
        _document = document;
        _masterKey = masterKey;
    }

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
        return _document.Items.TryGetValue(logicalPath, out string? encoded)
            ? Convert.FromBase64String(encoded)
            : null;
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
        _document.Items[logicalPath] = Convert.ToBase64String(contents);
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

    private void Save() => VaultPersistence.SaveExisting(_path, _envelope, _document, _masterKey);

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

/// <summary>Allowlisted audit types: no arbitrary user data or secret content.</summary>
public enum VaultSecurityEvent
{
    SuspiciousInput,
    UsbAttachRejected,
    PinPromptCancelled,
    IntegrityAlert,
    ManualLock
}
