namespace Nexora.Crypt;

/// <summary>Encrypted vault content. Never persisted in plaintext.</summary>
internal sealed class VaultDocument
{
    public string PinSalt { get; set; } = "";
    public string PinVerifier { get; set; } = "";
    public int FailedAttempts { get; set; }
    public DateTimeOffset? LockedUntilUtc { get; set; }
    public Dictionary<string, string> Items { get; set; } = new(StringComparer.Ordinal);
    public List<VaultAuditEntry> Audit { get; set; } = [];
}

/// <summary>
/// V1: single encrypted document. V2: authenticated HKDF-separated encrypted manifest
/// containing individually encrypted key-wrapped items. Header values are not secret.
/// </summary>
internal sealed class VaultEnvelope
{
    public string Format { get; set; } = "NEXORA-VAULT";
    public int Version { get; set; } = 1;
    public string RevisionToken { get; set; } = Guid.NewGuid().ToString("N");
    public string KdfSalt { get; set; } = ""; // v2 only; 32 random bytes, base64 encoded
    public List<DeviceKeySlot> AuthorizedDevices { get; set; } = [];
    public string RecoverySalt { get; set; } = "";
    public EncryptedBlob RecoveryKeySlot { get; set; } = new();
    public EncryptedBlob Payload { get; set; } = new();
}

internal sealed class DeviceKeySlot
{
    public string SlotId { get; set; } = Guid.NewGuid().ToString("N");
    public string DpapiCiphertext { get; set; } = "";
}

internal sealed class EncryptedBlob
{
    public string Nonce { get; set; } = "";
    public string Ciphertext { get; set; } = "";
    public string Tag { get; set; } = "";
}

public sealed record VaultAuditEntry(DateTimeOffset WhenUtc, string EventType);
public sealed record VaultCreationResult(string VaultPath, string RecoveryCode);

public sealed class VaultLockedException : InvalidOperationException
{
    public VaultLockedException(DateTimeOffset lockedUntilUtc)
        : base($"Nexora est bloque jusqu'au {lockedUntilUtc:O}.") => LockedUntilUtc = lockedUntilUtc;
    public DateTimeOffset LockedUntilUtc { get; }
}

public sealed class InvalidVaultPinException : UnauthorizedAccessException
{
    public InvalidVaultPinException(DateTimeOffset lockedUntilUtc)
        : base($"Code PIN incorrect. Prochaine tentative a partir du {lockedUntilUtc:O}.") => LockedUntilUtc = lockedUntilUtc;
    public DateTimeOffset LockedUntilUtc { get; }
}
