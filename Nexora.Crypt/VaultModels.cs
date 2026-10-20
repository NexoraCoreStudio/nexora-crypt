using System.Text.Json.Serialization;

namespace Nexora.Crypt;

/// <summary>Encrypted vault content. This object is NEVER written to disk in plaintext.</summary>
internal sealed class VaultDocument
{
    public string PinSalt { get; set; } = "";
    public string PinVerifier { get; set; } = "";
    public int FailedAttempts { get; set; }
    public DateTimeOffset? LockedUntilUtc { get; set; }
    public Dictionary<string, string> Items { get; set; } = new(StringComparer.Ordinal);
    public List<VaultAuditEntry> Audit { get; set; } = [];
}

/// <summary>Only cryptographic headers; actual key names, settings and audit stay encrypted.</summary>
internal sealed class VaultEnvelope
{
    public string Format { get; set; } = "NEXORA-VAULT";
    public int Version { get; set; } = 1;
    public string RevisionToken { get; set; } = Guid.NewGuid().ToString("N");
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

/// <summary>Show the 256-bit recovery code to the user ONCE, then do not persist it.</summary>
public sealed record VaultCreationResult(string VaultPath, string RecoveryCode);

public sealed class VaultLockedException : InvalidOperationException
{
    public VaultLockedException(DateTimeOffset lockedUntilUtc)
        : base($"Nexora est bloque jusqu'au {lockedUntilUtc:O}.")
    {
        LockedUntilUtc = lockedUntilUtc;
    }

    public DateTimeOffset LockedUntilUtc { get; }
}

public sealed class InvalidVaultPinException : UnauthorizedAccessException
{
    public InvalidVaultPinException(DateTimeOffset lockedUntilUtc)
        : base($"Code PIN incorrect. Prochaine tentative a partir du {lockedUntilUtc:O}.")
    {
        LockedUntilUtc = lockedUntilUtc;
    }

    public DateTimeOffset LockedUntilUtc { get; }
}
