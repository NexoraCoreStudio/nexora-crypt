using System.Security.Cryptography;
using Nexora.Crypt;

if (!OperatingSystem.IsWindows())
{
    Console.WriteLine("Ce projet teste Windows DPAPI : lancer les tests sur Windows.");
    return 1;
}

string tempDir = Path.Combine(Path.GetTempPath(), "Nexora-Crypt-Tests-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(tempDir);
try
{
    Console.WriteLine("[TEST] Creation, code de recuperation et donnees dans un unique coffre");
    string path = Path.Combine(tempDir, "Nexora.vault");
    VaultCreationResult created = VaultStore.Create(path, "1234");
    Require(created.RecoveryCode.Replace("-", "").Length == 64, "Code de 256 bits attendu");
    Require(File.Exists(path), "Le coffre doit exister");
    Require(VaultStore.IsAuthorizedOnThisWindowsProfile(path), "Profil Windows initial non reconnu");
    Require(!File.Exists(Path.Combine(tempDir, "ui-pin.json")), "PIN ne doit pas etre dans un JSON externe");

    using (var session = VaultStore.OpenOnAuthorizedComputer(path, "1234"))
    {
        session.WriteFile("keys/clef1/private.key", new byte[] { 23, 42, 99 });
        session.WriteFile("config/app.json", "SECRET-CONFIG-EXAMPLE"u8.ToArray());
        Require(session.ListPaths().Count == 2, "Deux fichiers internes attendus");
        Require(session.GetAudit().Any(x => x.EventType == "vault-entry-written"), "Audit interne attendu");
    }
    string raw = File.ReadAllText(path);
    Require(!raw.Contains("SECRET-CONFIG-EXAMPLE", StringComparison.Ordinal), "Fuite de contenu en clair");
    Require(!raw.Contains("clef1", StringComparison.Ordinal), "Fuite de nom de clef");
    Require(!raw.Contains(created.RecoveryCode, StringComparison.Ordinal), "Code de recuperation conserve en clair");

    Console.WriteLine("[TEST] Recuperation SHA-256 / HKDF, puis autorisation explicite");
    using (var recovered = VaultStore.OpenWithRecoveryCode(path, "1234", created.RecoveryCode))
    {
        Require(recovered.ReadFile("keys/clef1/private.key")!.SequenceEqual(new byte[] { 23, 42, 99 }),
            "Cle FIDO2 non retrouvee");
        recovered.AuthorizeThisComputer();
        Require(VaultStore.IsAuthorizedOnThisWindowsProfile(path), "Autorisation Windows non detectee");
        Require(recovered.GetAudit().Any(x => x.EventType == "windows-profile-authorized"),
            "Autorisation non journalisee");
        recovered.ChangePin("1234", "6789");
    }
    using (var session = VaultStore.OpenOnAuthorizedComputer(path, "6789"))
        Require(session.ReadFile("config/app.json") is not null, "Configuration perdue");

    Console.WriteLine("[TEST] Mauvais code de recuperation refuse");
    try
    {
        using var invalidRecovery = VaultStore.OpenWithRecoveryCode(path, "6789", new string('0', 64));
        throw new Exception("Le mauvais code de recuperation a ete accepte");
    }
    catch (UnauthorizedAccessException) { }

    Console.WriteLine("[TEST] Une erreur PIN => 15 minutes de blocage, etat persistant");
    try
    {
        using var wrong = VaultStore.OpenOnAuthorizedComputer(path, "0000");
        throw new Exception("PIN incorrect accepte");
    }
    catch (InvalidVaultPinException e)
    {
        double remaining = (e.LockedUntilUtc - DateTimeOffset.UtcNow).TotalMinutes;
        Require(remaining > 14 && remaining <= 15, "Delai 15 minutes incorrect");
    }
    try
    {
        using var blocked = VaultStore.OpenOnAuthorizedComputer(path, "6789");
        throw new Exception("Blocage PIN contourne");
    }
    catch (VaultLockedException) { }

    Console.WriteLine("[TEST] Integrite AES-GCM : modification du ciphertext detectee");
    string tamperedPath = Path.Combine(tempDir, "Tampered.vault");
    string tamperedJson = File.ReadAllText(path);
    // Replace a Base64 ciphertext character without making JSON invalid.
    int dataOffset = tamperedJson.LastIndexOf("\"Ciphertext\":\"", StringComparison.Ordinal);
    Require(dataOffset > 0, "Champ chiffre absent");
    dataOffset += "\"Ciphertext\":\"".Length;
    char replacement = tamperedJson[dataOffset] == 'A' ? 'B' : 'A';
    tamperedJson = tamperedJson[..dataOffset] + replacement + tamperedJson[(dataOffset + 1)..];
    File.WriteAllText(tamperedPath, tamperedJson);
    try
    {
        using var tampered = VaultStore.OpenOnAuthorizedComputer(tamperedPath, "6789");
        throw new Exception("Coffre corrompu accepte");
    }
    catch (CryptographicException) { }

    Console.WriteLine("TOUS LES TESTS NEXORA CRYPT ONT REUSSI");
    return 0;
}
finally
{
    // Do not delete a user's directory; tests create only a unique temporary directory.
    try { Directory.Delete(tempDir, recursive: true); }
    catch (IOException) { Console.Error.WriteLine("Nettoyage temporaire impossible : " + tempDir); }
    catch (UnauthorizedAccessException) { Console.Error.WriteLine("Nettoyage temporaire refuse : " + tempDir); }
}

static void Require(bool condition, string message)
{
    if (!condition) throw new Exception(message);
}
