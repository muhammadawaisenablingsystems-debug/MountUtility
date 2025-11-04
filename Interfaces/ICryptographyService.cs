namespace DiskMountUtility.Core.Interfaces;

public interface ICryptographyService
{
    (byte[] publicKey, byte[] secretKey) GenerateKyberKeyPair();
    byte[] EncryptData(byte[] data, string password, out byte[] kyberCiphertext, out byte[] kyberPublicKey, out byte[] kyberSecretKey, out byte[] nonce, byte[] salt, out byte[] kyberSecretKeyNonce);
    byte[] DecryptData(byte[] encryptedData, string password, byte[] kyberCiphertext, byte[] kyberPublicKey, byte[] kyberSecretKey, byte[] kyberSecretKeyNonce, byte[] nonce, byte[] salt);
    Task<byte[]> DecryptVaultToVhdxAsync(string vaultPath, string password);
    string HashPassword(string password, byte[] salt);
    bool VerifyPassword(string password, string passwordHash, byte[] salt);
    byte[] DerivePasswordKey(string password, byte[] salt);
    byte[] EncryptKyberSecretKey(byte[] secretKey, byte[] passwordKey, byte[] nonce);
}