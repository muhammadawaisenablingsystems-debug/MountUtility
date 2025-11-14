using System.Threading.Tasks;

namespace DiskMountUtility.Core.Interfaces
{
    public interface ICryptographyService
    {
        // Existing Kyber APIs
        (byte[] publicKey, byte[] secretKey) GenerateKyberKeyPair();
        byte[] EncryptData(byte[] data, string password, out byte[] kyberCiphertext, out byte[] kyberPublicKey, out byte[] kyberSecretKey, out byte[] nonce, byte[] salt, out byte[] kyberSecretKeyNonce);
        byte[] DecryptData(byte[] encryptedData, string password, byte[] kyberCiphertext, byte[] kyberPublicKey, byte[] kyberSecretKey, byte[] kyberSecretKeyNonce, byte[] nonce, byte[] salt);
        Task<byte[]> DecryptVaultToVhdxAsync(string vaultPath, string password);
        string HashPassword(string password, byte[] salt);
        bool VerifyPassword(string password, string passwordHash, byte[] salt);
        byte[] DerivePasswordKey(string password, byte[] salt);
        byte[] EncryptKyberSecretKey(byte[] secretKey, byte[] passwordKey, byte[] nonce);

        // New ECDH APIs
        (byte[] publicKey, byte[] secretKey) GenerateEcdhKeyPair();
        // Encrypt data using recipient ECDH public key; returns encrypted bytes and out ephemeral public & nonce
        byte[] EncryptDataEcdh(byte[] data, string password, byte[] recipientPublicKey, out byte[] ephemeralPublic, out byte[] nonce, byte[] salt);
        byte[] DecryptDataEcdh(byte[] encryptedData, string password, byte[] senderEphemeralPublic, byte[] recipientPrivateKeyEncrypted, byte[] recipientPrivateKeyNonce, byte[] diskNonce, byte[] diskSalt, byte[] fileSalt);
    }
}