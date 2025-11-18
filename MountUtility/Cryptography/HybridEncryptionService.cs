using DiskMountUtility.Core.Enums;
using LibOQS.NET;
using System.Security.Cryptography;
using System.Text.Json;
using MountUtility.Interfaces;

namespace DiskMountUtility.Infrastructure.Cryptography
{
    public class HybridEncryptionService : ICryptographyService
    {
        private const int KeySize = 32;
        private const int NonceSize = 12;
        private const int SaltSize = 32;
        private const int Iterations = 100_000;
        private const int TagSize = 16;

        // Generate Kyber Key Pair (existing)
        public (byte[] publicKey, byte[] secretKey) GenerateKyberKeyPair()
        {
            using var kem = new KemInstance(KemAlgorithm.Kyber1024);
            return kem.GenerateKeypair();
        }

        // New: Generate ECDH P-256 key pair (public: X||Y, private: D)
        public (byte[] publicKey, byte[] secretKey) GenerateEcdhKeyPair()
        {
            using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            var parameters = ecdh.ExportParameters(true);

            if (parameters.Q.X == null || parameters.Q.Y == null || parameters.D == null)
                throw new InvalidOperationException("ECDH parameters invalid.");

            var pub = new byte[parameters.Q.X.Length + parameters.Q.Y.Length];
            Buffer.BlockCopy(parameters.Q.X, 0, pub, 0, parameters.Q.X.Length);
            Buffer.BlockCopy(parameters.Q.Y, 0, pub, parameters.Q.X.Length, parameters.Q.Y.Length);

            var priv = parameters.D; // D length should be 32 bytes for P-256

            return (pub, priv);
        }

        // ECDH encapsulation: given recipient public key (X||Y) produce ephemeralPublic (X||Y) and sharedSecret
        public (byte[] ephemeralPublic, byte[] sharedSecret) EncapsulateEcdh(byte[] recipientPublicKey)
        {
            if (recipientPublicKey == null) throw new ArgumentNullException(nameof(recipientPublicKey));
            int coordLen = recipientPublicKey.Length / 2;
            var recipientParams = new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint
                {
                    X = new byte[coordLen],
                    Y = new byte[coordLen]
                }
            };
            Buffer.BlockCopy(recipientPublicKey, 0, recipientParams.Q.X, 0, coordLen);
            Buffer.BlockCopy(recipientPublicKey, coordLen, recipientParams.Q.Y, 0, coordLen);

            using var ephemeral = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            var ephemeralParams = ephemeral.ExportParameters(true);
            var ephemeralPub = new byte[ephemeralParams.Q.X.Length + ephemeralParams.Q.Y.Length];
            Buffer.BlockCopy(ephemeralParams.Q.X, 0, ephemeralPub, 0, ephemeralParams.Q.X.Length);
            Buffer.BlockCopy(ephemeralParams.Q.Y, 0, ephemeralPub, ephemeralParams.Q.X.Length, ephemeralParams.Q.Y.Length);

            using var recipientCandidate = ECDiffieHellman.Create();
            recipientCandidate.ImportParameters(recipientParams);

            var shared = ephemeral.DeriveKeyMaterial(recipientCandidate.PublicKey);
            return (ephemeralPub, shared);
        }

        // ECDH decapsulation: given recipientPrivate (D) and sender ephemeralPublic (X||Y), derive sharedSecret
        public byte[] DecapsulateEcdh(byte[] recipientPrivateKey, byte[] senderEphemeralPublic)
        {
            if (recipientPrivateKey == null) throw new ArgumentNullException(nameof(recipientPrivateKey));
            if (senderEphemeralPublic == null) throw new ArgumentNullException(nameof(senderEphemeralPublic));

            int coordLen = senderEphemeralPublic.Length / 2;
            var senderParams = new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint
                {
                    X = new byte[coordLen],
                    Y = new byte[coordLen]
                }
            };
            Buffer.BlockCopy(senderEphemeralPublic, 0, senderParams.Q.X, 0, coordLen);
            Buffer.BlockCopy(senderEphemeralPublic, coordLen, senderParams.Q.Y, 0, coordLen);

            var recipientParams = new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                D = recipientPrivateKey
            };

            using var recipient = ECDiffieHellman.Create();
            recipient.ImportParameters(recipientParams);

            using var senderPublicOnly = ECDiffieHellman.Create();
            senderPublicOnly.ImportParameters(senderParams);

            var shared = recipient.DeriveKeyMaterial(senderPublicOnly.PublicKey);
            return shared;
        }

        // Existing Kyber EncryptData (unchanged)
        public byte[] EncryptData(
            byte[] data,
            string password,
            out byte[] kyberCiphertext,
            out byte[] kyberPublicKey,
            out byte[] kyberSecretKeyEncrypted,
            out byte[] nonce,
            byte[] salt,
            out byte[] kyberSecretKeyNonce)
        {
            nonce = RandomNumberGenerator.GetBytes(NonceSize);

            // 1️ Generate Kyber key pair
            var (pubKey, secretKey) = GenerateKyberKeyPair();
            kyberPublicKey = pubKey;

            // 2️ KEM encapsulate
            using var kem = new KemInstance(KemAlgorithm.Kyber1024);
            (kyberCiphertext, var sharedSecret) = kem.Encapsulate(pubKey);

            // 3️ Derive AES key for content
            var aesKey = DeriveKey(password, salt, sharedSecret);

            // 4️ Encrypt disk content
            var ciphertext = new byte[data.Length];
            var tag = new byte[TagSize];
            using (var aesGcm = new AesGcm(aesKey))
                aesGcm.Encrypt(nonce, data, ciphertext, tag);

            var encryptedData = new byte[ciphertext.Length + tag.Length];
            Buffer.BlockCopy(ciphertext, 0, encryptedData, 0, ciphertext.Length);
            Buffer.BlockCopy(tag, 0, encryptedData, ciphertext.Length, tag.Length);

            // 5️ Encrypt Kyber secret key using password-derived key
            kyberSecretKeyNonce = RandomNumberGenerator.GetBytes(NonceSize);
            var passwordKey = DerivePasswordKey(password, salt);
            kyberSecretKeyEncrypted = EncryptKyberSecretKey(secretKey, passwordKey, kyberSecretKeyNonce);

            return encryptedData;
        }

        // New: Encrypt data with ECDH recipient public key
        public byte[] EncryptDataEcdh(byte[] data, string password, byte[] recipientPublicKey, out byte[] ephemeralPublic, out byte[] nonce, byte[] salt)
        {
            nonce = RandomNumberGenerator.GetBytes(NonceSize);

            var (ephemeral, sharedSecret) = EncapsulateEcdh(recipientPublicKey);
            ephemeralPublic = ephemeral;

            var aesKey = DeriveKey(password, salt, sharedSecret);

            var ciphertext = new byte[data.Length];
            var tag = new byte[TagSize];
            using (var aesGcm = new AesGcm(aesKey))
                aesGcm.Encrypt(nonce, data, ciphertext, tag);

            var encryptedData = new byte[ciphertext.Length + tag.Length];
            Buffer.BlockCopy(ciphertext, 0, encryptedData, 0, ciphertext.Length);
            Buffer.BlockCopy(tag, 0, encryptedData, ciphertext.Length, tag.Length);

            return encryptedData;
        }

        // New: Decrypt data encrypted by EncryptDataEcdh
        // NOTE: diskSalt (salt used at disk creation) is used to derive the password key to decrypt the stored recipient private key.
        //       fileSalt (per-file salt) is used to derive the AES key for the file contents.
        public byte[] DecryptDataEcdh(byte[] encryptedData, string password, byte[] senderEphemeralPublic, byte[] recipientPrivateKeyEncrypted, byte[] recipientPrivateKeyNonce, byte[] diskNonce, byte[] diskSalt, byte[] fileSalt)
        {
            // Decrypt recipient private key (AES-GCM using password-derived key derived from diskSalt)
            var passwordKey = DerivePasswordKey(password, diskSalt);

            if (recipientPrivateKeyEncrypted.Length < TagSize)
                throw new InvalidOperationException("Encrypted recipient private key is too short.");

            var ct = new byte[recipientPrivateKeyEncrypted.Length - TagSize];
            var tag = new byte[TagSize];
            Buffer.BlockCopy(recipientPrivateKeyEncrypted, 0, ct, 0, ct.Length);
            Buffer.BlockCopy(recipientPrivateKeyEncrypted, ct.Length, tag, 0, tag.Length);

            var recipientPrivate = new byte[ct.Length];
            using (var aesGcm = new AesGcm(passwordKey))
                aesGcm.Decrypt(recipientPrivateKeyNonce, ct, tag, recipientPrivate);

            // Derive shared secret (ECDH)
            var sharedSecret = DecapsulateEcdh(recipientPrivate, senderEphemeralPublic);

            // Derive AES content key using per-file salt (fileSalt) + sharedSecret
            var aesKey = DeriveKey(password, fileSalt, sharedSecret);

            if (encryptedData.Length < TagSize)
                throw new InvalidOperationException("Encrypted data too short.");

            var ciphertext = new byte[encryptedData.Length - TagSize];
            var dataTag = new byte[TagSize];
            Buffer.BlockCopy(encryptedData, 0, ciphertext, 0, ciphertext.Length);
            Buffer.BlockCopy(encryptedData, ciphertext.Length, dataTag, 0, dataTag.Length);

            var plaintext = new byte[ciphertext.Length];
            using var aesGcm2 = new AesGcm(aesKey);
            aesGcm2.Decrypt(diskNonce, ciphertext, dataTag, plaintext);

            return plaintext;
        }

        // Decrypt data using stored Kyber secret key (existing)
        public byte[] DecryptData(
            byte[] encryptedData,
            string password,
            byte[] kyberCiphertext,
            byte[] kyberPublicKey,
            byte[] kyberSecretKeyEncrypted,
            byte[] kyberSecretKeyNonce, // pass separate nonce
            byte[] diskNonce,
            byte[] salt)
        {
            using var kem = new KemInstance(KemAlgorithm.Kyber1024);

            var passwordKey = DerivePasswordKey(password, salt);
            var kyberSecretKey = DecryptKyberSecretKey(kyberSecretKeyEncrypted, passwordKey, kyberSecretKeyNonce);

            if (kyberSecretKey.Length != 3168)
                throw new InvalidOperationException($"Invalid Kyber secret key length: {kyberSecretKey.Length}");

            var sharedSecret = kem.Decapsulate(kyberSecretKey, kyberCiphertext);
            var aesKey = DeriveKey(password, salt, sharedSecret);

            if (encryptedData.Length < TagSize)
                throw new InvalidOperationException("Encrypted data too short.");

            var ciphertext = new byte[encryptedData.Length - TagSize];
            var tag = new byte[TagSize];
            Buffer.BlockCopy(encryptedData, 0, ciphertext, 0, ciphertext.Length);
            Buffer.BlockCopy(encryptedData, ciphertext.Length, tag, 0, tag.Length);

            var plaintext = new byte[ciphertext.Length];
            using var aesGcm = new AesGcm(aesKey);
            aesGcm.Decrypt(diskNonce, ciphertext, tag, plaintext);

            return plaintext;
        }

        // Password hashing
        public string HashPassword(string password, byte[] salt)
        {
            using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, Iterations, HashAlgorithmName.SHA512);
            return Convert.ToBase64String(pbkdf2.GetBytes(KeySize));
        }

        public bool VerifyPassword(string password, string passwordHash, byte[] salt)
        {
            return HashPassword(password, salt) == passwordHash;
        }

        // ======= Helper methods =======

        public byte[] DeriveKey(string password, byte[] salt, byte[] sharedSecret)
        {
            var combinedSalt = new byte[salt.Length + sharedSecret.Length];
            Buffer.BlockCopy(salt, 0, combinedSalt, 0, salt.Length);
            Buffer.BlockCopy(sharedSecret, 0, combinedSalt, salt.Length, sharedSecret.Length);

            using var pbkdf2 = new Rfc2898DeriveBytes(password, combinedSalt, Iterations, HashAlgorithmName.SHA512);
            return pbkdf2.GetBytes(KeySize);
        }

        public byte[] DerivePasswordKey(string password, byte[] salt)
        {
            using var kdf = new Rfc2898DeriveBytes(password, salt, Iterations, HashAlgorithmName.SHA512);
            return kdf.GetBytes(KeySize);
        }

        public byte[] EncryptKyberSecretKey(byte[] secretKey, byte[] passwordKey, byte[] nonce)
        {
            var ciphertext = new byte[secretKey.Length];
            var tag = new byte[TagSize];

            using (var aesGcm = new AesGcm(passwordKey))
            {
                aesGcm.Encrypt(nonce, secretKey, ciphertext, tag);
            }

            var combined = new byte[ciphertext.Length + tag.Length];
            Buffer.BlockCopy(ciphertext, 0, combined, 0, ciphertext.Length);
            Buffer.BlockCopy(tag, 0, combined, ciphertext.Length, tag.Length);

            return combined;
        }

        private byte[] DecryptKyberSecretKey(byte[] encryptedKey, byte[] passwordKey, byte[] nonce)
        {
            if (encryptedKey.Length < TagSize)
                throw new InvalidOperationException("Encrypted Kyber key is too short.");

            var ciphertext = new byte[encryptedKey.Length - TagSize];
            var tag = new byte[TagSize];
            Buffer.BlockCopy(encryptedKey, 0, ciphertext, 0, ciphertext.Length);
            Buffer.BlockCopy(encryptedKey, ciphertext.Length, tag, 0, tag.Length);

            var secretKey = new byte[ciphertext.Length];
            using var aesGcm = new AesGcm(passwordKey);
            aesGcm.Decrypt(nonce, ciphertext, tag, secretKey);

            return secretKey;
        }

        public async Task<byte[]> DecryptVaultToVhdxAsync(string vaultPath, string password)
        {
            if (string.IsNullOrEmpty(vaultPath)) throw new ArgumentNullException(nameof(vaultPath));
            if (!File.Exists(vaultPath)) throw new FileNotFoundException("Vault file not found", vaultPath);
            if (string.IsNullOrEmpty(password)) throw new ArgumentNullException(nameof(password));

            // Read vault JSON (metadata + encryptedContent)
            string json = await File.ReadAllTextAsync(vaultPath).ConfigureAwait(false);
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            // This method historically only supported Kyber-style file format.
            // Keep existing Kyber-centric extraction for backward compatibility.
            if (!root.TryGetProperty("metadata", out var metaEl))
                throw new InvalidDataException("Vault metadata missing.");

            string b64KyberCiphertext = metaEl.GetProperty("kyberCiphertext").GetString() ?? throw new InvalidDataException("kyberCiphertext missing");
            string b64KyberPublicKey = metaEl.GetProperty("kyberPublicKey").GetString() ?? throw new InvalidDataException("kyberPublicKey missing");
            string b64KyberSecretKey = metaEl.GetProperty("kyberSecretKey").GetString() ?? throw new InvalidDataException("kyberSecretKey missing");
            string b64KyberSecretKeyNonce = metaEl.GetProperty("kyberSecretKeyNonce").GetString() ?? throw new InvalidDataException("kyberSecretKeyNonce missing");
            string b64Nonce = metaEl.GetProperty("nonce").GetString() ?? throw new InvalidDataException("nonce missing");
            string b64Salt = metaEl.GetProperty("salt").GetString() ?? throw new InvalidDataException("salt missing");

            byte[] kyberCiphertext = Convert.FromBase64String(b64KyberCiphertext);
            byte[] kyberPublicKey = Convert.FromBase64String(b64KyberPublicKey);
            byte[] kyberSecretKeyEncrypted = Convert.FromBase64String(b64KyberSecretKey);
            byte[] kyberSecretKeyNonce = Convert.FromBase64String(b64KyberSecretKeyNonce);
            byte[] diskNonce = Convert.FromBase64String(b64Nonce);
            byte[] salt = Convert.FromBase64String(b64Salt);

            if (!root.TryGetProperty("encryptedContent", out var encEl))
                throw new InvalidDataException("encryptedContent missing.");

            string b64EncryptedContent = encEl.GetString() ?? throw new InvalidDataException("encryptedContent empty");
            byte[] encryptedContent = Convert.FromBase64String(b64EncryptedContent);

            byte[] decrypted = DecryptData(
                encryptedContent,
                password,
                kyberCiphertext,
                kyberPublicKey,
                kyberSecretKeyEncrypted,
                kyberSecretKeyNonce,
                diskNonce,
                salt
            );

            return decrypted;
        }
    }
}