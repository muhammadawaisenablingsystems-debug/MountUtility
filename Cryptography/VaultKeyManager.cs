using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace DiskMountUtility.Infrastructure.Cryptography
{
    public static class VaultKeyManager
    {
        private const string ProtectedPasswordFile = "vaultpw.bin";
        private static readonly string PasswordPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "DiskMountUtility",
            ProtectedPasswordFile);

        private static string? _cachedPassword;

        public static bool IsInitialized => !string.IsNullOrEmpty(_cachedPassword);

        /// <summary>
        /// Initializes SQLCipher 4 default mode with the user password.
        /// Password is optionally protected with DPAPI for reuse.
        /// </summary>
        public static void Initialize(string userPassword)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(PasswordPath)!);

            // Cache password in memory
            _cachedPassword = userPassword;

            // Optionally persist securely (encrypted by DPAPI)
            var protectedBytes = ProtectedData.Protect(
                Encoding.UTF8.GetBytes(userPassword),
                null,
                DataProtectionScope.CurrentUser);

            File.WriteAllBytes(PasswordPath, protectedBytes);
        }

        /// <summary>
        /// Loads the protected password from disk (if stored) and caches it.
        /// </summary>
        public static void Load()
        {
            if (!File.Exists(PasswordPath))
                throw new InvalidOperationException("No stored vault password found.");

            var protectedBytes = File.ReadAllBytes(PasswordPath);
            var plainBytes = ProtectedData.Unprotect(protectedBytes, null, DataProtectionScope.CurrentUser);
            _cachedPassword = Encoding.UTF8.GetString(plainBytes);
        }

        /// <summary>
        /// Returns the plaintext password for SQLCipher 4 default PRAGMA key usage.
        /// </summary>
        public static string GetPassword()
        {
            if (string.IsNullOrEmpty(_cachedPassword))
                throw new InvalidOperationException("Vault password not initialized. Call Initialize() or Load().");
            return _cachedPassword!;
        }

        public static void Clear()
        {
            _cachedPassword = null;
        }
    }
}
