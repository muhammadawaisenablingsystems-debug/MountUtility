using MountUtility.Enums;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace MountUtility.Cryptography
{
    public static class VaultKeyManager
    {
        private const string ProtectedPasswordFile = "vaultpw.bin";
        private const string SettingsFile = "vaultsettings.json";
        private static readonly string DataFolder = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "DiskMountUtility");
        private static readonly string PasswordPath = Path.Combine(DataFolder, ProtectedPasswordFile);
        private static readonly string SettingsPath = Path.Combine(DataFolder, SettingsFile);

        private static string? _cachedPassword;
        private static KeyExchangeAlgorithm _selectedAlgorithm = KeyExchangeAlgorithm.Kyber;

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

            // Load settings (if any)
            if (File.Exists(SettingsPath))
            {
                try
                {
                    var json = File.ReadAllText(SettingsPath);
                    var doc = JsonSerializer.Deserialize<UserVaultSettings>(json);
                    if (doc != null)
                        _selectedAlgorithm = doc.SelectedKeyExchange;
                }
                catch
                {
                    // ignore settings errors
                }
            }
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

        // --- Key exchange selection persistence ---

        public static KeyExchangeAlgorithm SelectedKeyExchange
        {
            get => _selectedAlgorithm;
            set
            {
                _selectedAlgorithm = value;
                SaveSettings();
            }
        }

        private static void SaveSettings()
        {
            try
            {
                Directory.CreateDirectory(DataFolder);
                var settings = new UserVaultSettings { SelectedKeyExchange = _selectedAlgorithm };
                var json = JsonSerializer.Serialize(settings);
                File.WriteAllText(SettingsPath, json);
            }
            catch
            {
                // best-effort save; ignore errors to not interrupt UI flows
            }
        }

        // Return true if user has previously saved an explicit key-exchange choice
        public static bool HasSavedSelection()
        {
            try
            {
                return File.Exists(SettingsPath);
            }
            catch
            {
                return false;
            }
        }

        // Load settings if present (non-throwing)
        public static void LoadSettingsIfExists()
        {
            try
            {
                if (!File.Exists(SettingsPath)) return;
                var json = File.ReadAllText(SettingsPath);
                var doc = JsonSerializer.Deserialize<UserVaultSettings>(json);
                if (doc != null)
                    _selectedAlgorithm = doc.SelectedKeyExchange;
            }
            catch
            {
                // ignore
            }
        }

        private class UserVaultSettings
        {
            public KeyExchangeAlgorithm SelectedKeyExchange { get; set; } = KeyExchangeAlgorithm.Kyber;
        }
    }
}