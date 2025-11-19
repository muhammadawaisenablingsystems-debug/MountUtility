using MountUtility.Cryptography;
using MountUtility.Interfaces;

namespace DiskMountUtility.Infrastructure.Cryptography
{
    public class LocalDbUnlocker : ILocalDbUnlocker
    {
        public bool IsInitialized { get; private set; }

        public void InitializeFromPassword(string userPassword)
        {
            VaultKeyManager.Initialize(userPassword);
            IsInitialized = true;
        }
    }
}
