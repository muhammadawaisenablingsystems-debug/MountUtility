using Microsoft.JSInterop;
using MountUtility.WPF.Cryptography;
using MountUtility.WPF.Enums;

namespace MountUtility.Services
{
    public static class VaultInterop
    {
        [JSInvokable]
        public static Task SaveKexSelection(string selected)
        {
            KeyExchangeAlgorithm algo = selected == "Kyber"
                ? KeyExchangeAlgorithm.Kyber
                : KeyExchangeAlgorithm.EcdhP256;

            VaultKeyManager.SelectedKeyExchange = algo;

            Console.WriteLine($"[VaultInterop] Saved KEX selection: {algo}");
            return Task.CompletedTask;
        }
    }
}
