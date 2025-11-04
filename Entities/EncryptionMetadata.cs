namespace DiskMountUtility.Core.Entities;

public class EncryptionMetadata
{
    public Guid Id { get; set; }
    public byte[] KyberCiphertext { get; set; } = Array.Empty<byte>();
    public byte[] KyberPublicKey { get; set; } = Array.Empty<byte>();
    public byte[] Nonce { get; set; } = Array.Empty<byte>();
    public byte[] Salt { get; set; } = Array.Empty<byte>();
    public byte[] KyberSecretKeyEncrypted { get; set; } = Array.Empty<byte>();
    public byte[] KyberSecretKeyNonce { get; set; } = Array.Empty<byte>();

    public Guid VirtualDiskId { get; set; }
    public VirtualDisk? VirtualDisk { get; set; }
}