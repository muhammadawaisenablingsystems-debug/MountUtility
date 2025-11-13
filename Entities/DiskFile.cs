namespace DiskMountUtility.Core.Entities;

public class DiskFile
{
    public Guid Id { get; set; }
    public Guid DiskId { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Path { get; set; } = string.Empty;
    public long SizeInBytes { get; set; }
    public bool IsDirectory { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime ModifiedAt { get; set; }
    public byte[] EncryptedContent { get; set; } = Array.Empty<byte>();
    public VirtualDisk? Disk { get; set; }

    // Kyber fields
    public byte[] KyberCiphertext { get; set; } = Array.Empty<byte>();
    public byte[] KyberPublicKey { get; set; } = Array.Empty<byte>();
    public byte[] KyberSecretKeyEncrypted { get; set; } = Array.Empty<byte>();
    public byte[] KyberSecretKeyNonce { get; set; } = Array.Empty<byte>();

    // ECDH per-file ephemeral public (X||Y)
    public byte[] EcdhEphemeralPublic { get; set; } = Array.Empty<byte>();

    public byte[] FileNonce { get; set; } = Array.Empty<byte>();
    public byte[] Salt { get; set; } = Array.Empty<byte>();
}