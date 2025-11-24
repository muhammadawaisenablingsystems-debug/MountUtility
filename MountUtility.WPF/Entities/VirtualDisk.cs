using MountUtility.WPF.Enums;
using System.ComponentModel.DataAnnotations.Schema;
using System.Threading.Tasks;

namespace MountUtility.WPF.Entities;

public class VirtualDisk
{
    public Guid Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public long SizeInBytes { get; set; }
    public long UsedSpaceInBytes { get; set; }
    public DiskStatus Status { get; set; }
    public EncryptionAlgorithm EncryptionAlgorithm { get; set; }
    public string FilePath { get; set; } = string.Empty;
    public string? TempMountPath {  get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
    public DateTime? LastMountedAt { get; set; }
    public DateTime? LastModifiedAt { get; set; }
    public string PasswordHash { get; set; } = string.Empty;

    public EncryptionMetadata? Metadata { get; set; }
    public ICollection<DiskFile> Files { get; set; } = new List<DiskFile>();
}