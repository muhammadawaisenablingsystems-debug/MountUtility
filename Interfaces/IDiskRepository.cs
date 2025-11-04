using DiskMountUtility.Core.Entities;
using DiskMountUtility.Core.Enums;

namespace DiskMountUtility.Core.Interfaces;

public interface IDiskRepository
{
    Task<VirtualDisk?> GetByIdAsync(Guid id);
    Task<VirtualDisk?> GetMountedDiskAsync();
    Task<List<VirtualDisk>> GetAllAsync();
    Task<VirtualDisk> CreateAsync(VirtualDisk disk);
    Task<VirtualDisk> UpdateAsync(VirtualDisk disk);
    Task<bool> DeleteAsync(Guid id);
    Task<EncryptionMetadata?> GetMetadataByDiskIdAsync(Guid diskId);
    Task<IEnumerable<VirtualDisk>> GetByStatusAsync(DiskStatus status);
}