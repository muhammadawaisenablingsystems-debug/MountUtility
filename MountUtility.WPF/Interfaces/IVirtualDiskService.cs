using MountUtility.WPF.Entities;

namespace MountUtility.WPF.Interfaces;

public interface IVirtualDiskService
{
    Task<VirtualDisk> CreateDiskAsync(string name, long sizeInBytes, string password);
    Task<bool> MountDiskAsync(Guid diskId, string password);
    Task<bool> MountAsPhysicalDriveAsync(Guid diskId);
    Task<bool> UnmountDiskAsync(Guid diskId);
    Task<bool> UnmountPhysicalDriveAsync(Guid diskId);
    Task<VirtualDisk?> GetMountedDiskAsync();
    Task<bool> ResizeDiskAsync(Guid diskId, long newSizeInBytes);
    Task<bool> ResizeDiskAsync(Guid diskId, long newSizeInBytes, string password);
    Task<List<DiskFile>> GetFilesAsync(Guid diskId, string path = "/");
    Task<bool> WriteFileAsync(Guid diskId, string path, string fileName, byte[] content);
    Task<byte[]?> ReadFileAsync(Guid diskId, string path);
    Task<bool> DeleteFileAsync(Guid diskId, string path);
    Task<bool> CreateDirectoryAsync(Guid diskId, string path);
    Task<bool> RenameFileAsync(Guid diskId, string oldPath, string newPath);
    Task<string?> GetMountedPathAsync(Guid diskId);
    Task InitializeAsync();
}