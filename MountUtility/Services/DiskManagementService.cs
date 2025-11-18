using DiskMountUtility.Application.DTOs;
using DiskMountUtility.Core.Entities;
using DiskMountUtility.Infrastructure.Cryptography;
using DiskMountUtility.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using MountUtility.FileWatcher;
using MountUtility.Interfaces;
using System;

namespace MountUtility.Services
{
    public class DiskManagementService
    {
        private readonly IVirtualDiskService _virtualDiskService;
        private readonly IDiskRepository _diskRepository;
        private readonly IDbContextFactory<AppDbContext> _dbContextFactory;
        private readonly VaultFileWatcherService _watcher;
        private readonly RealtimeVaultSyncService _realtimeSync;
        private readonly RealtimeFileExplorerService _realtimeUI;

        private const long MB = 1024 * 1024;

        public DiskManagementService(
            IVirtualDiskService virtualDiskService,
            IDiskRepository diskRepository,
            IDbContextFactory<AppDbContext> dbContextFactory,
            VaultFileWatcherService watcher,
            RealtimeVaultSyncService realtimeSync,
            RealtimeFileExplorerService realtimeUI)
        {
            _virtualDiskService = virtualDiskService;
            _diskRepository = diskRepository;
            _dbContextFactory = dbContextFactory;
            _watcher = watcher;
            _realtimeSync = realtimeSync;
            _realtimeUI = realtimeUI;

            _watcher.FileAdded += HandleFileAdded;
            _watcher.FileUpdated += HandleFileUpdated;
            _watcher.FileDeleted += HandleFileDeleted;
            _watcher.FileRenamed += HandleFileRenamed;

            _watcher.OnChangeDetected = async (path, changeType, oldPath) =>
            {
                await _realtimeSync.SyncFileChangeAsync(path, changeType, oldPath);
                _realtimeUI.NotifyFileChange();
            };
        }

        public string SubscribeToFileChanges(Func<Task> callback)
        {
            return _realtimeUI.Subscribe(callback);
        }

        public void UnsubscribeFromFileChanges(string subscriptionId)
        {
            _realtimeUI.Unsubscribe(subscriptionId);
        }

        public async Task<DiskInfoResponse> CreateDiskAsync(CreateDiskRequest request)
        {
            var sizeInBytes = request.SizeInMB * MB;

            var basePath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "DiskMountUtility", "Disks");
            Directory.CreateDirectory(basePath);

            var driveInfo = new DriveInfo(Path.GetPathRoot(basePath)!);

            if (driveInfo.AvailableFreeSpace < sizeInBytes)
            {
                var requiredMB = sizeInBytes / MB;
                var availableMB = driveInfo.AvailableFreeSpace / MB;
                throw new IOException($"Insufficient physical disk space. Required: {requiredMB} MB, Available: {availableMB} MB on drive {driveInfo.Name}.");
            }

            var disk = await _virtualDiskService.CreateDiskAsync(request.Name, sizeInBytes, request.Password);

            return new DiskInfoResponse
            {
                Id = disk.Id,
                Name = disk.Name,
                SizeInBytes = disk.SizeInBytes,
                UsedSpaceInBytes = disk.UsedSpaceInBytes,
                FreeSpaceInBytes = disk.SizeInBytes - disk.UsedSpaceInBytes,
                Status = disk.Status.ToString(),
                CreatedAt = disk.CreatedAt,
                LastMountedAt = disk.LastMountedAt,
                UsagePercentage = 0
            };
        }

        public async Task<bool> MountDiskAsync(MountDiskRequest request)
        {
            bool mounted = await _virtualDiskService.MountDiskAsync(request.DiskId, request.Password);
            if (!mounted) return false;

            bool physMounted = await _virtualDiskService.MountAsPhysicalDriveAsync(request.DiskId);
            if (!physMounted)
            {
                Console.WriteLine("⚠️ Physical mount failed — continuing logical only");
            }

            string? vaultPath = await _virtualDiskService.GetMountedPathAsync(request.DiskId);

            _realtimeSync.Initialize(request.DiskId, request.Password, vaultPath);

            _watcher.Initialize(vaultPath);
            _watcher.StartWatcher();

            Console.WriteLine($"✅ Vault mounted with realtime sync: {vaultPath}");
            return true;
        }

        public async Task<bool> UnmountDiskAsync(Guid diskId)
        {
            _watcher.StopWatcher();
            _realtimeSync.Shutdown();

            bool unmounted = await _virtualDiskService.UnmountDiskAsync(diskId);

            return unmounted;
        }

        public async Task<DiskInfoResponse?> GetMountedDiskInfoAsync()
        {
            var disk = await _virtualDiskService.GetMountedDiskAsync();
            if (disk == null)
            {
                return null;
            }

            return new DiskInfoResponse
            {
                Id = disk.Id,
                Name = disk.Name,
                SizeInBytes = disk.SizeInBytes,
                UsedSpaceInBytes = disk.UsedSpaceInBytes,
                FreeSpaceInBytes = disk.SizeInBytes - disk.UsedSpaceInBytes,
                Status = disk.Status.ToString(),
                CreatedAt = disk.CreatedAt,
                LastMountedAt = disk.LastMountedAt,
                UsagePercentage = disk.SizeInBytes > 0 ? (double)disk.UsedSpaceInBytes / disk.SizeInBytes * 100 : 0
            };
        }

        public async Task<List<DiskInfoResponse>> GetAllDisksAsync()
        {
            var disks = await _diskRepository.GetAllAsync();

            return disks.Select(disk => new DiskInfoResponse
            {
                Id = disk.Id,
                Name = disk.Name,
                SizeInBytes = disk.SizeInBytes,
                UsedSpaceInBytes = disk.UsedSpaceInBytes,
                FreeSpaceInBytes = disk.SizeInBytes - disk.UsedSpaceInBytes,
                Status = disk.Status.ToString(),
                CreatedAt = disk.CreatedAt,
                LastMountedAt = disk.LastMountedAt,
                UsagePercentage = disk.SizeInBytes > 0 ? (double)disk.UsedSpaceInBytes / disk.SizeInBytes * 100 : 0
            }).ToList();
        }

        public async Task<bool> ResizeDiskAsync(ResizeDiskRequest request)
        {
            var newSizeInBytes = request.NewSizeInMB * MB;

            var disk = await _diskRepository.GetByIdAsync(request.DiskId);
            if (disk == null)
                throw new InvalidOperationException("Disk not found.");

            if (newSizeInBytes < disk.UsedSpaceInBytes)
                throw new InvalidOperationException("New size cannot be smaller than the used space of the disk.");

            var driveInfo = new DriveInfo(Path.GetPathRoot(disk.FilePath)!);
            var additionalSpaceRequired = newSizeInBytes - disk.SizeInBytes;

            if (additionalSpaceRequired > 0 && driveInfo.AvailableFreeSpace < additionalSpaceRequired)
            {
                var requiredMB = additionalSpaceRequired / MB;
                var availableMB = driveInfo.AvailableFreeSpace / MB;
                throw new IOException($"Not enough physical disk space to resize. Additional required: {requiredMB} MB, Available: {availableMB} MB on drive {driveInfo.Name}.");
            }

            return await _virtualDiskService.ResizeDiskAsync(request.DiskId, newSizeInBytes);
        }

        public async Task<bool> ResizeDiskAsync(ResizeDiskRequest request, string password)
        {
            var newSizeInBytes = request.NewSizeInMB * MB;

            var disk = await _diskRepository.GetByIdAsync(request.DiskId);
            if (disk == null)
                throw new InvalidOperationException("Disk not found.");

            if (newSizeInBytes < disk.UsedSpaceInBytes)
                throw new InvalidOperationException("New size cannot be smaller than the used space of the disk.");

            var driveInfo = new DriveInfo(Path.GetPathRoot(disk.FilePath)!);
            var additionalSpaceRequired = newSizeInBytes - disk.SizeInBytes;

            if (additionalSpaceRequired > 0 && driveInfo.AvailableFreeSpace < additionalSpaceRequired)
            {
                var requiredMB = additionalSpaceRequired / MB;
                var availableMB = driveInfo.AvailableFreeSpace / MB;
                throw new IOException($"Insufficient drive space to resize unmounted disk. Additional required: {requiredMB} MB, Available: {availableMB} MB on drive {driveInfo.Name}.");
            }

            return await _virtualDiskService.ResizeDiskAsync(request.DiskId, newSizeInBytes, password);
        }

        public async Task<List<FileInfoResponse>> GetFilesAsync(Guid diskId, string path = "/")
        {
            var files = await _virtualDiskService.GetFilesAsync(diskId, path);

            return files.Select(file => new FileInfoResponse
            {
                Id = file.Id,
                Name = file.Name,
                Path = file.Path,
                SizeInBytes = file.SizeInBytes,
                IsDirectory = file.IsDirectory,
                CreatedAt = file.CreatedAt,
                ModifiedAt = file.ModifiedAt,
                FormattedSize = FormatBytes(file.SizeInBytes)
            }).ToList();
        }

        public async Task<bool> WriteFileAsync(Guid diskId, WriteFileRequest request)
        {
            return await _virtualDiskService.WriteFileAsync(diskId, request.Path, request.FileName, request.Content);
        }

        public async Task<byte[]?> ReadFileAsync(Guid diskId, string path)
        {
            return await _virtualDiskService.ReadFileAsync(diskId, path);
        }

        public async Task<bool> DeleteFileAsync(Guid diskId, string path)
        {
            return await _virtualDiskService.DeleteFileAsync(diskId, path);
        }

        public async Task<bool> CreateDirectoryAsync(Guid diskId, string path)
        {
            return await _virtualDiskService.CreateDirectoryAsync(diskId, path);
        }

        public async Task<bool> DeleteDiskAsync(Guid diskId)
        {
            var disk = await _diskRepository.GetByIdAsync(diskId);
            if (disk == null)
            {
                return false;
            }

            if (File.Exists(disk.FilePath))
            {
                File.Delete(disk.FilePath);
            }

            return await _diskRepository.DeleteAsync(diskId);
        }

        private string FormatBytes(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            double len = bytes;
            int order = 0;

            while (len >= 1024 && order < sizes.Length - 1)
            {
                order++;
                len /= 1024;
            }

            return $"{len:0.##} {sizes[order]}";
        }

        public async Task EnsureDatabaseReadyAsync()
        {
            using var context = _dbContextFactory.CreateDbContext();
            await context.Database.EnsureCreatedAsync();
        }

        public async Task InitializeDisksAfterUnlockAsync()
        {
            if (VaultKeyManager.IsInitialized)
            {
                await _virtualDiskService.InitializeAsync();
            }
        }

        public async Task<bool> MountPhysicalAsync(Guid diskId)
        {
            return await _virtualDiskService.MountAsPhysicalDriveAsync(diskId);
        }

        public async Task<bool> UnmountPhysicalAsync(Guid diskId)
        {
            return await _virtualDiskService.UnmountPhysicalDriveAsync(diskId);
        }

        internal void HandleFileAdded(string fullPath)
        {
            try
            {
                var fileInfo = new FileInfo(fullPath);
                if (!fileInfo.Exists) return;

                using var context = _dbContextFactory.CreateDbContext();

                var disk = context.VirtualDisks.FirstOrDefault(d =>
                    fullPath.StartsWith(Path.GetDirectoryName(d.FilePath)!, StringComparison.OrdinalIgnoreCase));

                if (disk == null) return;

                context.DiskFiles.Add(new DiskFile
                {
                    Id = Guid.NewGuid(),
                    DiskId = disk.Id,
                    Name = fileInfo.Name,
                    Path = fullPath,
                    SizeInBytes = fileInfo.Length,
                    CreatedAt = fileInfo.CreationTimeUtc,
                    ModifiedAt = fileInfo.LastWriteTimeUtc
                });

                disk.UsedSpaceInBytes += fileInfo.Length;
                context.SaveChanges();

                Console.WriteLine($"📄 DB Metadata Added: {fileInfo.Name}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error syncing added file: {ex.Message}");
            }
        }

        internal void HandleFileUpdated(string fullPath)
        {
            try
            {
                var fileInfo = new FileInfo(fullPath);
                if (!fileInfo.Exists) return;

                using var context = _dbContextFactory.CreateDbContext();
                var entity = context.DiskFiles.FirstOrDefault(f => f.Path == fullPath);

                if (entity == null)
                {
                    HandleFileAdded(fullPath);
                    return;
                }

                long sizeDiff = fileInfo.Length - entity.SizeInBytes;
                entity.SizeInBytes = fileInfo.Length;
                entity.ModifiedAt = fileInfo.LastWriteTimeUtc;

                var disk = context.VirtualDisks.FirstOrDefault(d => d.Id == entity.DiskId);
                if (disk != null)
                    disk.UsedSpaceInBytes += sizeDiff;

                context.SaveChanges();

                Console.WriteLine($"✏ DB Metadata Updated: {fileInfo.Name}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error updating file metadata: {ex.Message}");
            }
        }

        internal void HandleFileDeleted(string fullPath)
        {
            try
            {
                using var context = _dbContextFactory.CreateDbContext();
                var entity = context.DiskFiles.FirstOrDefault(f => f.Path == fullPath);
                if (entity == null) return;

                var disk = context.VirtualDisks.FirstOrDefault(d => d.Id == entity.DiskId);
                if (disk != null)
                    disk.UsedSpaceInBytes -= entity.SizeInBytes;

                context.DiskFiles.Remove(entity);
                context.SaveChanges();

                Console.WriteLine($"🗑 DB Metadata Removed: {Path.GetFileName(fullPath)}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error deleting file metadata: {ex.Message}");
            }
        }

        internal void HandleFileRenamed(string oldFullPath, string fullPath)
        {
            try
            {
                using var context = _dbContextFactory.CreateDbContext();
                var entity = context.DiskFiles.FirstOrDefault(f => f.Path == oldFullPath);

                if (entity != null)
                {
                    entity.Path = fullPath;
                    entity.Name = Path.GetFileName(fullPath);
                    entity.ModifiedAt = DateTime.UtcNow;
                    context.SaveChanges();
                }

                Console.WriteLine($"🔁 DB Metadata Renamed: {Path.GetFileName(oldFullPath)} → {Path.GetFileName(fullPath)}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error renaming metadata: {ex.Message}");
            }
        }

        public async Task<Stream?> OpenFileStreamAsync(Guid diskId, string path)
        {
            // Validate
            if (diskId == Guid.Empty || string.IsNullOrEmpty(path))
                return null;

            // Read & decrypt using existing API (this may buffer once during decryption)
            var content = await ReadFileAsync(diskId, path);
            if (content == null) return null;

            try
            {
                var tempFile = Path.Combine(Path.GetTempPath(), $"vault_dl_{diskId:N}_{Guid.NewGuid():N}_{Path.GetFileName(path)}");
                // ensure directory exists (TempPath always exists normally)
                await File.WriteAllBytesAsync(tempFile, content).ConfigureAwait(false);

                // Open with DeleteOnClose so temp file is removed when stream is disposed
                var fs = new FileStream(
                    tempFile,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.Read,
                    bufferSize: 65536,
                    options: FileOptions.Asynchronous | FileOptions.DeleteOnClose);

                return fs;
            }
            catch
            {
                return null;
            }
        }
    }
}