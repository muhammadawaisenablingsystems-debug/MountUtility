using DiskMountUtility.Core.Entities;
using DiskMountUtility.Core.Enums;
using Microsoft.EntityFrameworkCore;
using MountUtility.Interfaces;

namespace DiskMountUtility.Infrastructure.Persistence
{
    public class DiskRepository : IDiskRepository
    {
        private readonly AppDbContext _context;

        public DiskRepository(AppDbContext context)
        {
            _context = context;
        }

        public async Task<VirtualDisk?> GetByIdAsync(Guid id)
        {
            return await _context.VirtualDisks.FirstOrDefaultAsync(d => d.Id == id);
        }

        public async Task<VirtualDisk?> GetMountedDiskAsync()
        {
            return await _context.VirtualDisks.FirstOrDefaultAsync(d => d.Status == DiskStatus.Mounted);
        }

        public async Task<List<VirtualDisk>> GetAllAsync()
        {
            return await _context.VirtualDisks.ToListAsync();
        }

        public async Task<VirtualDisk> CreateAsync(VirtualDisk disk)
        {
            try
            {
                _context.VirtualDisks.Add(disk);

                if (disk.Metadata != null)
                {
                    disk.Metadata.VirtualDiskId = disk.Id;
                    _context.EncryptionMetadata.Add(disk.Metadata);
                }

                await _context.SaveChangesAsync();
                return disk;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error while creating virtual disk: {ex.Message}");
                throw;
            }
        }

        public async Task<VirtualDisk> UpdateAsync(VirtualDisk disk)
        {
            _context.VirtualDisks.Update(disk);
            await _context.SaveChangesAsync();
            return disk;
        }

        public async Task<bool> DeleteAsync(Guid id)
        {
            var disk = await _context.VirtualDisks.FindAsync(id);
            if (disk == null) return false;

            _context.VirtualDisks.Remove(disk);
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<EncryptionMetadata?> GetMetadataByDiskIdAsync(Guid diskId)
        {
            try
            {
                return await _context.EncryptionMetadata
                    .FirstOrDefaultAsync(m => m.VirtualDiskId == diskId);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error while fetching metadata: {ex.Message}");
                return null;
            }
        }

        public async Task<IEnumerable<VirtualDisk>> GetByStatusAsync(DiskStatus status)
        {
            return await _context.VirtualDisks
                .Where(d => d.Status == status)
                .ToListAsync();
        }
    }
}