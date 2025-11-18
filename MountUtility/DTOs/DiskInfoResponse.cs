namespace DiskMountUtility.Application.DTOs;

public class DiskInfoResponse
{
    public Guid Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public long SizeInBytes { get; set; }
    public long UsedSpaceInBytes { get; set; }
    public long FreeSpaceInBytes { get; set; }
    public string Status { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
    public DateTime? LastMountedAt { get; set; }
    public double UsagePercentage { get; set; }
}