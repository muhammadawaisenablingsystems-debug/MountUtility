namespace DiskMountUtility.Application.DTOs;

public class FileInfoResponse
{
    public Guid Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Path { get; set; } = string.Empty;
    public long SizeInBytes { get; set; }
    public bool IsDirectory { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime ModifiedAt { get; set; }
    public string FormattedSize { get; set; } = string.Empty;
}