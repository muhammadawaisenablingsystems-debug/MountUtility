namespace DiskMountUtility.Application.DTOs;

public class CreateDiskRequest
{
    public string Name { get; set; } = string.Empty;
    public long SizeInMB { get; set; }
    public string Password { get; set; } = string.Empty;
}