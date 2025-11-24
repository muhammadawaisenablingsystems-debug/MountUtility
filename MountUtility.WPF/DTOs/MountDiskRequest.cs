namespace MountUtility.WPF.DTOs;

public class MountDiskRequest
{
    public Guid DiskId { get; set; }
    public string Password { get; set; } = string.Empty;
}