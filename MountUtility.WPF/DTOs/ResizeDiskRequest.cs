namespace MountUtility.WPF.DTOs;

public class ResizeDiskRequest
{
    public Guid DiskId { get; set; }
    public long NewSizeInMB { get; set; }
}