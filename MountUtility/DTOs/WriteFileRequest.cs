namespace DiskMountUtility.Application.DTOs;

public class WriteFileRequest
{
    public string Path { get; set; } = "/";
    public string FileName { get; set; } = string.Empty;
    public byte[] Content { get; set; } = Array.Empty<byte>();
}